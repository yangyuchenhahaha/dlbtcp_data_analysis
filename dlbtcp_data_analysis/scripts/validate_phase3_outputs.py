#!/usr/bin/env python3
"""Independently validate phase-3 aggregates against phase-2 evidence.

This reads small summaries, session rows, the 1-second phase-2 profiles and
selected timeline packets. It deliberately does not reread or reclassify the
full events table. Any failed check writes all_checks_passed=false and exits 1.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import gzip
import hashlib
import json
import math
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
MEASURES = ("packets", "wire_bytes", "valid_payload_bytes")
CONDITIONAL = {
    "seq_event_given_data": "data",
    "seq_event_given_payload": "payload_bearing",
    "ack_event_given_ack": "ack_bearing",
}
SEQ_LABELS = {"NA", "INVALID", "BASELINE", "IN_ORDER", "AHEAD_GAP", "GAP_FILL",
              "PREFIX_UNOBSERVED", "DUP_FULL", "OVERLAP_PARTIAL"}
ACK_LABELS = {"NA", "INVALID", "BASELINE", "ADVANCE", "REPEAT", "WINDOW_UPDATE",
              "SAME", "BACKWARD"}
SHAPES = {"INVALID", "RST", "SYNACK", "SYN", "FIN", "DATA", "PURE_ACK", "OTHER"}


def read_csv(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def integer(value):
    return int(value)


def number(value):
    return None if value in (None, "") else float(value)


def nearest(values, q):
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * q) - 1] if ordered else None


def truth(value):
    return str(value).lower() in {"1", "true", "yes"}


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def file_metadata(path):
    info = path.stat()
    return dict(size_bytes=info.st_size, mtime_ns=info.st_mtime_ns)


class Checks:
    def __init__(self):
        self.groups = defaultdict(Counter)
        self.failures = []
        self.count = 0

    def check(self, group, ok, context="", **evidence):
        self.count += 1
        self.groups[group]["passed" if ok else "failed"] += 1
        if not ok:
            self.failures.append(dict(group=group, context=context, **evidence))

    def equal(self, group, actual, expected, context=""):
        self.check(group, actual == expected, context, actual=actual, expected=expected)

    def close(self, group, actual, expected, context=""):
        if actual is None or expected is None:
            ok = actual is None and expected is None
        else:
            ok = math.isfinite(actual) and math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-10)
        self.check(group, ok, context, actual=actual, expected=expected)


def unique_rows(rows, fields, checks, name):
    result = {}
    for row in rows:
        key = tuple(row[f] for f in fields)
        checks.check("unique_rows", key not in result, name, key=list(key))
        result[key] = row
    return result


def metric(row, name):
    return integer(row[name]) if row else 0


def phase2_expectations(phase2_dir):
    """Recompute cohort selections independently, including unions exactly once."""
    stats = {r["endpoint"]: r for r in read_csv(phase2_dir / "endpoint_statistics.csv")}
    profiles = read_csv(phase2_dir / "window_profiles_1s.csv.gz")
    by_endpoint = defaultdict(list)
    for row in profiles:
        by_endpoint[row["endpoint"]].append(row)
    expected = defaultdict(Counter)
    for ep, rows in by_endpoint.items():
        packets = [integer(r["packets"]) for r in rows]
        p40, p60, p90 = (nearest(packets, q) for q in (.4, .6, .9))
        threshold = max(20, p90)
        for row in rows:
            n = integer(row["packets"])
            high = n >= threshold
            single = high and float(row["top1_share"]) >= .5
            few = high and float(row["top5_share"]) >= .8 and integer(row["active_connections"]) >= 10
            selected = {
                "high_load": high, "single_hot_all": single, "few_hot_all": few,
                "hotspot_window_union": single or few,
                "ordinary": p40 <= n <= p60 and n > 0,
                "balanced_high": high and integer(row["active_connections"]) >= 10
                    and float(row["top1_share"]) <= .2 and float(row["top5_share"]) <= .5,
            }
            for cohort, included in selected.items():
                if included:
                    expected[ep, cohort].update(packets=n, wire_bytes=integer(row["wire_bytes"]),
                                                valid_payload_bytes=integer(row["payload_bytes"]))
            for cohort, count in (
                ("single_hot_dominant", integer(row["top1_packets"]) if single else 0),
                ("few_hot_dominant", integer(row["top5_packets"]) if few else 0),
                ("hotspot_dominant_union", integer(row["top5_packets"]) if few
                 else integer(row["top1_packets"]) if single else 0),
            ):
                expected[ep, cohort]["packets"] += count
    for sample in read_csv(phase2_dir / "representative_samples.csv"):
        ep, cohort = sample["endpoint"], "sample_" + sample["name"]
        selected = [r for r in by_endpoint[ep]
                    if float(sample["start_ts"]) <= float(r["start_ts"]) < float(sample["end_ts"])]
        expected[ep, cohort].update(packets=integer(sample["endpoint_packets"]),
                                    wire_bytes=integer(sample["wire_bytes"]),
                                    valid_payload_bytes=sum(integer(r["payload_bytes"]) for r in selected))
    payload_totals = {}
    for directory in ("primary_windows", "control_windows"):
        document = read_json(phase2_dir / directory / "summary.json")
        for ep, endpoint in document["endpoints"].items():
            widths = list(endpoint["windows"].values())
            payload_totals[ep] = integer(widths[0]["payload_bytes"])
    for ep, row in stats.items():
        expected[ep, "all"].update(packets=integer(row["packets"]),
                                    wire_bytes=integer(row["wire_bytes"]),
                                    valid_payload_bytes=payload_totals[ep])
    return stats, profiles, expected


def validate(directory, phase2_dir, checks):
    classification_inputs = [directory / name for name in
                             ("events.csv.gz", "sessions.csv", "classification_manifest.json")]
    initial_input_metadata = {str(path.resolve()): file_metadata(path) for path in classification_inputs}
    classifier = read_json(directory / "classification_manifest.json")
    summary = read_json(directory / "summary_manifest.json")
    cohorts = unique_rows(read_csv(directory / "cohort_summary.csv"),
                          ("endpoint", "cohort"), checks, "cohort_summary")
    event_rows = read_csv(directory / "event_summary.csv")
    details = unique_rows(event_rows, ("endpoint", "cohort", "dimension", "event"), checks, "event_summary")
    sessions = unique_rows(read_csv(directory / "sessions.csv"), ("session_id",), checks, "sessions")
    stats, profiles, expected = phase2_expectations(phase2_dir)
    checks.equal("fast_path_deferred", classifier["fast_path_status"], "deferred_by_user", "classifier")
    checks.equal("fast_path_deferred", summary["fast_path_status"], "deferred_by_user", "summary")
    checks.equal("classification_complete", classifier["status"], "classified")
    checks.check("classification_complete", classifier["phase3_real_trace_analysis_run"] is True)
    checks.check("completed_event_artifact", (directory / "events.csv.gz").is_file()
                 and not (directory / "events.csv.gz.partial").exists())
    checks.equal("summary_input_location", str(Path(summary["input_events"]).resolve()),
                 str((directory / "events.csv.gz").resolve()))
    checks.check("classifier_reported_checks", classifier["all_checks_passed"] is True)
    checks.check("summarizer_reported_checks", summary["conservation_checks_passed"] is True)
    checks.equal("session_context", integer(summary["missing_session_context_packets"]), 0)
    checks.check("run_is_observational", "not a fast path" in summary["definitions"]["routine_observed"].lower())
    checks.equal("endpoint_set", sorted({ep for ep, _ in cohorts}), sorted(stats))
    checks.equal("session_count", len(sessions), integer(classifier["session_fragments"]))
    checks.equal("session_count", len(sessions), integer(summary["sessions"]))
    phase2_manifest = read_json(phase2_dir / "analysis_manifest.json")
    phase2_inputs = {Path(r["path"]).name: r for r in phase2_manifest["inputs"]}
    for record in classifier["inputs"]:
        name = Path(record["path"]).name
        if name in phase2_inputs and not name.endswith(".gz"):
            checks.equal("phase2_input_identity", record["uncompressed_sha256"],
                         phase2_inputs[name]["sha256"], name)
    for record in classifier["cohort_checks"]:
        checks.equal("classifier_cohort_checks", integer(record["actual_packets"]),
                     integer(record["expected_packets"]), str((record["endpoint"], record["cohort"])))
        checks.check("classifier_cohort_checks", record["passed"] is True)

    session_counts = defaultdict(Counter)
    for (sid,), row in sessions.items():
        ep = row["endpoint"]
        tx, rx = integer(row["tx_packets"]), integer(row["rx_packets"])
        checks.check("session_rows", ep in stats and tx >= 0 and rx >= 0 and tx + rx > 0, sid)
        checks.check("session_rows", math.isfinite(float(row["first_ts"]))
                     and math.isfinite(float(row["last_ts"]))
                     and float(row["first_ts"]) <= float(row["last_ts"]), sid)
        checks.equal("session_endpoint", json.loads(row["connection"])[0], ep, sid)
        if truth(row["handshake_complete"]):
            checks.check("handshake_context", truth(row["syn_tx"]) and truth(row["syn_rx"])
                         and row["handshake_ts"] != "", sid)
            if row["handshake_ts"]:
                checks.check("handshake_context", float(row["first_ts"]) <= float(row["handshake_ts"])
                             <= float(row["last_ts"]), sid)
        session_counts[ep].update(TX=tx, RX=rx, payload_bytes=integer(row["payload_bytes"]))

    totals = {}
    payload_exclusions = {}
    for ep, row in stats.items():
        all_row = cohorts[ep, "all"]
        totals[ep] = {m: metric(all_row, m) for m in MEASURES}
        checks.equal("endpoint_packets", metric(all_row, "packets"), integer(row["packets"]), ep)
        checks.equal("endpoint_wire_bytes", metric(all_row, "wire_bytes"), integer(row["wire_bytes"]), ep)
        raw_payload = session_counts[ep]["payload_bytes"]
        valid_payload = metric(all_row, "valid_payload_bytes")
        invalid_packets = metric(details.get((ep, "all", "packet_type", "INVALID")), "packets")
        excluded = raw_payload - valid_payload
        checks.equal("endpoint_payload_source_conservation", raw_payload,
                     expected[ep, "all"]["valid_payload_bytes"], ep)
        checks.check("endpoint_payload_exclusion", excluded >= 0 and (invalid_packets > 0 or excluded == 0),
                     ep, raw_payload_bytes=raw_payload, valid_payload_bytes=valid_payload,
                     invalid_packets=invalid_packets, excluded_payload_bytes=excluded)
        payload_exclusions[ep] = dict(raw_inferred_payload_bytes=raw_payload,
                                      valid_payload_bytes=valid_payload,
                                      invalid_packets=invalid_packets,
                                      excluded_inferred_payload_bytes=excluded)
        checks.equal("classifier_endpoint_packets", integer(classifier["endpoint_packets"][ep]), integer(row["packets"]), ep)
        for direction, packet_field, byte_field in (("TX", "tx_packets", "tx_wire_bytes"),
                                                     ("RX", "rx_packets", "rx_wire_bytes")):
            detail = details.get((ep, "all", "direction", direction))
            checks.equal("endpoint_direction_packets", metric(detail, "packets"), integer(row[packet_field]), f"{ep}/{direction}")
            checks.equal("endpoint_direction_wire", metric(detail, "wire_bytes"), integer(row[byte_field]), f"{ep}/{direction}")
            checks.equal("session_direction_packets", session_counts[ep][direction], integer(row[packet_field]), f"{ep}/{direction}")
    grand_total = sum(integer(r["packets"]) for r in stats.values())
    checks.equal("total_packets", integer(classifier["total_endpoint_packets"]), grand_total)
    checks.equal("total_packets", integer(summary["input_packets"]), grand_total)

    grouped = defaultdict(list)
    for key, row in details.items():
        grouped[key[:3]].append(row)
        checks.check("event_cohort_exists", key[:2] in cohorts, str(key))
        checks.check("event_dimension_vocabulary", key[2] in {
            "packet_type", "seq_event", "ack_event", "direction", "uncertainty", *CONDITIONAL}, str(key))
        if key[2] not in CONDITIONAL and key[:2] in cohorts:
            cohort = cohorts[key[:2]]
            checks.equal("event_denominator_kind", row["denominator_kind"], "cohort", str(key))
            for field, denominator_field, fraction_field in (
                ("packets", "packet_denominator", "packet_fraction"),
                ("wire_bytes", "wire_byte_denominator", "wire_byte_fraction"),
                ("valid_payload_bytes", "valid_payload_byte_denominator", "valid_payload_byte_fraction"),
            ):
                numerator, denominator = metric(row, field), metric(cohort, field)
                checks.equal("event_declared_denominator", integer(row[denominator_field]), denominator, str(key))
                checks.close("event_declared_fraction", number(row[fraction_field]),
                             numerator / denominator if denominator else None, str(key))
                checks.check("event_bounds", 0 <= numerator <= denominator, str(key), measure=field)
    for key, row in cohorts.items():
        label = "/".join(key)
        for field in (*MEASURES, "wire_valid_packets", "payload_valid_packets", "uncertain_packets", "candidate_packets"):
            checks.check("nonnegative_cohort_totals", metric(row, field) >= 0, f"{label}/{field}")
        for field in ("wire_valid_packets", "payload_valid_packets", "uncertain_packets", "candidate_packets"):
            checks.check("cohort_packet_bounds", metric(row, field) <= metric(row, "packets"), f"{label}/{field}")
        checks.close("cohort_uncertainty_fraction", number(row["uncertain_packet_fraction"]),
                     metric(row, "uncertain_packets") / metric(row, "packets") if metric(row, "packets") else None, label)
        for dimension, labels in (("packet_type", SHAPES), ("seq_event", SEQ_LABELS),
                                  ("ack_event", ACK_LABELS), ("direction", {"TX", "RX"})):
            rows = grouped[key + (dimension,)]
            checks.check("event_label_vocabulary", all(r["event"] in labels for r in rows), f"{label}/{dimension}")
            for field in (*MEASURES, "wire_valid_packets", "payload_valid_packets"):
                checks.equal("exclusive_dimension_conservation", sum(metric(r, field) for r in rows),
                             metric(row, field), f"{label}/{dimension}/{field}")
        # Uncertainty reasons overlap. NONE is the only mutually exclusive complement.
        none = details.get(key + ("uncertainty", "NONE"))
        checks.equal("uncertainty_complement", metric(none, "packets") + metric(row, "uncertain_packets"),
                     metric(row, "packets"), label)
        for reason in grouped[key + ("uncertainty",)]:
            checks.check("uncertainty_reason_bound", 0 <= metric(reason, "packets") <= metric(row, "packets"),
                         f"{label}/{reason['event']}")
        wanted = expected.get(key, Counter())
        if key[1] in {"single_hot_dominant", "few_hot_dominant", "hotspot_dominant_union"}:
            fields = ("packets",)
        else:
            fields = MEASURES
        for field in fields:
            if field == "valid_payload_bytes":
                invalid = metric(details.get(key + ("packet_type", "INVALID")), "packets")
                excluded = wanted[field] - metric(row, field)
                maximum_excluded = payload_exclusions[key[0]]["excluded_inferred_payload_bytes"]
                checks.check("phase2_cohort_payload_exclusion", 0 <= excluded <= maximum_excluded
                             and (invalid > 0 or excluded == 0), label,
                             phase2_inferred_payload_bytes=wanted[field],
                             valid_payload_bytes=metric(row, field), invalid_packets=invalid,
                             excluded_inferred_payload_bytes=excluded,
                             endpoint_excluded_payload_bytes=maximum_excluded)
            else:
                checks.equal("phase2_cohort_conservation", metric(row, field), wanted[field], f"{label}/{field}")
        if key[1] != "all":
            for field in MEASURES:
                checks.check("cohort_subset_bounds", metric(row, field) <= metric(cohorts[key[0], "all"], field), f"{label}/{field}")
    for key, wanted in expected.items():
        checks.check("expected_cohort_present", key in cohorts, str(key))

    conditional_rows = []
    for key, cohort in cohorts.items():
        context = "/".join(key)
        data = details.get(key + ("packet_type", "DATA"))
        for field in MEASURES:
            checks.equal("data_condition_denominator", metric(cohort, "data_" + field), metric(data, field), f"{context}/{field}")
        checks.equal("payload_condition_bytes", metric(cohort, "payload_bearing_valid_payload_bytes"),
                     metric(cohort, "valid_payload_bytes"), context)
        checks.check("conditional_subset_bounds", metric(cohort, "data_packets") <= metric(cohort, "payload_bearing_packets")
                     <= metric(cohort, "payload_valid_packets"), context)
        checks.check("conditional_subset_bounds", metric(cohort, "ack_bearing_packets") <= metric(cohort, "payload_valid_packets"), context)
        invalid = details.get(key + ("packet_type", "INVALID"))
        ack_na = details.get(key + ("ack_event", "NA"))
        checks.equal("ack_condition_denominator", metric(cohort, "ack_bearing_packets"),
                     metric(cohort, "packets") - metric(invalid, "packets") - metric(ack_na, "packets"), context)
        for dimension, prefix in CONDITIONAL.items():
            rows = grouped[key + (dimension,)]
            labels = (ACK_LABELS if prefix == "ack_bearing" else SEQ_LABELS) - {"NA"}
            checks.check("conditional_label_vocabulary", all(r["event"] in labels for r in rows), f"{context}/{dimension}")
            denominators = {m: metric(cohort, prefix + "_" + m) for m in MEASURES}
            for field in MEASURES:
                checks.equal("conditional_conservation", sum(metric(r, field) for r in rows),
                             denominators[field], f"{context}/{dimension}/{field}")
            for event in sorted(labels):
                row = details.get(key + (dimension, event))
                result = dict(endpoint=key[0], cohort=key[1], condition=prefix, dimension=dimension, event=event)
                for field, denom_field, fraction_field in (
                    ("packets", "packet_denominator", "packet_fraction"),
                    ("wire_bytes", "wire_byte_denominator", "wire_byte_fraction"),
                    ("valid_payload_bytes", "valid_payload_byte_denominator", "valid_payload_byte_fraction"),
                ):
                    value, denominator = metric(row, field), denominators[field]
                    fraction = value / denominator if denominator else None
                    result.update({field: value, denom_field: denominator, fraction_field: fraction})
                    if row:
                        checks.equal("conditional_denominator_kind", row["denominator_kind"], prefix,
                                     f"{context}/{dimension}/{event}")
                        checks.equal("conditional_declared_denominator", integer(row[denom_field]), denominator,
                                     f"{context}/{dimension}/{event}/{field}")
                        checks.close("conditional_declared_fraction", number(row[fraction_field]), fraction,
                                     f"{context}/{dimension}/{event}/{field}")
                    checks.check("conditional_bounds", 0 <= value <= denominator, f"{context}/{dimension}/{event}/{field}")
                conditional_rows.append(result)
                overall_dim = "ack_event" if prefix == "ack_bearing" else "seq_event"
                overall = details.get(key + (overall_dim, event))
                if prefix in {"payload_bearing", "ack_bearing"}:
                    for field in MEASURES:
                        adjustment = metric(invalid, field) if event == "INVALID" else 0
                        checks.equal("conditional_vs_marginal", metric(row, field), metric(overall, field) - adjustment,
                                     f"{context}/{dimension}/{event}/{field}")
                if prefix == "data":
                    payload_row = details.get(key + ("seq_event_given_payload", event))
                    for field in MEASURES:
                        checks.check("data_within_payload_condition", metric(row, field) <= metric(payload_row, field),
                                     f"{context}/{event}/{field}")

    runs = unique_rows(read_csv(directory / "normal_runs.csv"), ("endpoint", "cohort"), checks, "normal_runs")
    histograms = defaultdict(Counter)
    for row in read_csv(directory / "normal_run_histogram.csv"):
        key = row["endpoint"], row["cohort"]
        length, count = integer(row["run_packets"]), integer(row["runs"])
        checks.check("run_histogram_positive", length > 0 and count > 0 and key in cohorts, str(key))
        checks.check("run_histogram_unique", length not in histograms[key], str(key), run_packets=length)
        histograms[key][length] += count
    checks.equal("run_cohort_set", sorted(runs), sorted(cohorts))
    reservoir = integer(summary["reservoir_size"])
    for key, row in runs.items():
        label, histogram = "/".join(key), histograms[key]
        n, total = sum(histogram.values()), sum(k * v for k, v in histogram.items())
        checks.equal("routine_definition", row["definition"], "routine_observed", label)
        checks.equal("run_histogram_count", integer(row["run_count"]), n, label)
        checks.equal("run_histogram_packets", integer(row["run_packet_total"]), total, label)
        checks.close("run_mean", number(row["run_packets_mean"]), total / n if n else None, label)
        checks.close("run_max", number(row["run_packets_max"]), max(histogram) if histogram else None, label)
        for q in (.5, .9, .99):
            target, cumulative, expected_quantile = math.ceil(n * q), 0, None
            for length, frequency in sorted(histogram.items()):
                cumulative += frequency
                if cumulative >= target:
                    expected_quantile = length
                    break
            checks.close("run_exact_quantile", number(row[f"run_packets_p{int(q * 100)}"]), expected_quantile, f"{label}/{q}")
        lower = metric(details.get(key + ("seq_event_given_data", "IN_ORDER")), "packets")
        upper = lower + metric(details.get(key + ("packet_type", "PURE_ACK")), "packets")
        checks.check("run_routine_packet_bounds", lower <= total <= upper, label, lower=lower, actual=total, upper=upper)
        checks.equal("run_duration_count", integer(row["duration_s_count"]), n, label)
        checks.equal("run_duration_reservoir", integer(row["duration_s_quantile_sample_size"]), min(n, reservoir), label)
        checks.equal("run_duration_reservoir", truth(row["duration_s_quantiles_exact"]), n <= reservoir, label)
        duration_values = [number(row[f"duration_s_{s}"]) for s in ("p50", "p90", "p99", "max")]
        if n:
            checks.check("run_duration_bounds", all(v is not None and math.isfinite(v) and v >= 0 for v in duration_values)
                         and duration_values == sorted(duration_values), label)
            checks.check("run_duration_bounds", 0 <= float(row["duration_s_mean"]) <= float(row["duration_s_max"]) + 1e-9, label)
        else:
            checks.check("run_duration_empty", all(v is None for v in duration_values), label)

    clustering = unique_rows(read_csv(directory / "anomaly_clustering.csv"), ("endpoint", "cohort"), checks, "anomaly_clustering")
    pairs = Counter()
    for row in read_csv(directory / "anomaly_adjacent_pairs.csv"):
        pairs[row["endpoint"], row["cohort"]] += integer(row["pairs"])
    checks.equal("anomaly_cohort_set", sorted(clustering), sorted(cohorts))
    for key, row in clustering.items():
        checks.equal("anomaly_packet_totals", integer(row["packets"]), metric(cohorts[key], "packets"), str(key))
        checks.equal("anomaly_candidate_totals", integer(row["candidate_packets"]), metric(cohorts[key], "candidate_packets"), str(key))
        checks.equal("anomaly_pair_totals", integer(row["adjacent_candidate_pairs"]), pairs[key], str(key))
        observed, baseline = integer(row["adjacent_candidate_pairs"]), float(row["random_adjacent_expectation"])
        checks.check("anomaly_bounds", 0 <= observed <= integer(row["candidate_packets"])
                     and math.isfinite(baseline) and baseline >= 0, str(key))
        checks.close("anomaly_ratio", number(row["observed_over_random_expectation"]), observed / baseline if baseline else None, str(key))

    examples = read_json(directory / "timeline_examples.json")
    specs = {r["example"]: r for r in examples}
    timeline_counts = Counter()
    with gzip.open(directory / "timeline_packets.csv.gz", "rt", newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            spec = specs[row["example"]]
            timeline_counts[row["example"]] += 1
            checks.check("timeline_membership", row["endpoint"] == spec["endpoint"]
                         and json.loads(row["connection"]) == json.loads(spec["connection"])
                         and float(spec["start_ts"]) <= float(row["ts"]) < float(spec["end_ts"]), row["example"])
    for name, spec in specs.items():
        checks.equal("timeline_counts", timeline_counts[name], integer(spec["observed_packets"]), name)
        selected = [r for r in profiles if r["endpoint"] == spec["endpoint"]
                    and float(spec["start_ts"]) <= float(r["start_ts"]) < float(spec["end_ts"])]
        if selected and all(json.loads(r["top1_connection"]) == json.loads(spec["connection"]) for r in selected):
            checks.equal("timeline_phase2_top1_packets", timeline_counts[name], sum(integer(r["top1_packets"]) for r in selected), name)

    for filename in ("cohort_summary.csv", "event_summary.csv", "normal_runs.csv"):
        with (directory / filename).open(newline="", encoding="utf-8") as handle:
            fields = next(csv.reader(handle))
        checks.check("no_fast_path_statistics", not any("fast_path" in f.lower() or "fastpath" in f.lower() for f in fields), filename)
    validated_files = [directory / name for name in (
        "classification_manifest.json", "summary_manifest.json", "sessions.csv",
        "cohort_summary.csv", "event_summary.csv", "normal_runs.csv", "normal_run_histogram.csv",
        "anomaly_clustering.csv", "anomaly_adjacent_pairs.csv", "timeline_examples.json", "timeline_packets.csv.gz")]
    validated_files += [phase2_dir / name for name in (
        "analysis_manifest.json", "endpoint_statistics.csv", "window_profiles_1s.csv.gz",
        "representative_samples.csv", "primary_windows/summary.json", "control_windows/summary.json")]
    summary_files = [directory / name for name in (
        "summary_manifest.json", "cohort_summary.csv", "event_summary.csv", "normal_runs.csv",
        "normal_run_histogram.csv", "anomaly_clustering.csv", "anomaly_adjacent_pairs.csv",
        "timeline_examples.json", "timeline_packets.csv.gz", "summary.json")]
    for source in classification_inputs:
        before = initial_input_metadata[str(source.resolve())]
        after = file_metadata(source)
        checks.equal("classification_inputs_stable_during_validation", after, before, source.name)
        for destination in summary_files:
            target = file_metadata(destination)
            checks.check("classification_before_every_summary", before["mtime_ns"] <= target["mtime_ns"],
                         f"{source.name} -> {destination.name}",
                         classification_mtime_ns=before["mtime_ns"], summary_mtime_ns=target["mtime_ns"])
    metadata_paths = set(validated_files + classification_inputs + summary_files)
    return dict(endpoint_totals=totals, session_fragments=len(sessions), cohorts=len(cohorts),
                conditional_rows=conditional_rows, timeline_packets_checked=sum(timeline_counts.values()),
                payload_exclusions=payload_exclusions,
                payload_validation_note="Original inferred payload is conserved against session totals. Valid payload excludes INVALID; any cohort exclusion is bounded by its endpoint exclusion because per-cohort raw-invalid bytes are not exported.",
                source_file_metadata={str(path.resolve()): file_metadata(path) for path in sorted(metadata_paths)},
                source_order_validation="Every final summary mtime_ns is at least every classification input mtime_ns; classification input size/mtime unchanged during validation. The pipeline ran classification then summary with no concurrent input writer.",
                input_sha256={str(path.resolve()): digest(path) for path in validated_files})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=ROOT / "report/phase3_mawi")
    parser.add_argument("--phase2-dir", type=Path, default=ROOT / "report/phase2_mawi")
    args = parser.parse_args(argv)
    checks = Checks()
    result = {}
    try:
        result = validate(args.input_dir, args.phase2_dir, checks)
    except Exception as error:
        checks.check("validator_execution", False, str(error), exception_type=type(error).__name__)
    passed = not checks.failures
    conditional_rows = result.pop("conditional_rows", [])
    if passed:
        destination = args.input_dir / "conditional_event_summary.csv"
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(conditional_rows[0]))
            writer.writeheader()
            writer.writerows(conditional_rows)
        result["input_sha256"][str(destination.resolve())] = digest(destination)
        result["source_file_metadata"][str(destination.resolve())] = file_metadata(destination)
    document = dict(all_checks_passed=passed, independent_validation=True,
                    fast_path_status="deferred_by_user", checks_run=checks.count,
                    check_groups=dict(checks.groups), failures=checks.failures,
                    validation_scope="aggregates and final sessions against phase2; selected timeline packets only; full events not reread or reclassified",
                    conditional_summary_written=passed,
                    conditional_event_summary_rows=len(conditional_rows) if passed else 0, **result)
    args.input_dir.mkdir(parents=True, exist_ok=True)
    temporary = args.input_dir / "validation.json.tmp"
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(args.input_dir / "validation.json")
    print(json.dumps(dict(all_checks_passed=passed, checks_run=checks.count,
                          failures=len(checks.failures)), ensure_ascii=False))
    if not passed:
        for failure in checks.failures[:12]:
            print(json.dumps(failure, ensure_ascii=False), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
