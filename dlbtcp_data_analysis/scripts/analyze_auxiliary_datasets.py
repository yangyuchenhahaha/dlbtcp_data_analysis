#!/usr/bin/env python3
"""Recompute Facebook rack matrices and AWS/Azure experiment summaries.

Only Python's standard library is required. Inputs remain unchanged. Facebook
values are sampled packet-byte sums, never endpoint/connection packet counts.
AWS/Azure metadata records are excluded from experiment counts; negative loss
values are preserved and marked instead of silently clipped.
"""
import argparse
import collections
import csv
import gzip
import hashlib
import json
import math
import statistics
from pathlib import Path


def quantile(values, p):
    if not values:
        return None
    s = sorted(values)
    x = (len(s) - 1) * p
    lo = int(x)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (x - lo)


def describe(values):
    vals = [float(v) for v in values if v is not None and math.isfinite(float(v))]
    if not vals:
        return {"count": 0}
    mean = statistics.fmean(vals)
    sd = statistics.pstdev(vals)
    return {"count": len(vals), "min": min(vals), "p05": quantile(vals, .05),
            "p50": quantile(vals, .5), "p95": quantile(vals, .95), "max": max(vals),
            "mean": mean, "std_population": sd, "cv": sd / mean if mean else None}


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False) + "\n")


def csv_writer(path, fields):
    f = gzip.open(path, "wt", newline="") if path.suffix == ".gz" else path.open("w", newline="")
    writer = csv.DictWriter(f, fields)
    writer.writeheader()
    return f, writer


def ratio(a, b):
    return a / b if b else None


def facebook(project):
    out = project / "report/facebook"
    out.mkdir(parents=True, exist_ok=True)
    windows_fields = ["cluster", "window_index", "relative_start_s", "relative_end_s",
                      "sampled_bytes", "nonzero_cells", "cells", "nonzero_fraction",
                      "intra_rack_bytes", "intra_rack_share", "inter_rack_bytes",
                      "sending_racks", "receiving_racks", "top1_sender_rack", "top1_sender_share",
                      "top5_sender_share", "top1_pair_src", "top1_pair_dst", "top1_pair_share",
                      "nonzero_cell_p50_bytes", "max_cell_bytes"]
    rack_fields = ["cluster", "window_index", "rack_index", "sent_sampled_bytes", "received_sampled_bytes",
                   "intra_rack_sampled_bytes", "sent_share", "received_share", "out_nonzero_racks", "in_nonzero_racks"]
    pair_fields = ["cluster", "src_rack", "dst_rack", "sampled_bytes_all_windows", "nonzero_windows",
                   "share_all_cluster_sampled_bytes", "intra_rack"]
    wf, ww = csv_writer(out / "windows.csv", windows_fields)
    rf, rw = csv_writer(out / "rack_windows.csv.gz", rack_fields)
    pf, pw = csv_writer(out / "rack_pairs.csv.gz", pair_fields)
    summaries = {}
    try:
        for cluster in ("a", "b"):
            path = project / f"data/facebook/facebook_cluster_{cluster}_10min.json"
            data = json.loads(path.read_text())["data"]
            n = len(data[0])
            assert all(len(m) == n and all(len(row) == n for row in m) for m in data)
            pair_sums = [[0] * n for _ in range(n)]
            pair_nonzero = [[0] * n for _ in range(n)]
            send_all, receive_all = [0] * n, [0] * n
            total, diagonal, nz_total = 0, 0, 0
            nonzero_values, window_totals, top1shares = [], [], []
            for t, matrix in enumerate(data):
                send, receive = [sum(row) for row in matrix], [0] * n
                out_nz, in_nz = [0] * n, [0] * n
                values = []
                peak_value, peak_src, peak_dst = -1, None, None
                for i, row in enumerate(matrix):
                    for j, val in enumerate(row):
                        if not isinstance(val, int) or val < 0:
                            raise ValueError(f"invalid matrix value {cluster}:{t}:{i}:{j}")
                        receive[j] += val
                        pair_sums[i][j] += val
                        if val:
                            values.append(val)
                            out_nz[i] += 1
                            in_nz[j] += 1
                            pair_nonzero[i][j] += 1
                        if val > peak_value:
                            peak_value, peak_src, peak_dst = val, i, j
                wtotal = sum(send)
                assert wtotal == sum(receive)
                diag = sum(matrix[i][i] for i in range(n))
                ranks = sorted(range(n), key=lambda i: (-send[i], i))
                top1 = ratio(send[ranks[0]], wtotal)
                window_totals.append(wtotal)
                top1shares.append(top1)
                ww.writerow(dict(zip(windows_fields, [cluster.upper(), t, t * 600, (t + 1) * 600,
                    wtotal, len(values), n * n, len(values) / (n * n), diag, ratio(diag, wtotal),
                    wtotal - diag, sum(x > 0 for x in send), sum(x > 0 for x in receive),
                    ranks[0], top1, ratio(sum(send[i] for i in ranks[:5]), wtotal),
                    peak_src, peak_dst, ratio(peak_value, wtotal), quantile(values, .5), peak_value])))
                for i in range(n):
                    send_all[i] += send[i]
                    receive_all[i] += receive[i]
                    rw.writerow(dict(zip(rack_fields, [cluster.upper(), t, i, send[i], receive[i],
                        matrix[i][i], ratio(send[i], wtotal), ratio(receive[i], wtotal), out_nz[i], in_nz[i]])))
                total += wtotal
                diagonal += diag
                nz_total += len(values)
                nonzero_values.extend(values)
            assert sum(send_all) == sum(receive_all) == sum(map(sum, pair_sums)) == total
            ranks = sorted(range(n), key=lambda i: (-send_all[i], i))
            for i in range(n):
                for j in range(n):
                    pw.writerow(dict(zip(pair_fields, [cluster.upper(), i, j, pair_sums[i][j],
                        pair_nonzero[i][j], ratio(pair_sums[i][j], total), int(i == j)])))
            summaries[cluster.upper()] = {
                "input": str(path.relative_to(project)), "sha256": sha256(path), "file_bytes": path.stat().st_size,
                "windows": len(data), "window_s": 600, "covered_bins_s": len(data) * 600,
                "covered_bins_are_not_exact_capture_duration": True, "racks": n,
                "cells": len(data) * n * n, "nonzero_cells": nz_total,
                "nonzero_fraction": nz_total / (len(data) * n * n), "total_sampled_bytes": total,
                "intra_rack_sampled_bytes": diagonal, "intra_rack_share": ratio(diagonal, total),
                "top1_sender_rack_all_windows": ranks[0], "top1_sender_share_all_windows": ratio(send_all[ranks[0]], total),
                "top5_sender_share_all_windows": ratio(sum(send_all[i] for i in ranks[:5]), total),
                "nonzero_cell_p50_bytes": quantile(nonzero_values, .5), "max_cell_bytes": max(nonzero_values),
                "window_sampled_bytes": describe(window_totals), "window_top1_sender_share": describe(top1shares),
                "sent_sampled_bytes_per_rack": send_all, "received_sampled_bytes_per_rack": receive_all,
                "source": "https://github.com/apnet23-reducing/evaluation/tree/main/data",
                "interpretation": "600 s rack-to-rack sampled packet-byte sums; no packet counts, IP, ports or TCP events. Zero means no observed sampled bytes; it does not prove no actual traffic. No 30000 scaling applied. Rack indexes are matrix positions.",
            }
            print(f"Facebook {cluster.upper()}: {len(data)} windows, {n} racks, {total} sampled bytes", flush=True)
        write_json(out / "summary.json", summaries)
    finally:
        wf.close(); rf.close(); pf.close()
    return summaries


def awsazure(project):
    out = project / "report/awsazure"
    out.mkdir(parents=True, exist_ok=True)
    fields = ["experiment_id", "source_file", "source_record", "provider", "protocol", "size_sender",
              "size_receiver", "region_sender", "region_receiver", "start_epoch_s", "duration_s",
              "throughput_samples", "loss_samples", "union_seconds", "throughput_mean_mbps",
              "throughput_std_mbps", "throughput_p50_mbps", "throughput_p95_mbps", "throughput_min_mbps",
              "throughput_max_mbps", "throughput_cv", "throughput_synthetic_mean_mbps",
              "throughput_mean_difference_mbps", "loss_mean_pct", "loss_min_pct", "loss_max_pct",
              "loss_negative_samples", "loss_gt100_samples", "throughput_negative_samples",
              "delay_mean_reported", "delay_has_detailed", "expected_seconds_without_throughput"]
    seconds_fields = ["experiment_id", "provider", "protocol", "epoch_second", "relative_second",
                      "throughput_mbps", "loss_pct", "loss_negative", "loss_gt100", "throughput_negative"]
    ef, ew = csv_writer(out / "experiments.csv", fields)
    sf, sw = csv_writer(out / "seconds.csv.gz", seconds_fields)
    manifest, rows = [], []
    metadata_records = 0
    seconds_count = 0
    try:
        for path in sorted((project / "data/awsazure/raw").rglob("*.json")):
            content = json.loads(path.read_text())
            records = content if isinstance(content, list) else [content]
            source = str(path.relative_to(project))
            valid = [x for x in records if isinstance(x, dict) and "results" in x and "proto" in x]
            metadata_records += len(records) - len(valid)
            manifest.append({"file": source, "sha256": sha256(path), "json_records": len(records),
                             "result_experiments": len(valid), "metadata_records": len(records) - len(valid)})
            for index, x in enumerate(records):
                if not isinstance(x, dict) or "results" not in x or "proto" not in x:
                    continue
                experiment_id = len(rows) + 1
                result, camp = x["results"], x.get("camp", {})
                throughput = result.get("tput", {}).get("detailed") or {}
                loss = result.get("loss", {}).get("detailed") or {}
                throughput = {int(k): float(v) for k, v in throughput.items() if v is not None}
                loss = {int(k): float(v) for k, v in loss.items() if v is not None}
                ts = describe(list(throughput.values()))
                ls = describe(list(loss.values()))
                start = int(x["start"])
                duration = float(x.get("duration", 0))
                synt = result.get("tput", {}).get("synt") or {}
                synt_mean = synt.get("mean")
                provider = "AWS" if "AWS" in path.parts else "Azure" if "Azure" in path.parts else "Unknown"
                all_seconds = sorted(throughput.keys() | loss.keys())
                expected = set(range(start, start + int(duration)))
                row = dict(zip(fields, [experiment_id, source, index, provider, x["proto"], camp.get("size_snd"),
                    camp.get("size_rcv"), camp.get("region_snd"), camp.get("region_rcv"), start, duration,
                    len(throughput), len(loss), len(all_seconds), ts.get("mean"), ts.get("std_population"),
                    ts.get("p50"), ts.get("p95"), ts.get("min"), ts.get("max"), ts.get("cv"), synt_mean,
                    ts["mean"] - synt_mean if synt_mean is not None and ts["count"] else None,
                    ls.get("mean"), ls.get("min"), ls.get("max"), sum(v < 0 for v in loss.values()),
                    sum(v > 100 for v in loss.values()), sum(v < 0 for v in throughput.values()),
                    (result.get("delay", {}).get("synt") or {}).get("mean"),
                    int(bool(result.get("delay", {}).get("detailed"))), len(expected - throughput.keys())]))
                ew.writerow(row)
                rows.append(row)
                for epoch in all_seconds:
                    tv, lv = throughput.get(epoch), loss.get(epoch)
                    sw.writerow(dict(zip(seconds_fields, [experiment_id, provider, x["proto"], epoch, epoch-start,
                        tv, lv, int(lv is not None and lv < 0), int(lv is not None and lv > 100),
                        int(tv is not None and tv < 0)])))
                seconds_count += len(all_seconds)
        groups = collections.defaultdict(list)
        fine_groups = collections.defaultdict(list)
        for row in rows:
            groups[(row["provider"], row["protocol"])].append(row)
            fine_groups[tuple(row[k] for k in ["provider", "protocol", "size_sender", "region_sender", "region_receiver"])].append(row)
        def group_result(key, r):
            return {"group": key, "experiments": len(r), "throughput_mean_mbps_experiment_weighted":
                describe([v["throughput_mean_mbps"] for v in r]),
                "throughput_cv": describe([v["throughput_cv"] for v in r]),
                "loss_mean_pct_experiment_weighted": describe([v["loss_mean_pct"] for v in r]),
                "delay_mean_reported": describe([v["delay_mean_reported"] for v in r]),
                "seconds": sum(v["union_seconds"] for v in r),
                "negative_loss_samples": sum(v["loss_negative_samples"] for v in r)}
        grouped = [group_result(key, r) for key, r in sorted(groups.items())]
        fine = [group_result(key, r) for key, r in sorted(fine_groups.items())]
        summary = {"source": "https://data.mendeley.com/datasets/tvpj528mwz/1", "source_doi": "10.17632/tvpj528mwz.1",
            "archive_sha256": sha256(project / "data/awsazure/ds.tar.gz"), "json_files": len(manifest),
            "experiments": len(rows), "metadata_records_excluded": metadata_records,
            "protocol_counts": dict(collections.Counter(v["protocol"] for v in rows)),
            "provider_counts": dict(collections.Counter(v["provider"] for v in rows)),
            "seconds_rows": seconds_count, "duration_s": describe([v["duration_s"] for v in rows]),
            "throughput_samples": sum(v["throughput_samples"] for v in rows),
            "loss_samples": sum(v["loss_samples"] for v in rows),
            "negative_loss_samples": sum(v["loss_negative_samples"] for v in rows),
            "loss_gt100_samples": sum(v["loss_gt100_samples"] for v in rows),
            "negative_throughput_samples": sum(v["throughput_negative_samples"] for v in rows),
            "experiments_with_negative_loss": sum(v["loss_negative_samples"] > 0 for v in rows),
            "experiments_missing_expected_throughput_seconds": sum(v["expected_seconds_without_throughput"] > 0 for v in rows),
            "delay_detailed_experiments": sum(v["delay_has_detailed"] for v in rows),
            "groups": grouped,
            "interpretation": "Independent nuttcp performance experiments with aggregate throughput/loss by epoch second. These rows are not packet traces or simultaneous server connections. Negative reported loss is preserved and flagged. Delay is the source-reported statistic, not assumed to be TCP RTT. Group throughput uses equal experiment weighting; no network packet counts are inferred."}
        write_json(out / "summary.json", summary)
        write_json(out / "groups_by_vm_region.json", fine)
        write_json(out / "source_files.json", manifest)
        print(f"AWS/Azure: {len(rows)} experiments, {seconds_count} seconds, protocols={summary['protocol_counts']}", flush=True)
        return summary
    finally:
        ef.close(); sf.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--only", choices=["facebook", "awsazure"])
    args = parser.parse_args()
    if args.only != "awsazure":
        facebook(args.project)
    if args.only != "facebook":
        awsazure(args.project)


if __name__ == "__main__":
    main()
