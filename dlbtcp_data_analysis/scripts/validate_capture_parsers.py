#!/usr/bin/env python3
"""Independently build tiny pcap fixtures and validate local C parsers.

No real capture is scanned. Source files are compiled to private test binaries.
Assertions compare only fields for which fixtures provide exact ground truth.
"""
import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path


def tcp(payload=b"data", thl=20, captured_header=None):
    header = struct.pack("!HHIIBBHHH", 12345, 443, 1000, 2000,
                         (thl // 4) << 4, 0x18, 4096, 0, 0)
    header += b"\x01" * max(0, thl - 20)
    if captured_header is not None:
        header = header[:captured_header]
    return header + payload


def ipv4(l4, proto=6, fragment=0, declared_len=None):
    length = 20 + len(l4) if declared_len is None else declared_len
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, length, 1, fragment, 64,
                       proto, 0, b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02") + l4


def ipv6(l4, proto=6):
    return struct.pack("!IHBB16s16s", 6 << 28, len(l4), proto, 64,
                       bytes.fromhex("20010db8000000000000000000000001"),
                       bytes.fromhex("20010db8000000000000000000000002")) + l4


def ethernet(ip, v6=False, vlan=False):
    ethertype = 0x86dd if v6 else 0x0800
    return b"\x00" * 12 + (struct.pack("!HHH", 0x8100, 1, ethertype) if vlan else struct.pack("!H", ethertype)) + ip


def pcap(path, packets, linktype=1, nanosecond=False):
    magic = 0xa1b23c4d if nanosecond else 0xa1b2c3d4
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", magic, 2, 4, 0, 0, 96, linktype))
        for packet, caplen, wirelen, sec, subsec in packets:
            f.write(struct.pack("<IIII", sec, subsec, caplen, wirelen))
            f.write(packet[:caplen])


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args()
    project = args.project.resolve()
    out = project / "report/rebuilt_20261005"
    fixtures = out / "parser_fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    binary_paths, sources = {}, {}
    for name in ("pcap_inventory", "pcap2tsv_checked"):
        source = project / "scripts" / (name + ".c")
        snapshot = fixtures / (name + ".tested.c")
        snapshot.write_bytes(source.read_bytes())
        target = fixtures / (name + "_test")
        subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", str(snapshot), "-lpcap", "-o", str(target)], check=True)
        sources[name] = {"source": str(source.relative_to(project)), "sha256": sha(snapshot),
                         "tested_snapshot": str(snapshot.relative_to(project))}
        binary_paths[name] = target

    cases = []
    normal = ethernet(ipv4(tcp()))
    normal6 = ethernet(ipv6(tcp()), v6=True)
    base = {"packets": 1, "tcp_fixed_header_missing": 0, "tcp_invalid_data_offset": 0,
            "tcp_options_truncated": 0}
    # Expected columns use zero-based indexes in the fixed 16-column TSV.
    def case(name, packet, inventory, columns=None, emitted=1, caplen=None, linktype=1, nanosecond=False):
        path = fixtures / (name + ".pcap")
        caplen = len(packet) if caplen is None else caplen
        pcap(path, [(packet, caplen, len(packet), 100, 123456000 if nanosecond else 123456)],
             linktype=linktype, nanosecond=nanosecond)
        cases.append((name, path, {**base, **inventory}, columns or {}, emitted))

    common_tcp = {1: "6", 4: "12345", 5: "443", 6: "24", 7: "4", 8: "24",
                  9: "1000", 10: "2000", 11: "4096", 12: "20", 15: "0"}
    case("ipv4_normal", normal, {"ipv4": 1, "ipv6": 0, "ip_protocol_counts": {"6": 1}}, common_tcp)
    case("ipv6_normal", normal6, {"ipv4": 0, "ipv6": 1, "ip_protocol_counts": {"6": 1}}, common_tcp)
    fragment = struct.pack("!BBHI", 6, 0, 8, 0x12345678) + tcp()
    case("ipv6_nonfirst_fragment", ethernet(ipv6(fragment, 44), v6=True),
         {"ipv6": 1, "ip_protocol_counts": {"44": 1}}, emitted=0)
    first_fragment = struct.pack("!BBHI", 6, 0, 1, 0x12345678) + tcp()
    case("ipv6_first_fragment", ethernet(ipv6(first_fragment, 44), v6=True),
         {"ipv6": 1, "ip_protocol_counts": {"6": 1}}, common_tcp)
    case("ipv4_nonfirst_fragment", ethernet(ipv4(tcp(), fragment=1)),
         {"ipv4": 1, "ip_protocol_counts": {"6": 1}}, emitted=0)
    case("tcp_fixed_header_truncated", normal,
         {"tcp_fixed_header_missing": 1, "truncated_packets": 1},
         {1: "6", 4: "-1", 5: "-1", 6: "24", 7: "-1", 8: "-1", 12: "-1", 15: "1"}, caplen=44)
    case("tcp_dataoffset_too_small", ethernet(ipv4(tcp(thl=16))),
         {"tcp_invalid_data_offset": 1},
         {4: "12345", 5: "443", 6: "24", 7: "-1", 8: "-1", 9: "1000", 12: "-1", 15: "1"})
    case("tcp_dataoffset_exceeds_ip_payload", ethernet(ipv4(tcp(payload=b"", thl=60, captured_header=20))),
         {"tcp_invalid_data_offset": 1}, {6: "20", 7: "-1", 8: "-1", 12: "-1", 15: "1"})
    options = ethernet(ipv4(tcp(thl=32)))
    case("tcp_options_truncated", options,
         {"tcp_options_truncated": 1, "truncated_packets": 1},
         {6: "36", 7: "4", 8: "24", 9: "1000", 12: "32", 15: "1"}, caplen=58)
    case("ethernet_vlan", ethernet(ipv4(tcp()), vlan=True), {"ip_protocol_counts": {"6": 1}}, common_tcp)
    case("raw_ipv4", ipv4(tcp()), {"ip_protocol_counts": {"6": 1}}, common_tcp, linktype=228)
    case("raw_ipv6", ipv6(tcp()), {"ip_protocol_counts": {"6": 1}}, common_tcp, linktype=229)
    sll = struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800) + ipv4(tcp())
    case("linux_sll", sll, {"ip_protocol_counts": {"6": 1}}, common_tcp, linktype=113)
    case("nanosecond_pcap", normal, {"ip_protocol_counts": {"6": 1}}, {**common_tcp, 0: "100.123456"}, nanosecond=True)
    case("short_ethernet", normal[:10], {"short_headers": 1}, emitted=0)

    timestamps = fixtures / "timestamp_order.pcap"
    pcap(timestamps, [(normal, len(normal), len(normal), 100, 0),
                      (normal, len(normal), len(normal), 99, 750000),
                      (normal, len(normal), len(normal), 101, 0)])
    cases.append(("timestamp_order", timestamps, {"packets": 3, "timestamp_backwards": 1,
        "gaps_gt1s": 1, "gaps_gt100ms": 1, "max_gap_s": 1.25, "gaps_gt1s_total_s": 1.25}, {}, 3))

    results = []
    all_passed = True
    for name, path, expected, cols, emitted in cases:
        ir = subprocess.run([str(binary_paths["pcap_inventory"]), str(path)], text=True, capture_output=True)
        cr = subprocess.run([str(binary_paths["pcap2tsv_checked"]), "-u", "-6", str(path)], text=True, capture_output=True)
        failures = []
        if ir.returncode != 0 or cr.returncode != 0:
            failures.append(f"unexpected returncodes inventory={ir.returncode} converter={cr.returncode}")
        observed = json.loads(ir.stdout) if ir.returncode == 0 else {}
        for key, value in expected.items():
            if observed.get(key) != value:
                failures.append(f"inventory {key}: expected {value}, observed {observed.get(key)}")
        lines = [line.split("\t") for line in cr.stdout.splitlines()]
        if len(lines) != emitted:
            failures.append(f"emitted expected={emitted}, observed={len(lines)}")
        for row in lines:
            if len(row) != 16:
                failures.append(f"column count expected=16, observed={len(row)}")
            else:
                for col, value in cols.items():
                    if row[col] != value:
                        failures.append(f"TSV column {col + 1}: expected={value}, observed={row[col]}")
        all_passed &= not failures
        results.append({"case": name, "fixture": str(path.relative_to(project)), "passed": not failures,
                        "failures": failures, "expected_inventory": expected, "observed_inventory": observed,
                        "tsv_rows": lines, "converter_stderr": cr.stderr.strip()})

    # A cut record must fail; EOF at a record boundary must remain successful.
    broken = fixtures / "corrupt_truncated_record.pcap"
    broken.write_bytes((fixtures / "ipv4_normal.pcap").read_bytes()[:-1])
    bad_results = {}
    for name, binary in binary_paths.items():
        command = [str(binary)] + (["-6"] if name == "pcap2tsv_checked" else []) + [str(broken)]
        run = subprocess.run(command, text=True, capture_output=True)
        bad_results[name] = {"returncode": run.returncode, "stderr": run.stderr.strip(), "passed": run.returncode != 0}
        all_passed &= run.returncode != 0

    report = {"validation_date": "2026-10-05", "scope": "Synthetic tiny pcap fixtures only; no original large capture rerun",
              "sources": sources, "all_passed": bool(all_passed), "fixture_cases": results,
              "corrupt_record_tests": bad_results,
              "interpretation_notes": [
                  "TCP options truncation can coexist with complete fixed TCP fields and valid payload length calculated from IP metadata.",
                  "TSV column 16 merges option truncation and unusable TCP-header marking; column 13 == -1 identifies unusable TCP fixed/header metadata.",
                  "IPv4 non-first fragments retain IPv4 protocol 6 in inventory; IPv6 non-first fragments count Fragment header 44. These counters do not uniformly mean final transport-layer protocol.",
                  "Adjacent record timestamps may go backwards. Positive-gap totals and first/last duration are record-order statistics, not proof of lost capture time.",
                  "Fixture validation does not confirm the counts in a separate MAWI capture; those are results from inspecting its bytes."]}
    target = out / "parser_validation.json"
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"all_passed": report["all_passed"], "fixture_cases": len(results),
                      "report": str(target), "failed_cases": [r["case"] for r in results if not r["passed"]]}, indent=2))
    if not all_passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
