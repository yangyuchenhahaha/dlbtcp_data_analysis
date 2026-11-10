#!/usr/bin/env python3.11
"""
fbcsv2tsv: convert the Facebook datacenter trace (fb_clusterX_full.csv,
Roy et al. SIGCOMM'15, Fbflow 1:30000 packet-header sampling) into the same
16-column TSV that pcap2tsv emits, so phase1_endpoint_summary.py can read it.

The public CSV has a header row. Confirmed columns (from the apnet23-reducing
code): timestamp, packetlength, srcrack, dstrack, srcpod, dstpod, intercluster.
The full file is also known to carry anonymized srcip/dstip. Whether it carries
L4 ports and the IP protocol is NOT confirmed, so every column is looked up by
name from a list of aliases; anything missing is written as -1 and reported.

Output columns (same as pcap2tsv):
  ts proto src dst sport dport l4len plen flags seq ack win thl caplen wirelen opts_trunc
Mapping:
  ts      <- timestamp (integer seconds in the public release)
  proto   <- protocol column if present, else -1 (unknown)
  src/dst <- srcip/dstip if present, else srcrack/dstrack (rack-level only)
  sport/dport <- L4 ports if present, else -1
  l4len   <- -1 ; plen <- -1 (payload length is not derivable)
  wirelen <- packetlength
  flags/seq/ack/win/thl/caplen/opts_trunc <- -1 (not in the trace)

Usage:
  fbcsv2tsv.py fb_clusterA_full.csv > fbA.tsv
  fbcsv2tsv.py --tcp-only fb_clusterA_full.csv > fbA_tcp.tsv   (needs a protocol column)
  zcat fb_clusterA_full.csv.gz | fbcsv2tsv.py - > fbA.tsv
Options:
  --tcp-only        keep only protocol==6 rows (error if no protocol column)
  --drop-intercluster  drop rows with intercluster==true (what apnet23 did)
  --limit N         stop after N data rows (for a quick look)
"""
import argparse, csv, sys

ALIASES = {
    "ts":    ["timestamp", "time", "ts"],
    "len":   ["packetlength", "packet_length", "pktlen", "length"],
    "srcip": ["srcip", "src_ip", "srcaddr"],
    "dstip": ["dstip", "dst_ip", "dstaddr"],
    "sport": ["srcl4port", "srcport", "src_port", "sport", "srcl4"],
    "dport": ["dstl4port", "dstport", "dst_port", "dport", "dstl4"],
    "proto": ["ipprotocol", "protocol", "proto", "ip_protocol"],
    "srcrack": ["srcrack"], "dstrack": ["dstrack"],
    "inter": ["intercluster"],
}

ap = argparse.ArgumentParser()
ap.add_argument("csv")
ap.add_argument("--tcp-only", action="store_true")
ap.add_argument("--drop-intercluster", action="store_true")
ap.add_argument("--limit", type=int, default=0)
a = ap.parse_args()

f = sys.stdin if a.csv == "-" else open(a.csv, newline="")
rd = csv.reader(f)
header = [h.strip().lower() for h in next(rd)]
idx = {}
for key, names in ALIASES.items():
    for n in names:
        if n in header:
            idx[key] = header.index(n); break

print(f"# header: {header}", file=sys.stderr)
print(f"# mapped: { {k: header[v] for k, v in idx.items()} }", file=sys.stderr)
missing = [k for k in ("ts", "len", "srcip", "dstip", "sport", "dport", "proto") if k not in idx]
if missing:
    print(f"# WARNING missing columns (written as -1): {missing}", file=sys.stderr)
if "ts" not in idx or "len" not in idx:
    sys.exit("fatal: need at least timestamp and packetlength columns")
if a.tcp_only and "proto" not in idx:
    sys.exit("fatal: --tcp-only needs a protocol column, none found")
use_ip = "srcip" in idx and "dstip" in idx
if not use_ip:
    print("# WARNING no IP columns; using rack IDs as src/dst (endpoint = rack)", file=sys.stderr)

def get(row, k, default="-1"):
    i = idx.get(k)
    if i is None or i >= len(row):
        return default
    v = row[i].strip()
    return default if v in ("", "N", "\\N") else v

out = sys.stdout; w = out.write
n_in = n_out = n_skip = 0
for row in rd:
    n_in += 1
    if a.limit and n_in > a.limit:
        break
    if a.drop_intercluster and get(row, "inter", "false").lower() == "true":
        n_skip += 1; continue
    proto = get(row, "proto")
    if a.tcp_only and proto != "6":
        n_skip += 1; continue
    src = get(row, "srcip") if use_ip else get(row, "srcrack")
    dst = get(row, "dstip") if use_ip else get(row, "dstrack")
    if src == "-1" or dst == "-1":
        n_skip += 1; continue
    w(f"{get(row,'ts')}\t{proto}\t{src}\t{dst}\t{get(row,'sport')}\t{get(row,'dport')}"
      f"\t-1\t-1\t-1\t-1\t-1\t-1\t-1\t-1\t{get(row,'len')}\t-1\n")
    n_out += 1
print(f"# rows_in={n_in} emitted={n_out} skipped={n_skip}", file=sys.stderr)
