#!/usr/bin/env python3.11
"""
Phase-1 endpoint-level summary from a 16-column TSV (pcap2tsv or fbcsv2tsv).

Answers, for a whole trace:
  0. field availability, timestamp resolution, protocol mix (TCP share)
  1. capture stalls (inter-packet gaps)             -> window validity (unsampled data only)
  2. sampling check: TCP seq contiguity             -> ~0% contiguous means packet-sampled
  3. per-IP bidirectionality and #connections       -> which endpoint to pick
  4. packet rate per window, trace-wide and for the top endpoints
  5. handshake pairing and pure-ACK share           -> only if TCP flags are present

Relaxed phase-2 bar (2026-09-29): TCP-dominant traces, coarse windows and
packet-sampled traces are acceptable. Hence windows and gap thresholds are
parameters, and --sample-rate scales packet counts to estimated true counts.

Usage:
  phase1_endpoint_summary.py <tsv> [--windows 0.01,0.1,1] [--gaps 0.1,1]
        [--sample-rate 1] [--top 20] [--endpoints 3] [--all-proto] [--out summary.json]
Examples:
  # unsampled pcap, fine windows (the original bar)
  phase1_endpoint_summary.py uni2.tsv --out uni2.json
  # Facebook Fbflow, 1:30000 sampled, integer-second timestamps
  phase1_endpoint_summary.py fbA.tsv --windows 1,10,60 --sample-rate 30000 --out fbA.json

TSV columns:
  0 ts 1 proto 2 src 3 dst 4 sport 5 dport 6 l4len 7 plen 8 flags 9 seq 10 ack
  11 win 12 thl 13 caplen 14 wirelen 15 opts_trunc      (-1 = not available)
"""
import json, argparse, math, sys
from collections import defaultdict
import numpy as np
import pandas as pd

ap = argparse.ArgumentParser()
ap.add_argument("tsv")
ap.add_argument("--windows", default="0.01,0.1,1", help="window sizes in seconds, comma separated")
ap.add_argument("--gaps", default="0.1,1", help="gap thresholds in seconds, comma separated")
ap.add_argument("--sample-rate", type=float, default=1.0,
                help="1 packet kept out of N; counts are multiplied by N for est_* fields")
ap.add_argument("--top", type=int, default=20, help="rows in top_ips / top_pairs")
ap.add_argument("--endpoints", type=int, default=3,
                help="per-window stats for this many busiest IPs (second pass); 0 disables")
ap.add_argument("--all-proto", action="store_true",
                help="analyze all rows, not only TCP (default: TCP rows, or rows with unknown proto)")
ap.add_argument("--contig-rows", type=int, default=5_000_000,
                help="max data packets used for the seq-contiguity sampling check")
ap.add_argument("--out", default=None)
ap.add_argument("--chunk", type=int, default=5_000_000)
a = ap.parse_args()

WINDOWS = sorted(float(x) for x in a.windows.split(","))
GAPS = sorted(float(x) for x in a.gaps.split(","))
SR = a.sample_rate

cols = ["ts","proto","src","dst","sport","dport","l4len","plen","flags","seq","ack",
        "win","thl","caplen","wirelen","opts_trunc"]
dt = {"ts":"float64","proto":"int16","src":"str","dst":"str","sport":"int32","dport":"int32",
      "l4len":"int32","plen":"int32","flags":"int16","seq":"int64","ack":"int64","win":"int32",
      "thl":"int16","caplen":"int32","wirelen":"int32","opts_trunc":"int8"}

def chunks():
    return pd.read_csv(a.tsv, sep="\t", header=None, names=cols, dtype=dt, comment="#",
                       chunksize=a.chunk, na_filter=False)

def wkey(w):  # label like "10ms", "1s", "60s"
    return f"{w*1000:g}ms" if w < 1 else f"{w:g}s"

# ---------------- pass 1 ----------------
n_all = 0; proto_cnt = defaultdict(int)
n = 0; first_ts = None; last_ts = None; prev_ts = None
min_dt = math.inf; n_int_ts = 0
gap_n = {g: 0 for g in GAPS}; gap_sum = {g: 0.0 for g in GAPS}; max_gap = 0.0; max_gap_at = None
have = {"ports": False, "flags": False, "seq": False, "plen": False, "thl": False}
syn = synack = pure_ack = fin = rst = data = opts_trunc = hdr_inc = 0
tx = defaultdict(int); rx = defaultdict(int); conns_by_ip = defaultdict(set)
pair_fwd = defaultdict(int); pair_rev = defaultdict(int)
win_cnt = {w: defaultdict(int) for w in WINDOWS}
contig_last = {}; contig_n = contig_ok = 0

for ch in chunks():
    n_all += len(ch)
    for p, c in ch["proto"].value_counts().items(): proto_cnt[int(p)] += int(c)
    if not a.all_proto:
        ch = ch[(ch["proto"] == 6) | (ch["proto"] == -1)]
    if len(ch) == 0: continue
    ts = ch["ts"].to_numpy()
    n += len(ts)
    if first_ts is None: first_ts = float(ts[0])
    last_ts = float(ts[-1])
    n_int_ts += int((ts == np.floor(ts)).sum())
    seq_ts = np.concatenate(([prev_ts], ts)) if prev_ts is not None else ts
    d = np.diff(seq_ts)
    if len(d):
        pos = d[d > 0]
        if len(pos): min_dt = min(min_dt, float(pos.min()))
        for g in GAPS:
            m = d > g; gap_n[g] += int(m.sum()); gap_sum[g] += float(d[m].sum())
        i = int(d.argmax())
        if d[i] > max_gap: max_gap = float(d[i]); max_gap_at = float(seq_ts[i])
    prev_ts = last_ts

    sp = ch["sport"].to_numpy(); dp = ch["dport"].to_numpy()
    fl = ch["flags"].to_numpy(); pl = ch["plen"].to_numpy(); thl = ch["thl"].to_numpy()
    sq = ch["seq"].to_numpy()
    have["ports"] |= bool((sp >= 0).any()); have["flags"] |= bool((fl >= 0).any())
    have["seq"] |= bool((sq >= 0).any()); have["plen"] |= bool((pl >= 0).any())
    have["thl"] |= bool((thl >= 0).any())

    ok = fl >= 0
    if ok.any():
        f2 = fl[ok]; p2 = pl[ok]
        is_syn = (f2 & 0x02) != 0; is_ack = (f2 & 0x10) != 0
        syn += int((is_syn & ~is_ack).sum()); synack += int((is_syn & is_ack).sum())
        fin += int(((f2 & 0x01) != 0).sum()); rst += int(((f2 & 0x04) != 0).sum())
        pure_ack += int(((p2 == 0) & is_ack & ~is_syn & ((f2 & 0x05) == 0)).sum())
        data += int(((p2 > 0) & ~is_syn).sum())
    okt = thl >= 0
    if okt.any():
        opts_trunc += int((ch["caplen"].to_numpy()[okt] < 34 + thl[okt]).sum())
    hdr_inc += int(((thl == -1) & (fl >= 0)).sum())

    # sampling check: is each data packet's seq == previous data packet's seq+len
    # in the same direction of the same connection?
    if contig_n < a.contig_rows and have["seq"] and have["flags"]:
        m = (pl > 0) & (fl >= 0) & ((fl & 0x02) == 0) & (sq >= 0)
        sub = ch.loc[m, ["src","sport","dst","dport","seq","plen"]]
        sub = sub.iloc[: max(0, a.contig_rows - contig_n)]
        if len(sub):
            k = sub["src"] + ":" + sub["sport"].astype(str) + ">" + sub["dst"] + ":" + sub["dport"].astype(str)
            end = (sub["seq"] + sub["plen"]) % 2**32
            prev_end = end.groupby(k.values).shift()
            first = prev_end.isna().to_numpy()
            carry = k[first].map(contig_last)
            prev_end = prev_end.to_numpy(dtype="float64", copy=True)
            prev_end[first] = carry.to_numpy(dtype="float64")
            has = ~np.isnan(prev_end)
            contig_n += int(has.sum())
            contig_ok += int((sub["seq"].to_numpy()[has] == prev_end[has]).sum())
            last = end.groupby(k.values).last()
            contig_last.update(last.to_dict())

    src = ch["src"]; dst = ch["dst"]
    for ip, c in src.value_counts().items(): tx[ip] += int(c)
    for ip, c in dst.value_counts().items(): rx[ip] += int(c)
    a_ = src.to_numpy(dtype=object); b_ = dst.to_numpy(dtype=object)
    swap = a_ > b_
    ka = np.where(swap, b_, a_); kb = np.where(swap, a_, b_)
    kap = np.where(swap, dp, sp); kbp = np.where(swap, sp, dp)
    for t in set(zip(ka, kap, kb, kbp)):
        conns_by_ip[t[0]].add(t); conns_by_ip[t[2]].add(t)
    pk = pd.Series(ka) + " " + pd.Series(kb)
    for kk, c in pk[~swap].value_counts().items(): pair_fwd[kk] += int(c)
    for kk, c in pk[swap].value_counts().items(): pair_rev[kk] += int(c)
    for w in WINDOWS:
        for kk, c in pd.Series(np.floor(ts / w).astype(np.int64)).value_counts().items():
            win_cnt[w][int(kk)] += int(c)

if n == 0:
    sys.exit("no rows after protocol filter (use --all-proto to keep non-TCP rows)")

duration = last_ts - first_ts
resolution = min_dt if min_dt < math.inf else None
int_frac = n_int_ts / n

def pct(arr, q):
    arr = np.sort(np.asarray(arr))
    return int(arr[min(len(arr) - 1, int(math.ceil(q * len(arr)) - 1))]) if len(arr) else 0

def rate_stats(cnt, w, span):
    v = np.fromiter(cnt.values(), dtype=np.int64)
    # windows are aligned to multiples of w, so count the aligned slots the trace touches
    total_windows = max(1, int(math.floor(last_ts / w)) - int(math.floor(first_ts / w)) + 1)
    r = {"window_s": w, "nonempty_windows": int(len(v)), "total_windows": total_windows,
         "empty_frac": round(1 - len(v) / total_windows, 4),
         "pkts_max": int(v.max()) if len(v) else 0, "pkts_p99": pct(v, 0.99), "pkts_p50": pct(v, 0.5),
         "pps_mean_over_span": float(v.sum() / (total_windows * w))}
    if SR != 1:
        r["est_pps_max"] = r["pkts_max"] * SR / w
        r["est_pps_p99"] = r["pkts_p99"] * SR / w
        r["est_pps_p50"] = r["pkts_p50"] * SR / w
        r["est_pps_mean_over_span"] = r["pps_mean_over_span"] * SR
    if resolution is not None and w < resolution * 0.999:
        r["warning"] = f"window smaller than timestamp resolution ({resolution:g} s); counts are meaningless"
    return r

# ---------------- pass 2: per-window load of the busiest endpoints ----------------
ips = set(tx) | set(rx)
tot = {ip: tx[ip] + rx[ip] for ip in ips}
top = sorted(tot.items(), key=lambda kv: -kv[1])
ep_ips = [ip for ip, _ in top[: a.endpoints]]
ep_stats = {}
if ep_ips:
    ep_cnt = {ip: {w: defaultdict(int) for w in WINDOWS} for ip in ep_ips}
    ep_conn = {ip: {w: defaultdict(lambda: defaultdict(int)) for w in WINDOWS} for ip in ep_ips}
    for ch in chunks():
        if not a.all_proto:
            ch = ch[(ch["proto"] == 6) | (ch["proto"] == -1)]
        for ip in ep_ips:
            m = (ch["src"] == ip) | (ch["dst"] == ip)
            if not m.any(): continue
            s = ch[m]
            peer = np.where(s["src"] == ip, s["dst"], s["src"])
            lport = np.where(s["src"] == ip, s["sport"], s["dport"])
            pport = np.where(s["src"] == ip, s["dport"], s["sport"])
            conn = pd.Series(peer).astype(str) + ":" + pd.Series(pport).astype(str) + "@" + pd.Series(lport).astype(str)
            for w in WINDOWS:
                wi = np.floor(s["ts"].to_numpy() / w).astype(np.int64)
                g = pd.DataFrame({"w": wi, "c": conn.values}).groupby(["w", "c"]).size()
                for (wk, ck), c in g.items():
                    ep_cnt[ip][w][int(wk)] += int(c); ep_conn[ip][w][int(wk)][ck] += int(c)
    for ip in ep_ips:
        per = {}
        for w in WINDOWS:
            r = rate_stats(ep_cnt[ip][w], w, duration)
            top1 = []; top5 = []; active = []
            for wk, cc in ep_conn[ip][w].items():
                vals = sorted(cc.values(), reverse=True); s_ = sum(vals)
                top1.append(vals[0] / s_); top5.append(sum(vals[:5]) / s_); active.append(len(vals))
            if top1:
                r["active_conns_p50"] = float(np.median(active)); r["active_conns_max"] = int(max(active))
                r["top1_share_p50"] = round(float(np.median(top1)), 3)
                r["top5_share_p50"] = round(float(np.median(top5)), 3)
                r["windows_top1_ge_50pct"] = round(float(np.mean(np.array(top1) >= 0.5)), 3)
            per[wkey(w)] = r
        ep_stats[ip] = {"pkts": tot[ip], "tx": tx[ip], "rx": rx[ip], "windows": per}

# ---------------- assemble ----------------
top_rows = [{"ip": ip, "pkts": c, "tx": tx[ip], "rx": rx[ip], "rx_share": round(rx[ip] / c, 3),
             "conns": len(conns_by_ip[ip])} for ip, c in top[: a.top]]
pairs = sorted(((pair_fwd[k] + pair_rev[k], pair_fwd[k], pair_rev[k], k)
                for k in set(pair_fwd) | set(pair_rev)), reverse=True)[: a.top]
min_pk = max(1, int(1000 / SR)) if SR > 1 else 1000
big = [ip for ip in ips if tot[ip] >= min_pk]
bidir = sum(1 for ip in big if min(tx[ip], rx[ip]) / max(tx[ip], rx[ip], 1) >= 0.2)

notes = []
if SR != 1:
    notes.append(f"packet-sampled 1:{SR:g}; est_* fields are counts x {SR:g}. Gaps and "
                 "per-connection shares on short windows are dominated by sampling noise.")
if not have["ports"]:
    notes.append("no L4 ports: 'conns' counts IP pairs, not connections")
if not have["flags"]:
    notes.append("no TCP flags/seq: handshake, pure-ACK and sampling-check stats unavailable")
if int_frac > 0.99:
    notes.append("timestamps are whole seconds: use windows >= 1 s")

summary = {
    "input": a.tsv, "params": {"windows": WINDOWS, "gaps": GAPS, "sample_rate": SR,
                               "all_proto": a.all_proto},
    "rows_total": n_all,
    "proto_share": {str(k): round(v / n_all, 4) for k, v in sorted(proto_cnt.items(), key=lambda kv: -kv[1])},
    "packets": n, "first_ts": first_ts, "last_ts": last_ts, "duration_s": duration,
    "fields_available": have,
    "timestamp": {"min_positive_delta_s": resolution, "integer_second_frac": round(int_frac, 4)},
    "gaps": {**{f"gt{wkey(g)}": gap_n[g] for g in GAPS},
             **{f"gt{wkey(g)}_total_s": round(gap_sum[g], 3) for g in GAPS},
             "max_gap_s": max_gap, "max_gap_at": max_gap_at},
    "sampling_check": ({"data_pkts_compared": contig_n,
                        "seq_contiguous_frac": round(contig_ok / contig_n, 4) if contig_n else None,
                        "hint": "near 1 = unsampled capture; near 0 = packet-sampled"}
                       if contig_n else "unavailable (needs seq and flags)"),
    "flags": ({"syn": syn, "synack": synack, "fin": fin, "rst": rst, "pure_ack": pure_ack,
               "data": data, "opts_truncated": opts_trunc, "hdr_incomplete": hdr_inc}
              if have["flags"] else "unavailable"),
    "ips_total": len(ips), f"ips_ge{min_pk}pkts": len(big), f"ips_ge{min_pk}_bidirectional": bidir,
    "rate": {wkey(w): rate_stats(win_cnt[w], w, duration) for w in WINDOWS},
    "top_endpoints_windows": ep_stats,
    "top_ips": top_rows,
    "top_pairs": [{"pkts": t, "fwd": f, "rev": r, "pair": k} for t, f, r, k in pairs],
    "notes": notes,
}
js = json.dumps(summary, indent=1)
if a.out: open(a.out, "w").write(js)
print(js)
