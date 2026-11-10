#!/usr/bin/env python3.11
"""
Phase-1 inspection of the 'Data Center TCP Dataset' (Zenodo 10894768).

Each CSV = one iperf3 TCP flow, sampled periodically with `ss -i` style counters.
We check: sampling interval, duration, counter monotonicity, and derive per-flow
packet-level quantities that matter for DLBTCP (packets, not bytes):
  - data segments sent per second, ACK/segments received per second
  - ACKs per data segment (how many pure ACKs the receiver generates)
  - retransmitted bytes ratio
  - cwnd / rtt behaviour
Outputs: per-file table (CSV) + per-CCA summary (CSV) + JSON of dataset-level facts.
"""
import sys, os, glob, json
import numpy as np, pandas as pd

root = sys.argv[1]; outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
rows = []; interval_rows = []
issues = {"nonmono_lastrcv": 0, "nonmono_segs_out": 0, "empty": 0, "parse_err": 0}

for path in sorted(glob.glob(os.path.join(root, "*", "*.csv"))):
    cca = os.path.basename(os.path.dirname(path)); run = os.path.basename(path)
    try:
        df = pd.read_csv(path, sep=";", decimal=".", engine="python")
    except Exception as e:
        issues["parse_err"] += 1; continue
    df = df.loc[:, ~df.columns.str.startswith("Unnamed")]
    if len(df) < 2: issues["empty"] += 1; continue
    for c in ("bytes_retrans",):          # ss omits a counter when it is 0
        if c not in df.columns: df[c] = 0; issues["missing_col_"+c] = issues.get("missing_col_"+c, 0) + 1
    # wscale like "7,7" -> keep as string; numeric conversion for the rest
    for c in df.columns:
        if c != "wscale": df[c] = pd.to_numeric(df[c], errors="coerce")
    t = df["lastrcv"].to_numpy(dtype=float) / 1000.0   # ms -> s
    dt = np.diff(t)
    if (dt < 0).any(): issues["nonmono_lastrcv"] += 1
    if (np.diff(df["segs_out"].to_numpy()) < 0).any(): issues["nonmono_segs_out"] += 1
    dur = t[-1] - t[0]
    last = df.iloc[-1]
    d_out = np.diff(df["data_segs_out"].to_numpy(dtype=float))
    s_in = np.diff(df["segs_in"].to_numpy(dtype=float))
    s_out = np.diff(df["segs_out"].to_numpy(dtype=float))
    good = dt > 0
    pps_out = d_out[good] / dt[good]; pps_in = s_in[good] / dt[good]
    rows.append({
        "cca": cca, "run": run, "rows": len(df), "duration_s": dur,
        "interval_med_ms": float(np.median(dt) * 1000), "interval_p99_ms": float(np.percentile(dt, 99) * 1000),
        "mss": int(last["mss"]), "rtt_med_ms": float(df["rtt"].median()), "rtt_max_ms": float(df["rtt"].max()),
        "cwnd_med": float(df["cwnd"].median()), "cwnd_max": float(df["cwnd"].max()),
        "bytes_sent": int(last["bytes_sent"]), "bytes_retrans": int(last["bytes_retrans"]),
        "segs_out": int(last["segs_out"]), "segs_in": int(last["segs_in"]), "data_segs_out": int(last["data_segs_out"]),
        "delivered": int(last["delivered"]),
        "tput_mbps": float(last["bytes_sent"] * 8 / dur / 1e6) if dur > 0 else np.nan,
        "data_pps_out_mean": float(last["data_segs_out"] / dur) if dur > 0 else np.nan,
        "segs_pps_in_mean": float(last["segs_in"] / dur) if dur > 0 else np.nan,
        "data_pps_out_max_interval": float(pps_out.max()) if len(pps_out) else np.nan,
        "segs_pps_in_max_interval": float(pps_in.max()) if len(pps_in) else np.nan,
        "acks_per_data_seg": float(last["segs_in"] / max(last["data_segs_out"], 1)),
        "retrans_ratio": float(last["bytes_retrans"] / max(last["bytes_sent"], 1)),
        "avg_data_seg_bytes": float(last["bytes_sent"] / max(last["data_segs_out"], 1)),
        "nondata_segs_out": int(last["segs_out"] - last["data_segs_out"]),
    })
    interval_rows.append(pd.DataFrame({"cca": cca, "run": run, "t": t[1:][good], "dt": dt[good],
                                       "data_pps_out": pps_out, "segs_pps_in": pps_in,
                                       "cwnd": df["cwnd"].to_numpy()[1:][good], "rtt": df["rtt"].to_numpy()[1:][good]}))

per_file = pd.DataFrame(rows)
per_file.to_csv(os.path.join(outdir, "dctcp_per_flow.csv"), index=False)
iv = pd.concat(interval_rows, ignore_index=True)
iv.to_csv(os.path.join(outdir, "dctcp_intervals.csv.gz"), index=False)

agg = per_file.groupby("cca").agg(
    runs=("run", "count"), rows_med=("rows", "median"), dur_med_s=("duration_s", "median"),
    interval_med_ms=("interval_med_ms", "median"), tput_mbps_med=("tput_mbps", "median"),
    rtt_med_ms=("rtt_med_ms", "median"), cwnd_med=("cwnd_med", "median"),
    data_pps_out=("data_pps_out_mean", "median"), segs_pps_in=("segs_pps_in_mean", "median"),
    data_pps_out_max=("data_pps_out_max_interval", "median"), acks_per_data=("acks_per_data_seg", "median"),
    retrans_ratio=("retrans_ratio", "median"), avg_seg_bytes=("avg_data_seg_bytes", "median"),
).sort_values("tput_mbps_med", ascending=False)
agg.to_csv(os.path.join(outdir, "dctcp_per_cca.csv"))

facts = {
    "files": len(per_file), "ccas": sorted(per_file["cca"].unique().tolist()),
    "issues": issues,
    "rows": {"min": int(per_file["rows"].min()), "med": int(per_file["rows"].median()), "max": int(per_file["rows"].max())},
    "duration_s": {"min": float(per_file["duration_s"].min()), "med": float(per_file["duration_s"].median()), "max": float(per_file["duration_s"].max())},
    "interval_ms": {"min": float(per_file["interval_med_ms"].min()), "med": float(per_file["interval_med_ms"].median()), "max": float(per_file["interval_med_ms"].max())},
    "rows_7201_ccas": per_file.loc[per_file["rows"] > 4000, "cca"].value_counts().to_dict(),
    "mss": per_file["mss"].value_counts().to_dict(),
    "rtt_med_ms_overall": float(per_file["rtt_med_ms"].median()),
    "tput_mbps": {"min": float(per_file["tput_mbps"].min()), "med": float(per_file["tput_mbps"].median()), "max": float(per_file["tput_mbps"].max())},
    "data_pps_out": {"med": float(per_file["data_pps_out_mean"].median()), "max_interval_overall": float(per_file["data_pps_out_max_interval"].max())},
    "segs_pps_in": {"med": float(per_file["segs_pps_in_mean"].median()), "max_interval_overall": float(per_file["segs_pps_in_max_interval"].max())},
    "acks_per_data_seg": {"min": float(per_file["acks_per_data_seg"].min()), "med": float(per_file["acks_per_data_seg"].median()), "max": float(per_file["acks_per_data_seg"].max())},
    "retrans_ratio": {"med": float(per_file["retrans_ratio"].median()), "p90": float(per_file["retrans_ratio"].quantile(0.9)), "max": float(per_file["retrans_ratio"].max())},
    "nondata_segs_out_med": float(per_file["nondata_segs_out"].median()),
}
json.dump(facts, open(os.path.join(outdir, "dctcp_facts.json"), "w"), indent=1)
print(json.dumps(facts, indent=1))
print()
print(agg.round(3).to_string())
