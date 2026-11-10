#!/usr/bin/env python3.11
"""Figures for the Data Center TCP Dataset inspection (excludes the 9 corrupt reno flows)."""
import sys, pandas as pd, numpy as np, matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt
rep = sys.argv[1] if len(sys.argv) > 1 else "report/dctcp"
d = pd.read_csv(f"{rep}/dctcp_per_flow.csv"); iv = pd.read_csv(f"{rep}/dctcp_intervals.csv.gz")
bad = set(zip(*d[(d.rows > 4000) | (d.segs_out < 0) | (d.segs_in < 0)][["cca", "run"]].to_numpy().T))
iv = iv[~pd.Series(list(zip(iv.cca, iv.run))).isin(bad).to_numpy()]; iv = iv[iv.dt > 0]

order = iv.groupby("cca").data_pps_out.median().sort_values(ascending=False).index
fig, ax = plt.subplots(figsize=(11, 4.5))
ax.boxplot([iv[iv.cca == c].data_pps_out.values for c in order], tick_labels=list(order), showfliers=False, whis=(1, 99))
ax.set_ylabel("data segments sent / s (per ~172 ms sample)")
ax.set_title("Data Center TCP Dataset: one iperf3 flow, data-segment rate by CCA (whiskers p1..p99)")
plt.setp(ax.get_xticklabels(), rotation=45, ha="right"); fig.tight_layout(); fig.savefig(f"{rep}/fig_pps_by_cca.png", dpi=130)

fig, axs = plt.subplots(2, 1, figsize=(11, 6), sharex=True)
for ax, (c, r) in zip(axs, [("cubic", "cubic10.log.csv"), ("bbr", "bbr10.log.csv")]):
    s = iv[(iv.cca == c) & (iv.run == r)]; t = s.t - s.t.min()
    ax.plot(t, s.data_pps_out, lw=0.6, label="data segs out / s"); ax.plot(t, s.segs_pps_in, lw=0.6, label="segs (ACKs) in / s")
    ax2 = ax.twinx(); ax2.plot(t, s.cwnd, color="gray", lw=0.5, alpha=0.6); ax2.set_ylabel("cwnd (segs)")
    ax.set_ylabel("pkts / s"); ax.set_title(f"{c}/{r}"); ax.legend(loc="upper right", fontsize=8)
axs[-1].set_xlabel("time (s)"); fig.tight_layout(); fig.savefig(f"{rep}/fig_flow_timeline.png", dpi=130)
print("figs written")
