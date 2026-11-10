#!/usr/bin/env bash
set -euo pipefail
DLBTCP_GRAIN_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd -- "$DLBTCP_GRAIN_ROOT"
python3 scripts/phase2_endpoint_windows.py data/mawi/mawi_endpoints.tsv \
  --endpoints 150.74.240.107,203.42.121.173,203.42.117.47 \
  --out-dir report/phase2_mawi/window_granularity_20261021/core_primary \
  --windows 0.01,0.1 --core-windows 0.01,0.1 --core-counts 8 \
  --core-policies hash,lpt --hash-repeats 1 \
  --span-start 1767157200.398184 --span-end 1767158100.170696
python3 scripts/phase2_endpoint_windows.py data/mawi/phase2_controls.tsv \
  --endpoints 2001:fab8:1071:93ea:700:1a:3fc1:7e80,202.249.10.115,43.15.244.195 \
  --out-dir report/phase2_mawi/window_granularity_20261021/core_control \
  --windows 0.01,0.1 --core-windows 0.01,0.1 --core-counts 8 \
  --core-policies hash,lpt --hash-repeats 1 \
  --span-start 1767157200.398184 --span-end 1767158100.170696
python3 scripts/compare_phase2_window_granularity.py
