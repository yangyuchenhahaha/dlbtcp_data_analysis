#!/usr/bin/env bash
# Reproduce the completed phase-2 outputs from locally recovered MAWI inputs.
set -euo pipefail
DLBTCP_PROJECT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$DLBTCP_PROJECT"
export PYTHONPATH="$DLBTCP_PROJECT/.python-packages${PYTHONPATH:+:$PYTHONPATH}"
export MPLCONFIGDIR="$DLBTCP_PROJECT/.mplconfig"
PRIMARY_ENDPOINTS='150.74.240.107,203.42.121.173,203.42.117.47'
CONTROL_ENDPOINTS='2001:fab8:1071:93ea:700:1a:3fc1:7e80,202.249.10.115,43.15.244.195'
if [[ ! -f data/mawi/phase2_controls.tsv ]]; then
  python3 scripts/extract_phase2_controls.py
fi
COMMON_WINDOWS=(--windows 0.001,0.01,0.1,1,10,60
  --span-start 1767157200.398184 --span-end 1767158100.170696
  --core-windows 1,10,60 --hash-repeats 16)
python3 scripts/phase2_connection_totals.py data/mawi/mawi_endpoints.tsv \
  --endpoints "$PRIMARY_ENDPOINTS" --out-dir report/phase2_mawi
python3 scripts/phase2_connection_totals.py data/mawi/phase2_controls.tsv \
  --endpoints "$CONTROL_ENDPOINTS" --out-dir report/phase2_mawi/controls_connections
python3 scripts/phase2_endpoint_windows.py data/mawi/mawi_endpoints.tsv \
  --endpoints "$PRIMARY_ENDPOINTS" "${COMMON_WINDOWS[@]}" \
  --out-dir report/phase2_mawi/primary_windows
python3 scripts/phase2_endpoint_windows.py data/mawi/phase2_controls.tsv \
  --endpoints "$CONTROL_ENDPOINTS" "${COMMON_WINDOWS[@]}" \
  --out-dir report/phase2_mawi/control_windows
python3 scripts/summarize_phase2_mawi.py
python3 scripts/plot_phase2_mawi.py
python3 scripts/plot_phase2_samples.py
python3 scripts/build_phase2_manifest.py
