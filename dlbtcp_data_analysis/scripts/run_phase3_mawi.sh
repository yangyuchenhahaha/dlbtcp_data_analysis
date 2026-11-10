#!/usr/bin/env bash
# Reproduce phase 3 from the completed phase-2 endpoint inputs and window tags.
set -euo pipefail
DLBTCP_PHASE3_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$DLBTCP_PHASE3_ROOT"
export PYTHONPATH="$DLBTCP_PHASE3_ROOT/.python-packages${PYTHONPATH:+:$PYTHONPATH}"
export MPLCONFIGDIR="$DLBTCP_PHASE3_ROOT/.mplconfig"
python3 -m unittest scripts/test_phase3_tcp_events.py -q
python3 scripts/summarize_phase3.py --self-test
python3 scripts/phase3_tcp_events.py
python3 scripts/summarize_phase3.py
python3 scripts/validate_phase3_outputs.py
python3 scripts/phase3_frontier_sensitivity.py --self-test
python3 scripts/phase3_frontier_sensitivity.py
python3 scripts/plot_phase3.py
python3 scripts/report_phase3.py
python3 scripts/build_phase3_manifest.py
