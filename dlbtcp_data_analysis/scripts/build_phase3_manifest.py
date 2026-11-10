#!/usr/bin/env python3
"""Fingerprint the reproducible phase-3 source, input provenance and artifacts."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def record(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(8 * 1024 * 1024):
            h.update(block)
    try:
        name = str(path.relative_to(ROOT))
    except ValueError:
        name = str(path)
    return {'path': name, 'bytes': path.stat().st_size, 'sha256': h.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', type=Path, default=ROOT / 'report/phase3_mawi')
    args = parser.parse_args()
    classification = json.loads((args.out_dir / 'classification_manifest.json').read_text())
    validation = json.loads((args.out_dir / 'validation.json').read_text())
    if not validation.get('all_checks_passed'):
        raise RuntimeError('phase-3 validation has not passed')
    script_names = ['phase3_tcp_events.py', 'test_phase3_tcp_events.py', 'summarize_phase3.py',
                    'validate_phase3_outputs.py', 'phase3_frontier_sensitivity.py', 'plot_phase3.py', 'report_phase3.py',
                    'run_phase3_mawi.sh', 'build_phase3_manifest.py']
    provenance_names = ['analysis_manifest.json', 'endpoint_statistics.csv', 'window_profiles_1s.csv.gz',
                        'hotspot_segments_complete.csv', 'representative_samples.csv']
    metadata = {
        'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'status': 'phase3_event_classification_complete_fast_path_deferred',
        'phase3_real_trace_analysis_run': True,
        'fast_path_status': 'deferred_by_user',
        'scope': 'six phase-2-selected MAWI endpoints; full-history state followed by 1s cohort selection',
        'endpoint_packets': classification['endpoint_packets'],
        'total_endpoint_packets': classification['total_endpoint_packets'],
        'classification_inputs': classification['inputs'],
        'all_checks_passed': True,
        'scripts': [record(ROOT / 'scripts' / name) for name in script_names],
        'phase2_provenance': [record(ROOT / 'report/phase2_mawi' / name) for name in provenance_names],
        'capture_provenance': [record(ROOT / name) for name in
                               ['data/README.md', 'report/rebuilt_20261005/mawi_prepared_inputs.json',
                                'report/rebuilt_20261005/mawi_sorted_input_validation.json']],
        'artifacts': [record(p) for p in sorted(args.out_dir.rglob('*'))
                      if p.is_file() and p.name != 'analysis_manifest.json' and not p.name.endswith('.partial')],
        'references': classification['references'],
        'limitations': ['observed sequence-range repetition is not confirmed retransmission',
                        'timestamp order is not a verified receiver arrival order',
                        'missing handshake/one direction/unseen sequence ranges do not prove capture loss',
                        'normal observed runs are not a deployable or parallel fast-path fraction'],
    }
    destination = args.out_dir / 'analysis_manifest.json'
    destination.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n')
    print(f'phase3 manifest: {len(metadata["artifacts"])} artifacts; validation passed')


if __name__ == '__main__':
    main()
