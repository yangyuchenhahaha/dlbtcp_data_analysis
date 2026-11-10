#!/usr/bin/env python3
"""Restore MAWI inputs and exact phase-1 accounting, without phase-2/3 analysis.

Requires g++, GNU sort, and gzip. The C++ scanner keeps exact TCP tuple counters
in memory, and preserves raw capture order while accounting for backwards
TIMESTAMPS. GNU sort performs stable numeric timestamp sorting for downstream
inputs; ties retain capture order. The original all-protocol TSV is unchanged.
All input/output timestamps are epoch seconds. No sampling correction is made.

Example:
  python3 scripts/prepare_mawi_inputs.py data/mawi/mawi_all.tsv \
    --data-dir data/mawi --report-dir report/rebuilt_20261005

Outputs mawi_endpoints.tsv (stable sorted TCP subset), mawi_tcp_sorted.tsv.gz
(stable sorted complete TCP), phase1_mawi_bidir.json (exact integer counters and
per-column validity), and mawi_prepared_inputs.json (order and provenance).
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(args, **kwargs):
    print(' '.join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input_tsv', type=Path)
    parser.add_argument('--data-dir', required=True, type=Path)
    parser.add_argument('--report-dir', required=True, type=Path)
    parser.add_argument('--endpoints', default='150.74.240.107,203.42.121.173,203.42.117.47')
    parser.add_argument('--sort-memory', default='4G')
    parser.add_argument('--sort-parallel', default='4')
    args = parser.parse_args()
    if not args.input_tsv.is_file() or args.input_tsv.name.endswith('.part'):
        parser.error('input must be a completed TSV, not a .part file')
    args.data_dir.mkdir(parents=True, exist_ok=True)
    args.report_dir.mkdir(parents=True, exist_ok=True)
    endpoints = list(dict.fromkeys(args.endpoints.split(',')))
    source = Path(__file__).with_suffix('.cpp')
    stats_path = args.report_dir / 'phase1_mawi_bidir.json'
    subset_path = args.data_dir / 'mawi_endpoints.tsv'
    tcp_path = args.data_dir / 'mawi_tcp_sorted.tsv.gz'
    for path in (stats_path, subset_path, tcp_path):
        if path.exists():
            parser.error(f'output already exists: {path}; choose a fresh destination')
    environment = dict(os.environ, LC_ALL='C')
    with tempfile.TemporaryDirectory(prefix='.mawi-prepare-', dir=args.data_dir) as temp:
        temporary = Path(temp)
        helper = temporary / 'scanner'
        raw_tcp = temporary / 'tcp_capture.tsv'
        raw_subset = temporary / 'selected_capture.tsv'
        sorted_tcp = temporary / 'tcp_sorted.tsv'
        stats_temporary = temporary / 'phase1_mawi_bidir.json'
        run(['g++', '-std=c++17', '-O3', '-o', helper, source])
        run([helper, args.input_tsv, raw_tcp, raw_subset, stats_temporary, *endpoints])
        stats = json.loads(stats_temporary.read_text())
        if stats['rows_total'] != stats['tcp_pkts'] + stats['udp_pkts']:
            raise ValueError('input has unexpected protocols beyond TCP/UDP')
        sort_options = ['sort', '--stable', '-t', '\t', '-k1,1n',
                        '--buffer-size', args.sort_memory, '--parallel', args.sort_parallel,
                        '--temporary-directory', temporary]
        subset_part = subset_path.with_suffix('.tsv.part')
        run([*sort_options, '-o', subset_part, raw_subset], env=environment)
        subset_part.replace(subset_path)
        raw_subset.unlink()
        run([*sort_options, '-o', sorted_tcp, raw_tcp], env=environment)
        raw_tcp.unlink()
        tcp_part = Path(str(tcp_path) + '.part')
        with tcp_part.open('wb') as output:
            run(['gzip', '-1', '-n', '-c', sorted_tcp], stdout=output)
        run(['gzip', '-t', tcp_part])
        tcp_part.replace(tcp_path)
        stats['prepared_input_order'] = {
            'mawi_all.tsv': 'original capture order; timestamp backwards counted, not silently sorted',
            'mawi_endpoints.tsv': 'stable numeric timestamp order; ties retain capture order',
            'mawi_tcp_sorted.tsv.gz': 'stable numeric timestamp order; ties retain capture order'}
        stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + '\n')
        manifest = {'source_tsv': str(args.input_tsv.resolve()),
            'source_bytes': args.input_tsv.stat().st_size,
            'source_order': stats['prepared_input_order']['mawi_all.tsv'],
            'source_rows': stats['rows_total'], 'source_tcp_rows': stats['tcp_pkts'],
            'full_span_start_ts': stats['capture_order_timestamps']['all_emitted']['min_ts'],
            'full_span_end_ts': stats['capture_order_timestamps']['all_emitted']['max_ts'],
            'selected_endpoints': endpoints, 'statistics': str(stats_path.resolve()),
            'outputs': {
                'endpoint_subset': {'path': str(subset_path.resolve()), 'rows': stats['selected_packets'],
                    'bytes': subset_path.stat().st_size, 'order': 'stable timestamp numeric',
                    'protocol': 'TCP', 'unique_connections': stats['selected_connections']},
                'tcp_full': {'path': str(tcp_path.resolve()), 'rows': stats['tcp_pkts'],
                    'bytes': tcp_path.stat().st_size, 'compression': 'gzip; gzip -t passed',
                    'order': 'stable timestamp numeric', 'protocol': 'TCP',
                    'unique_connections': stats['tcp_connections']}},
            'phase2_or_phase3_analysis_run': False,
            'sorting': {'tool': 'GNU sort --stable -t TAB -k1,1n', 'locale': 'C',
                        'buffer_size': args.sort_memory, 'parallel': args.sort_parallel},
            'limitations': ['Observed four-tuples are not separated into TCP sessions.',
                'Stable timestamp sorting changes backwards capture-order records; retain original pcap/all TSV for capture-order questions.',
                'Validity counts check values and ranges; they do not prove capture completeness or full TCP options.',
                'All TSV contains converter-retained TCP and UDP only, not every pcap packet.']}
        (args.report_dir / 'mawi_prepared_inputs.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({'tcp_rows': stats['tcp_pkts'], 'tcp_connections': stats['tcp_connections'],
                          'both_directions': stats['tcp_connections_both_dirs'],
                          'large_both_directions': stats['conns_ge100pkts_both_dirs'],
                          'selected_rows': stats['selected_packets']}, indent=2))


if __name__ == '__main__':
    main()
