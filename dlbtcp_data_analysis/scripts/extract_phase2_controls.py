#!/usr/bin/env python3
"""Extract bidirectional endpoint controls from the full sorted MAWI TCP TSV.

The defaults supplement the existing three endpoint traces with IPv6 and IPv4
endpoints of lower packet volume.  Selection uses phase-1 packet counts,
direction shares and connection counts, never phase-2 concentration or hotness.
They are candidate ordinary/balanced controls; the common subsequent window
analysis determines which bins are actually ordinary or balanced.

Every matching original 16-column row is preserved, once, in source order.
Connections are observed local-port/peer-IP/peer-port tuples per endpoint;
separate TCP sessions reusing the same tuple are not separated.  An endpoint
observed on the monitored backbone link is not its complete server workload.

Example (from the project directory):
  python3 scripts/extract_phase2_controls.py \
    --input data/mawi/mawi_tcp_sorted.tsv.gz \
    --output data/mawi/phase2_controls.tsv \
    --report report/phase2_mawi_control_selection.json
"""
import argparse
from collections import defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time

DEFAULT_ENDPOINTS = [
    '2001:fab8:1071:93ea:700:1a:3fc1:7e80',
    '202.249.10.115',
    '43.15.244.195',
]
BASELINE_ENDPOINTS = ['150.74.240.107', '203.42.121.173', '203.42.117.47']


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(16 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def new_stats():
    return dict(packets=0, tx_packets=0, rx_packets=0, wire_bytes=0,
                tx_wire_bytes=0, rx_wire_bytes=0, payload_bytes=0,
                unknown_ports_packets=0, first_ts=None, last_ts=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input', type=Path, default=Path('data/mawi/mawi_tcp_sorted.tsv.gz'))
    parser.add_argument('--output', type=Path, default=Path('data/mawi/phase2_controls.tsv'))
    parser.add_argument('--report', type=Path, default=Path('report/phase2_mawi_control_selection.json'))
    parser.add_argument('--phase1', type=Path, default=Path('report/phase1_mawi_summary.json'))
    parser.add_argument('--endpoints', default=','.join(DEFAULT_ENDPOINTS))
    args = parser.parse_args()
    endpoints = list(dict.fromkeys(ip.strip() for ip in args.endpoints.split(',') if ip.strip()))
    if not endpoints:
        parser.error('at least one endpoint is required')
    if args.input.resolve() == args.output.resolve():
        parser.error('output must differ from input')
    selected = {ip.encode(): ip for ip in endpoints}
    stats = {ip: new_stats() for ip in endpoints}
    # Keyed relative to each endpoint: local port, peer IP, peer port.
    connections = {ip: defaultdict(lambda: [0, 0]) for ip in endpoints}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    input_bytes = args.input.stat().st_size
    input_sha = file_sha256(args.input)
    source_rows = selected_rows = dual_selected_rows = 0
    output_sha = hashlib.sha256()
    first_ts = last_ts = previous_selected_ts = None
    started = time.monotonic()
    opener = gzip.open if args.input.suffix == '.gz' else open
    with opener(args.input, 'rb') as source, args.output.open('wb') as output:
        for line in source:
            if line.startswith(b'#') or not line.strip():
                continue
            source_rows += 1
            # Avoid parsing all the numeric fields of nonselected records.
            head = line.split(b'\t', 4)
            if len(head) != 5:
                raise ValueError(f'malformed source row {source_rows}')
            if head[1] != b'6':
                raise ValueError(f'non-TCP source row {source_rows}')
            if first_ts is None:
                first_ts = head[0].decode()
            last_ts = head[0].decode()
            src, dst = head[2], head[3]
            if src in selected or dst in selected:
                fields = line.rstrip(b'\n').split(b'\t')
                if len(fields) != 16:
                    raise ValueError(f'expected 16 columns at source row {source_rows}')
                timestamp = float(fields[0])
                if previous_selected_ts is not None and timestamp < previous_selected_ts:
                    raise ValueError(f'selected timestamp decreased at source row {source_rows}')
                previous_selected_ts = timestamp
                sport, dport = int(fields[4]), int(fields[5])
                wire, payload = int(fields[14]), int(fields[7])
                if wire < 0 or payload < 0:
                    raise ValueError(f'unknown/negative byte size at source row {source_rows}')
                output.write(line)
                output_sha.update(line)
                selected_rows += 1
                dual_selected_rows += int(src in selected and dst in selected)
                for endpoint_bytes, sending in ((src, True), (dst, False)):
                    if endpoint_bytes not in selected:
                        continue
                    ip = selected[endpoint_bytes]
                    row = stats[ip]
                    row['packets'] += 1
                    row['tx_packets' if sending else 'rx_packets'] += 1
                    row['wire_bytes'] += wire
                    row['tx_wire_bytes' if sending else 'rx_wire_bytes'] += wire
                    row['payload_bytes'] += payload
                    row['unknown_ports_packets'] += int(sport < 0 or dport < 0)
                    if row['first_ts'] is None:
                        row['first_ts'] = fields[0].decode()
                    row['last_ts'] = fields[0].decode()
                    conn = ((sport, dst, dport) if sending else (dport, src, sport))
                    connections[ip][conn][0 if sending else 1] += 1
            if source_rows % 10_000_000 == 0:
                print(f'{source_rows:,} source rows; {selected_rows:,} selected; '
                      f'{time.monotonic() - started:.1f}s', file=sys.stderr, flush=True)
    phase1 = json.loads(args.phase1.read_text()) if args.phase1.exists() else {}
    known = {row['ip']: row for row in phase1.get('top_ips', [])}
    for ip, row in stats.items():
        conns = connections[ip]
        both = [n for n in conns.values() if n[0] and n[1]]
        row['observed_four_tuples'] = len(conns)
        row['bidirectional_four_tuples'] = len(both)
        row['bidirectional_four_tuple_fraction'] = len(both) / len(conns) if conns else None
        row['packets_in_bidirectional_four_tuples'] = sum(sum(n) for n in both)
        row['bidirectional_four_tuple_packet_fraction'] = (
            row['packets_in_bidirectional_four_tuples'] / row['packets'] if row['packets'] else None)
        row['rx_packet_fraction'] = row['rx_packets'] / row['packets'] if row['packets'] else None
        row['observed_duration_s'] = (float(row['last_ts']) - float(row['first_ts'])
                                      if row['packets'] else None)
        row['phase1_selection_metadata'] = known.get(ip)
        if ip in known:
            for field, old_field in [('packets', 'pkts'), ('tx_packets', 'tx'),
                                     ('rx_packets', 'rx'), ('observed_four_tuples', 'conns')]:
                if row[field] != known[ip][old_field]:
                    raise AssertionError(f'{ip}: {field} does not agree with phase-1 metadata')
    if sum(row['packets'] for row in stats.values()) != selected_rows + dual_selected_rows:
        raise AssertionError('endpoint counts do not conserve selected rows')
    report = dict(
        input=str(args.input.resolve()), input_bytes=input_bytes, input_sha256=input_sha,
        source_rows=source_rows, source_first_ts=first_ts, source_last_ts=last_ts,
        output=str(args.output.resolve()), output_bytes=args.output.stat().st_size,
        output_sha256=output_sha.hexdigest(), output_rows=selected_rows,
        packets_between_selected_endpoints=dual_selected_rows,
        selected_endpoints=endpoints, baseline_endpoints=BASELINE_ENDPOINTS,
        selection_basis='Phase-1 counts only; no selection based on window concentration',
        selection_logic=[
            'Exclude the original three high-volume bidirectional endpoints.',
            'Use endpoints with both directions substantial (rx share .1-.9) and >=100 observed four-tuples.',
            'Supplement at lower volumes with one IPv6 endpoint and two IPv4 endpoints of different connection counts.',
            'Do not label the complete chosen endpoint as balanced before common phase-2 window analysis.',
        ],
        endpoints=stats,
        validation=dict(source_compressed_sha256_computed=True, complete_gzip_read=args.input.suffix == '.gz',
                        selected_timestamp_order='nondecreasing',
                        output_fields=16, protocol='TCP', source_rows_expected=55_783_111,
                        source_rows_agree=source_rows == 55_783_111,
                        phase1_metadata_agree=all(ip in known for ip in endpoints)),
        limitations=[
            'Observed four-tuples are not separated into TCP sessions.',
            'Bidirectional means packets observed in both directions, not a complete handshake or complete capture.',
            'The monitored backbone link does not reveal the endpoint\'s complete server workload.',
            'Candidate controls are purposive examples, not a representative random sample of all endpoints.',
            'Wire bytes are pcap original packet lengths; Ethernet overhead beyond that field is not added.',
        ],
        elapsed_s=time.monotonic() - started,
    )
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'output_rows': selected_rows, 'endpoints': stats,
                      'report': str(args.report)}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
