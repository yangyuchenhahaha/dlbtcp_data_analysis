#!/usr/bin/env python3
"""Aggregate endpoint TCP connection totals from the standard 16-column TSV.

Connection is an observed endpoint/local-port/peer-IP/peer-port tuple. Sessions
reusing a tuple are NOT split. First/last timestamps describe observed packets,
not connection establishment/termination. A tuple-reuse hint means two distinct
initial SYN sequence numbers in the same direction; it is not proof of reuse.
Flags are counted for field availability only; no TCP sequence-event analysis
is performed. Input may be plain, .gz, or stdin ('-'), and need not be sorted.

Example:
  python3 scripts/phase2_connection_totals.py data/mawi/mawi_endpoints.tsv \
    --endpoints 150.74.240.107,203.42.121.173,203.42.117.47 \
    --out-dir report/phase2_mawi
"""
import argparse
from collections import Counter
import csv
import gzip
import json
import math
from pathlib import Path
import sys

NS = 1_000_000_000
# Mutable counters are indexed to avoid allocating dictionaries per packet.
FIRST, LAST, TXP, RXP, TXW, RXW, TXB, RXB = range(8)
SYN, SYNACK, FIN, RST, FLAGS_VALID, PLEN_VALID, WIRE_VALID, OPTS_TRUNC = range(8, 16)
PORTS_UNKNOWN, HEADER_UNKNOWN, SEQ_INVALID, SYN_TX, SYN_RX = range(16, 21)
FIELDS = ['endpoint', 'local_port', 'peer_ip', 'peer_port', 'first_ts', 'last_ts',
          'observed_duration_s', 'packets', 'tx_packets', 'rx_packets',
          'wire_bytes', 'tx_wire_bytes', 'rx_wire_bytes', 'payload_bytes',
          'tx_payload_bytes', 'rx_payload_bytes', 'both_directions',
          'seen_syn', 'seen_synack', 'seen_fin', 'seen_rst', 'syn_packets',
          'synack_packets', 'fin_packets', 'rst_packets',
          'flags_valid_packets', 'payload_valid_packets', 'wire_valid_packets',
          'options_truncated_packets', 'unknown_ports_packets',
          'invalid_tcp_header_packets', 'invalid_seq_packets',
          'tx_initial_syn_distinct_iss', 'rx_initial_syn_distinct_iss',
          'tuple_reuse_syn_iss_hint']


def timestamp_ns(value):
    whole, _, fraction = value.partition('.')
    if len(fraction) > 9 and any(c != '0' for c in fraction[9:]):
        raise ValueError('timestamps finer than nanoseconds are unsupported')
    return int(whole) * NS + int((fraction[:9] + '000000000')[:9])


def stamp(value):
    return f'{value // NS}.{value % NS:09d}'


def quantiles(values):
    ordered = sorted(values)
    if not ordered:
        return {key: None for key in ('p0', 'p10', 'p50', 'p90', 'p95', 'p99', 'max', 'mean')}
    n = len(ordered)
    return {'p0': ordered[0], **{
        f'p{int(q * 100)}': ordered[max(0, math.ceil(q * n) - 1)]
        for q in (.1, .5, .9, .95, .99)},
        'max': ordered[-1], 'mean': math.fsum(ordered) / n}


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def connection_row(endpoint, key, state):
    local_port, peer, peer_port = key
    txp, rxp, txw, rxw, txb, rxb = state[TXP:RXB + 1]
    txiss = len(state[SYN_TX]) if state[SYN_TX] else 0
    rxiss = len(state[SYN_RX]) if state[SYN_RX] else 0
    return dict(zip(FIELDS, [endpoint, local_port, peer, peer_port,
        stamp(state[FIRST]), stamp(state[LAST]), (state[LAST] - state[FIRST]) / NS,
        txp + rxp, txp, rxp, txw + rxw, txw, rxw, txb + rxb, txb, rxb,
        int(txp > 0 and rxp > 0), int(state[SYN] > 0), int(state[SYNACK] > 0),
        int(state[FIN] > 0), int(state[RST] > 0), state[SYN], state[SYNACK],
        state[FIN], state[RST], state[FLAGS_VALID], state[PLEN_VALID],
        state[WIRE_VALID], state[OPTS_TRUNC], state[PORTS_UNKNOWN],
        state[HEADER_UNKNOWN], state[SEQ_INVALID], txiss, rxiss,
        int(txiss > 1 or rxiss > 1)]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('tsv')
    parser.add_argument('--endpoints', required=True)
    parser.add_argument('--out-dir', required=True)
    parser.add_argument('--gzip-level', type=int, default=2)
    args = parser.parse_args(argv)
    endpoints = list(dict.fromkeys(x.strip() for x in args.endpoints.split(',') if x.strip()))
    if not endpoints or not 0 <= args.gzip_level <= 9:
        parser.error('endpoints must be nonempty and gzip-level between 0 and 9')
    selected = set(endpoints)
    states = {ep: {} for ep in endpoints}
    input_totals = {ep: Counter() for ep in endpoints}
    metadata = Counter()
    first = last = previous = None
    stream = sys.stdin if args.tsv == '-' else (
        gzip.open(args.tsv, 'rt') if args.tsv.endswith('.gz') else open(args.tsv))
    try:
        for line_number, line in enumerate(stream, 1):
            if not line.strip() or line.startswith('#'):
                continue
            columns = line.rstrip('\r\n').split('\t')
            if len(columns) != 16:
                raise ValueError(f'line {line_number}: expected 16 columns, got {len(columns)}')
            ts = timestamp_ns(columns[0])
            metadata['rows'] += 1
            metadata['timestamp_backwards'] += int(previous is not None and ts < previous)
            previous = ts
            first = ts if first is None else min(first, ts)
            last = ts if last is None else max(last, ts)
            if columns[1] != '6':
                continue
            metadata['tcp_rows'] += 1
            src, dst = columns[2:4]
            if src not in selected and dst not in selected:
                continue
            metadata['selected_unique_packets'] += 1
            metadata['self_address_packets'] += int(src == dst)
            sport, dport = int(columns[4]), int(columns[5])
            l4len, plen, flags, seq = map(int, columns[6:10])
            thl, _, wire, opts_trunc = map(int, columns[12:16])
            header_valid = 20 <= thl <= 60 and thl % 4 == 0 and l4len >= thl
            flags_valid = header_valid and 0 <= flags <= 511
            plen_valid = header_valid and 0 <= plen <= l4len and plen == l4len - thl
            wire_valid = wire >= 0
            seq_valid = header_valid and 0 <= seq < 2 ** 32
            # Keep the same max(0, value) byte accounting as endpoint windows;
            # validity counters expose any uninterpretable/inferred records.
            wire = max(0, wire)
            plen = max(0, plen)
            ports_known = 0 <= sport <= 65535 and 0 <= dport <= 65535
            incidents = []
            if src in selected:
                incidents.append((src, (sport, dst, dport), True))
            if dst in selected and dst != src:
                incidents.append((dst, (dport, src, sport), False))
            metadata['endpoint_packet_incidents'] += len(incidents)
            for ep, key, sending in incidents:
                state = states[ep].get(key)
                if state is None:
                    state = states[ep][key] = [ts, ts] + [0] * 17 + [None, None]
                else:
                    state[FIRST] = min(state[FIRST], ts)
                    state[LAST] = max(state[LAST], ts)
                state[TXP if sending else RXP] += 1
                state[TXW if sending else RXW] += wire
                state[TXB if sending else RXB] += plen
                state[FLAGS_VALID] += flags_valid
                state[PLEN_VALID] += plen_valid
                state[WIRE_VALID] += wire_valid
                state[OPTS_TRUNC] += int(opts_trunc > 0)
                state[PORTS_UNKNOWN] += int(not ports_known)
                state[HEADER_UNKNOWN] += int(not header_valid)
                state[SEQ_INVALID] += int(not seq_valid)
                if flags_valid:
                    state[SYN] += int(bool(flags & 2) and not (flags & 16))
                    state[SYNACK] += int(bool(flags & 2) and bool(flags & 16))
                    state[FIN] += int(bool(flags & 1))
                    state[RST] += int(bool(flags & 4))
                    if flags & 2 and not flags & 16 and seq_valid:
                        syn_index = SYN_TX if sending else SYN_RX
                        if state[syn_index] is None:
                            state[syn_index] = set()
                        state[syn_index].add(seq)
                totals = input_totals[ep]
                totals['packets'] += 1
                totals['tx_packets' if sending else 'rx_packets'] += 1
                totals['wire_bytes'] += wire
                totals['tx_wire_bytes' if sending else 'rx_wire_bytes'] += wire
                totals['payload_bytes'] += plen
                totals['tx_payload_bytes' if sending else 'rx_payload_bytes'] += plen
            if metadata['rows'] % 2_000_000 == 0:
                print(f"read {metadata['rows']:,} rows", file=sys.stderr, flush=True)
    finally:
        if stream is not sys.stdin:
            stream.close()
    if first is None:
        raise ValueError('input has no packet rows')
    output = Path(args.out_dir)
    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / 'connection_totals.csv.gz'
    summary = {'input': args.tsv, 'input_first_ts': stamp(first),
        'input_last_ts': stamp(last), 'input_observed_span_s': (last - first) / NS,
        'metadata': dict(metadata), 'connection_totals_csv': str(csv_path),
        'definitions': {
            'connection': 'observed endpoint/local-port/peer-IP/peer-port tuple; reused TCP sessions are not separated',
            'direction': 'tx: source equals endpoint; rx: destination equals endpoint; self-address packets counted once as tx',
            'duration': 'last observed packet minus first observed packet; not a measured TCP session lifetime',
            'both_directions': 'at least one observed tx packet and one observed rx packet in the tuple; does not prove complete capture',
            'wire_bytes': 'original pcap packet length; no added Ethernet framing overhead',
            'payload_bytes': 'inferred plen TSV field; negative values zeroed; this is observed TCP payload volume, not unique goodput',
            'syn_packets': 'SYN=1 ACK=0, including retransmitted initial SYNs',
            'synack_packets': 'SYN=1 ACK=1',
            'tuple_reuse_syn_iss_hint': 'two or more distinct initial-SYN sequence numbers in the same direction; possible tuple reuse/anomaly only',
            'quantiles': 'exact nearest-rank over observed tuples, including one-packet zero-duration tuples',
            'field_availability': 'syntactic/header validity only; no third-stage sequence-event classification',
            'capture_completeness': 'not inferred from direction or flag availability'},
        'endpoints': {}, 'all_conservation_checks_passed': False}
    with gzip.open(csv_path, 'wt', newline='', compresslevel=args.gzip_level) as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for ep in endpoints:
            connections = states[ep]
            aggregated = Counter()
            both = Counter()
            metrics = {name: [] for name in ('packets', 'wire_bytes', 'payload_bytes', 'observed_duration_s')}
            counts = Counter()
            largest = []
            for key, state in sorted(connections.items()):
                row = connection_row(ep, key, state)
                writer.writerow(row)
                for name in input_totals[ep]:
                    aggregated[name] += row[name]
                for name in metrics:
                    metrics[name].append(row[name])
                if row['both_directions']:
                    both['connections'] += 1
                    for name in ('packets', 'wire_bytes', 'payload_bytes'):
                        both[name] += row[name]
                counts['single_packet_connections'] += int(row['packets'] == 1)
                counts['connections_ge100_packets'] += int(row['packets'] >= 100)
                counts['connections_ge100_packets_both_directions'] += int(row['packets'] >= 100 and row['both_directions'])
                for name in ('seen_syn', 'seen_synack', 'seen_fin', 'seen_rst', 'tuple_reuse_syn_iss_hint'):
                    counts[f'connections_{name}'] += row[name]
                for name in ('syn_packets', 'synack_packets', 'fin_packets', 'rst_packets',
                             'flags_valid_packets', 'payload_valid_packets', 'wire_valid_packets',
                             'options_truncated_packets', 'unknown_ports_packets',
                             'invalid_tcp_header_packets', 'invalid_seq_packets'):
                    counts[name] += row[name]
                largest.append(row)
            checks = {name: {'input': input_totals[ep][name], 'output': aggregated[name],
                             'passed': input_totals[ep][name] == aggregated[name]}
                      for name in input_totals[ep]}
            checks['direction_packets'] = {'passed': aggregated['tx_packets'] + aggregated['rx_packets'] == aggregated['packets']}
            checks['direction_wire_bytes'] = {'passed': aggregated['tx_wire_bytes'] + aggregated['rx_wire_bytes'] == aggregated['wire_bytes']}
            checks['direction_payload_bytes'] = {'passed': aggregated['tx_payload_bytes'] + aggregated['rx_payload_bytes'] == aggregated['payload_bytes']}
            if not all(check['passed'] for check in checks.values()):
                raise AssertionError(f'{ep}: failed conservation check')
            n = len(connections)
            totals = {name: aggregated[name] for name in (
                'packets', 'tx_packets', 'rx_packets', 'wire_bytes', 'tx_wire_bytes',
                'rx_wire_bytes', 'payload_bytes', 'tx_payload_bytes', 'rx_payload_bytes')}
            by_packets = sorted(largest, key=lambda row: (-row['packets'], row['local_port'], row['peer_ip'], row['peer_port']))
            by_wire = sorted(largest, key=lambda row: (-row['wire_bytes'], row['local_port'], row['peer_ip'], row['peer_port']))
            summary['endpoints'][ep] = {'observed_connections': n, **totals,
                'both_directions': {'connections': both['connections'],
                    'connection_fraction': ratio(both['connections'], n),
                    **{name: both[name] for name in ('packets', 'wire_bytes', 'payload_bytes')},
                    **{name + '_fraction': ratio(both[name], aggregated[name])
                       for name in ('packets', 'wire_bytes', 'payload_bytes')}},
                'availability_and_flags': dict(counts),
                'connection_quantiles': {name: quantiles(values) for name, values in metrics.items()},
                'top1_total_packet_share': ratio(by_packets[0]['packets'], aggregated['packets']) if by_packets else None,
                'top5_total_packet_share': ratio(sum(row['packets'] for row in by_packets[:5]), aggregated['packets']),
                'top1_total_wire_byte_share': ratio(by_wire[0]['wire_bytes'], aggregated['wire_bytes']) if by_wire else None,
                'top5_total_wire_byte_share': ratio(sum(row['wire_bytes'] for row in by_wire[:5]), aggregated['wire_bytes']),
                'largest_connections_by_packets': by_packets[:10],
                'largest_connections_by_wire_bytes': by_wire[:10],
                'conservation': checks}
            print(f'{ep}: {n:,} tuples, {aggregated["packets"]:,} packets; conservation passed', file=sys.stderr)
    summary['all_conservation_checks_passed'] = True
    summary_path = output / 'endpoints_connections.json'
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print(summary_path)
    return summary


if __name__ == '__main__':
    main()
