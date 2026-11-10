#!/usr/bin/env python3
"""Stream selected TCP endpoints from standard 16-column TSV (plain, .gz, or '-').

Example:
  python3 scripts/phase2_endpoint_windows.py data/mawi/mawi_endpoints.tsv \
    --endpoints 150.74.240.107,203.42.121.173,203.42.117.47 \
    --out-dir report/phase2_mawi --core-windows 1,10,60

Default widths are 1s, 10s, and 60s; explicitly request finer windows if needed.
All windows use epoch-aligned half-open intervals and include empty bins across
one common observation span. Input must be ordered by timestamp. For endpoint
subsets pass --span-start/--span-end from the FULL trace to retain edge empty
bins. Counts and quantiles are exact observations, without sampling scaling.
Wire bytes are original pcap packet lengths (TSV column 15), without inventing
Ethernet framing overhead. Payload bytes are inferred TCP payload lengths.
Nominal rates divide by the full aligned window; observed_duration_s clips to
the common observation span, and pps_observed_partial divides by that duration
(blank for zero duration). Principal postprocessed conclusions should use
complete windows and separately check sensitivity to the partial edge windows.

Connection means the observed endpoint/local-port/peer/peer-port tuple; reused
TCP sessions are not separated. Hash uses deterministic BLAKE2b, NOT actual RSS.
Repeated hash summaries use stable seeds (default 16); seed 0 reproduces the
original unseeded hash, with every digest cached at a connection's first packet.
RR assigns a connection once, at its first observed packet, and stays stable.
LPT reassigns whole connections in each window using a greedy largest-first
algorithm; it is NOT an optimal solution. Every policy conserves packet counts.
The indivisible-connection bound is max(1, K * top1_share), for nonempty bins.

Exploratory hotspots require top1_share >= .5 AND packets >= all-bin p90 AND
packets >= 20; threshold ties can select more than 10% of windows. A segment
requires the SAME dominant connection in adjacent qualifying bins. Empty bins
break segments. Segment durations describe aligned bins, with a separate
clipped duration within the observed span. These are concentration/packet-work
proxies; CPU costs and actual server traffic outside this capture are unknown.
Only one live bin per window width is retained; raw CSVs are streamed to a
temporary directory, then annotated after the p90 threshold becomes known.
"""
import argparse
from array import array
from collections import Counter
import csv
from decimal import Decimal
import gzip
import hashlib
import heapq
import json
import math
from pathlib import Path
import sys
import tempfile

NS = 1_000_000_000
BASE_FIELDS = ['endpoint', 'window_s', 'window_index', 'start_ts', 'end_ts',
               'packets', 'tx_packets', 'rx_packets', 'wire_bytes',
               'tx_wire_bytes', 'rx_wire_bytes', 'payload_bytes',
               'unknown_ports_packets', 'active_connections', 'top1_packets',
               'top5_packets', 'top1_share', 'top5_share', 'top1_connection',
               'top5_connections', 'top5_connection_packets']
SEG_FIELDS = ['endpoint', 'window_s', 'connection', 'start_ts', 'end_ts',
              'windows', 'aligned_duration_s', 'observed_duration_s', 'packets',
              'connection_packets', 'peak_endpoint_pps', 'peak_connection_pps']


def timestamp_ns(value):
    whole, _, fraction = value.partition('.')
    if len(fraction) > 9 and any(c != '0' for c in fraction[9:]):
        raise ValueError('timestamps finer than nanoseconds are unsupported')
    return int(whole) * NS + int((fraction[:9] + '000000000')[:9])


def width_ns(value):
    result = Decimal(value) * NS
    if result <= 0 or result != result.to_integral_value():
        raise ValueError('window widths must be positive integral nanoseconds')
    return int(result)


def stamp(value):
    return f'{value // NS}.{value % NS:09d}'


def label(width):
    seconds = width / NS
    return f'{seconds * 1000:g}ms' if seconds < 1 else f'{seconds:g}s'


def conn_text(endpoint, conn):
    local_port, peer, peer_port = conn
    return json.dumps([endpoint, local_port, peer, peer_port], separators=(',', ':'))


def connection_assignment(endpoint, conn, ordinal, repeats):
    """Return stable RR ordinal, original hash, and cached seeded hashes.

    Seed zero is exactly the original BLAKE2b(conn_text). Higher seeds are
    domain separated with BLAKE2b's fixed-width personalization parameter.
    """
    encoded = conn_text(endpoint, conn).encode()
    original = int.from_bytes(hashlib.blake2b(encoded, digest_size=8).digest(), 'big')
    seeded = [original]
    for seed in range(1, repeats):
        digest = hashlib.blake2b(encoded, digest_size=8,
                                 person=seed.to_bytes(16, 'big')).digest()
        seeded.append(int.from_bytes(digest, 'big'))
    return ordinal, original, array('Q', seeded)


def nearest_rank_hist(histogram, q, nonzero=False):
    n = sum(c for value, c in histogram.items() if not nonzero or value != 0)
    if not n:
        return 0
    rank = max(1, math.ceil(q * n))
    for value, count in sorted(histogram.items()):
        if nonzero and value == 0:
            continue
        rank -= count
        if rank <= 0:
            return value
    raise AssertionError('invalid histogram')


def quantiles(values):
    if not values:
        return {'p50': None, 'p90': None, 'p99': None, 'max': None, 'mean': None}
    ordered = sorted(values)
    n = len(ordered)
    return {**{f'p{int(q * 100)}': ordered[max(0, math.ceil(q * n) - 1)]
               for q in (.5, .9, .99)},
            'max': ordered[-1], 'mean': math.fsum(ordered) / n}


class Bucket:
    __slots__ = ('connections', 'packets', 'tx', 'rx', 'wire', 'tx_wire',
                 'rx_wire', 'payload', 'unknown_ports')

    def __init__(self):
        self.connections = Counter()
        self.packets = self.tx = self.rx = self.wire = self.tx_wire = 0
        self.rx_wire = self.payload = self.unknown_ports = 0

    def add(self, connection, sending, wire, payload, ports_known):
        self.connections[connection] += 1
        self.packets += 1
        self.tx += int(sending)
        self.rx += int(not sending)
        self.wire += wire
        self.tx_wire += wire if sending else 0
        self.rx_wire += 0 if sending else wire
        self.payload += payload
        self.unknown_ports += int(not ports_known)


def core_allocations(ranked, assignments, policies, counts):
    result = {}
    total = sum(n for _, n in ranked)
    for k in counts:
        for policy in policies:
            loads = [0] * k
            if policy == 'lpt':
                heap = [(0, i) for i in range(k)]
                for _, packets in ranked:
                    load, i = heapq.heappop(heap)
                    loads[i] = load + packets
                    heapq.heappush(heap, (loads[i], i))
            else:
                position = 1 if policy == 'hash' else 0
                for conn, packets in ranked:
                    loads[assignments[conn][position] % k] += packets
            if sum(loads) != total:
                raise AssertionError('core allocation does not conserve packets')
            result[policy, k] = loads
    return result


def repeated_hash_allocations(ranked, assignments, k, repeats):
    """Yield packet-conserving vectors; temporary storage is repeats times K."""
    total = sum(packets for _, packets in ranked)
    seed_loads = [[0] * k for _ in range(repeats)]
    for conn, packets in ranked:
        for seed, hashed in enumerate(assignments[conn][2]):
            seed_loads[seed][hashed % k] += packets
    for loads in seed_loads:
        if sum(loads) != total:
            raise AssertionError('seeded hash allocation does not conserve packets')
        yield loads


def repeated_hash_summary(ranked, assignments, k, repeats):
    total = sum(packets for _, packets in ranked)
    values = sorted(max(loads) * k / total if total else 0
                    for loads in repeated_hash_allocations(ranked, assignments, k, repeats))
    return {'min': values[0], 'p50': values[math.ceil(.5 * repeats) - 1],
            'p90': values[math.ceil(.9 * repeats) - 1], 'max': values[-1]}


def open_input(path):
    if path == '-':
        return sys.stdin
    return gzip.open(path, 'rt') if path.endswith('.gz') else open(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('tsv')
    parser.add_argument('--endpoints', required=True, help='comma-separated exact TSV IP strings')
    parser.add_argument('--windows', default='1,10,60')
    parser.add_argument('--out-dir', required=True)
    parser.add_argument('--span-start', help='full trace first timestamp, epoch seconds')
    parser.add_argument('--span-end', help='full trace last timestamp, epoch seconds')
    parser.add_argument('--core-policies', default='hash,rr,lpt', help='comma-separated hash,rr,lpt, or none')
    parser.add_argument('--core-counts', default='2,4,8,16,32')
    parser.add_argument('--core-windows', help='window widths to simulate; default: all widths')
    parser.add_argument('--hash-repeats', type=int, default=16,
                        help='stable BLAKE2b seed count, including original seed 0')
    parser.add_argument('--hot-share', type=float, default=.5)
    parser.add_argument('--hot-quantile', type=float, default=.9)
    parser.add_argument('--hot-min-packets', type=int, default=20)
    parser.add_argument('--gzip-level', type=int, default=2)
    args = parser.parse_args(argv)
    endpoints = list(dict.fromkeys(x.strip() for x in args.endpoints.split(',') if x.strip()))
    widths = sorted(set(width_ns(x) for x in args.windows.split(',')))
    core_widths = set(widths if args.core_windows is None else
                      [width_ns(x) for x in args.core_windows.split(',')])
    policies = [] if args.core_policies in ('', 'none') else args.core_policies.split(',')
    counts = sorted(set(int(x) for x in args.core_counts.split(',')))
    if (not endpoints or not set(policies) <= {'hash', 'rr', 'lpt'} or
            not core_widths <= set(widths) or not counts or min(counts) < 1 or
            not 0 < args.hot_quantile <= 1 or not 0 <= args.hot_share <= 1 or
            args.hot_min_packets < 1 or not 0 <= args.gzip_level <= 9 or args.hash_repeats < 1):
        parser.error('invalid endpoints, core options, or hotspot thresholds')
    span_start = timestamp_ns(args.span_start) if args.span_start else None
    span_end = timestamp_ns(args.span_end) if args.span_end else None
    if span_start is not None and span_end is not None and span_end < span_start:
        parser.error('span-end must be at least span-start')
    output = Path(args.out_dir)
    output.mkdir(parents=True, exist_ok=True)
    assignments = {ep: {} for ep in endpoints}
    selected = set(endpoints)
    metadata = {'rows': 0, 'tcp_rows': 0, 'selected_packets': 0,
                'selected_endpoint_packet_incidents': 0, 'self_address_packets': 0,
                'unknown_wire_length_packets': 0, 'unknown_payload_length_packets': 0}
    fields, writers, handles, histograms, active_histograms = {}, {}, {}, {}, {}
    states, indices, raw_paths = {}, {}, {}
    first = last = None

    with tempfile.TemporaryDirectory(prefix='.phase2-', dir=output) as tmp:
        for width in widths:
            extra = []
            if width in core_widths:
                for k in counts:
                    extra.append(f'connection_bound_{k}')
                    for policy in policies:
                        extra += [f'{policy}_{k}_loads', f'{policy}_{k}_max', f'{policy}_{k}_imbalance']
                    if 'hash' in policies:
                        extra += [f'hash_{k}_repeat_imbalance_{metric}'
                                  for metric in ('min', 'p50', 'p90', 'max')]
            fields[width] = BASE_FIELDS + extra
            states[width] = {}
            for i, ep in enumerate(endpoints):
                key = ep, width
                raw_paths[key] = Path(tmp) / f'{i}_{width}.csv.gz'
                handle = gzip.open(raw_paths[key], 'wt', newline='', compresslevel=1)
                handles[key] = handle
                writers[key] = csv.DictWriter(handle, fieldnames=fields[width])
                writers[key].writeheader()
                histograms[key] = Counter()
                active_histograms[key] = Counter()

        def flush(width, index):
            for ep in endpoints:
                bucket = states[width].get(ep) or Bucket()
                ranked = sorted(bucket.connections.items(), key=lambda item: (-item[1], item[0]))
                top1 = ranked[0][1] if ranked else 0
                top5 = sum(n for _, n in ranked[:5])
                share1 = top1 / bucket.packets if bucket.packets else 0
                share5 = top5 / bucket.packets if bucket.packets else 0
                row = dict(zip(BASE_FIELDS, [ep, width / NS, index, stamp(index * width),
                    stamp((index + 1) * width), bucket.packets, bucket.tx, bucket.rx,
                    bucket.wire, bucket.tx_wire, bucket.rx_wire, bucket.payload,
                    bucket.unknown_ports, len(ranked), top1, top5, share1, share5,
                    conn_text(ep, ranked[0][0]) if ranked else '',
                    json.dumps([conn_text(ep, conn) for conn, _ in ranked[:5]], separators=(',', ':')),
                    json.dumps([packets for _, packets in ranked[:5]], separators=(',', ':'))]))
                if width in core_widths:
                    allocations = core_allocations(ranked, assignments[ep], policies, counts)
                    for k in counts:
                        row[f'connection_bound_{k}'] = max(1, k * share1) if bucket.packets else 0
                        for policy in policies:
                            loads = allocations[policy, k]
                            row[f'{policy}_{k}_loads'] = json.dumps(loads, separators=(',', ':'))
                            row[f'{policy}_{k}_max'] = max(loads)
                            row[f'{policy}_{k}_imbalance'] = max(loads) * k / bucket.packets if bucket.packets else 0
                        if 'hash' in policies:
                            repeated = repeated_hash_summary(ranked, assignments[ep], k, args.hash_repeats)
                            for metric, value in repeated.items():
                                row[f'hash_{k}_repeat_imbalance_{metric}'] = value
                writers[ep, width].writerow(row)
                histograms[ep, width][bucket.packets] += 1
                active_histograms[ep, width][len(ranked)] += 1
            states[width] = {}

        stream = open_input(args.tsv)
        try:
            for line_number, line in enumerate(stream, 1):
                if not line.strip() or line.startswith('#'):
                    continue
                columns = line.rstrip('\r\n').split('\t')
                if len(columns) != 16:
                    raise ValueError(f'line {line_number}: expected 16 TSV columns, got {len(columns)}')
                ts = timestamp_ns(columns[0])
                if last is not None and ts < last:
                    raise ValueError(f'line {line_number}: timestamps are not sorted')
                if first is None:
                    first = ts
                    begin = span_start if span_start is not None else first
                    if begin > first:
                        raise ValueError('span-start excludes input timestamps')
                    for width in widths:
                        indices[width] = begin // width
                last = ts
                if span_end is not None and ts > span_end:
                    raise ValueError('span-end excludes input timestamps')
                metadata['rows'] += 1
                if columns[1] != '6':
                    continue
                metadata['tcp_rows'] += 1
                src, dst = columns[2], columns[3]
                if src not in selected and dst not in selected:
                    continue
                metadata['selected_packets'] += 1
                sport, dport = int(columns[4]), int(columns[5])
                wire, payload = int(columns[14]), int(columns[7])
                metadata['unknown_wire_length_packets'] += int(wire < 0)
                metadata['unknown_payload_length_packets'] += int(payload < 0)
                wire, payload = max(0, wire), max(0, payload)
                if src == dst:
                    metadata['self_address_packets'] += 1
                # A packet contributes once per selected endpoint. Self-addressed
                # traffic is assigned TX to preserve tx + rx == packets.
                incidents = []
                if src in selected:
                    incidents.append((src, (sport, dst, dport), True))
                if dst in selected and dst != src:
                    incidents.append((dst, (dport, src, sport), False))
                metadata['selected_endpoint_packet_incidents'] += len(incidents)
                for ep, conn, _ in incidents:
                    if conn not in assignments[ep]:
                        assignments[ep][conn] = connection_assignment(
                            ep, conn, len(assignments[ep]), args.hash_repeats if 'hash' in policies else 1)
                for width in widths:
                    target = ts // width
                    while indices[width] < target:
                        flush(width, indices[width])
                        indices[width] += 1
                    for ep, conn, sending in incidents:
                        bucket = states[width].get(ep)
                        if bucket is None:
                            bucket = states[width][ep] = Bucket()
                        bucket.add(conn, sending, wire, payload, sport >= 0 and dport >= 0)
        finally:
            if stream is not sys.stdin:
                stream.close()
        if first is None:
            raise ValueError('input contains no packet rows')
        span_start = first if span_start is None else span_start
        span_end = last if span_end is None else span_end
        for width in widths:
            final_index = span_end // width
            while indices[width] <= final_index:
                flush(width, indices[width])
                indices[width] += 1
        for handle in handles.values():
            handle.close()

        summary = {'input': args.tsv, 'input_first_ts': stamp(first), 'input_last_ts': stamp(last),
                   'span_start_ts': stamp(span_start), 'span_end_ts': stamp(span_end),
                   'span_duration_s': (span_end - span_start) / NS,
                   'metadata': metadata,
                   'definitions': {
                       'connection': 'endpoint/local-port/peer/peer-port observed tuple; sessions not split',
                       'window': 'epoch-aligned half-open bins; all bins touching common span included',
                       'packet_quantiles': 'nearest-rank; all bins and nonempty bins reported separately',
                       'share_quantiles': 'nearest-rank over nonempty endpoint bins',
                       'hash': 'deterministic BLAKE2b modulo K; not actual RSS',
                       'hash_repeats': 'seed 0 is original hash; seeds 1+ use 16-byte big-endian BLAKE2b personalization; stable per connection; nearest-rank summaries',
                       'rr': 'stable assignment by first-observed connection ordinal modulo K',
                       'lpt': 'per-window largest-first greedy assignment; not optimal',
                       'load': 'TCP packet count proxy; no CPU capacity inferred',
                       'wire_bytes': 'original pcap packet length, excluding invented Ethernet overhead',
                       'rates': 'pps and wire rates use nominal aligned width; observed_duration_s clips to common trace span; pps_observed_partial is blank for zero duration',
                       'top5_connections': 'JSON list of canonical conn_text strings, ranked by packet count then tuple; top5_connection_packets is the corresponding JSON list',
                       'complete_windows': 'principal postprocessed conclusions should exclude partial_boundary_window and report boundary sensitivity',
                       'self_address': 'packet counted once as TX per endpoint',
                       'hotspot': 'same-connection consecutive bins satisfying concentration and load thresholds',
                       'capture_completeness': 'no sampling/drop/visibility conclusion is made'},
                   'parameters': {'endpoints': endpoints, 'windows_s': [w / NS for w in widths],
                       'core_counts': counts, 'core_policies': policies,
                       'hash_repeats': args.hash_repeats,
                       'core_windows_s': [w / NS for w in sorted(core_widths)],
                       'hot_share': args.hot_share, 'hot_quantile': args.hot_quantile,
                       'hot_min_packets': args.hot_min_packets,
                       'hot_threshold_status': 'explicit exploratory defaults; not a validated CPU threshold'},
                   'endpoints': {ep: {'observed_connections': len(assignments[ep]), 'windows': {}} for ep in endpoints}}
        segment_path = output / 'hotspot_segments.csv.gz'
        with gzip.open(segment_path, 'wt', newline='', compresslevel=args.gzip_level) as seg_handle:
            seg_writer = csv.DictWriter(seg_handle, fieldnames=SEG_FIELDS)
            seg_writer.writeheader()
            for width in widths:
                for ep in endpoints:
                    histogram = histograms[ep, width]
                    active_histogram = active_histograms[ep, width]
                    n_windows = sum(histogram.values())
                    n_nonempty = n_windows - histogram[0]
                    packet_total = sum(n * count for n, count in histogram.items())
                    percentile_threshold = nearest_rank_hist(histogram, args.hot_quantile)
                    threshold = max(args.hot_min_packets, percentile_threshold)
                    filename = f'{ep.replace(":", "_")}__{label(width)}.csv.gz'
                    csv_path = output / filename
                    share1, share5 = array('d'), array('d')
                    core_values = {(policy, k): array('d') for policy in policies for k in counts
                                   if width in core_widths}
                    hot_count = hot_packets = hot_conn_packets = segment_count = 0
                    longest_segment = 0
                    current = None
                    emitted = 0
                    aggregate = Counter()

                    def finish_segment():
                        nonlocal current, segment_count, longest_segment
                        if current is None:
                            return
                        start_ns = current.pop('_start_ns')
                        end_ns = current.pop('_end_ns')
                        current['aligned_duration_s'] = (end_ns - start_ns) / NS
                        current['observed_duration_s'] = max(0, min(end_ns, span_end) - max(start_ns, span_start)) / NS
                        longest_segment = max(longest_segment, current['windows'])
                        seg_writer.writerow(current)
                        segment_count += 1
                        current = None

                    extra_fields = ['partial_boundary_window', 'high_load_threshold_packets',
                                    'is_high_load', 'is_concentrated', 'is_hotspot',
                                    'pps', 'wire_bytes_per_s', 'wire_bits_per_s',
                                    'tx_pps', 'rx_pps', 'observed_duration_s', 'pps_observed_partial']
                    with gzip.open(raw_paths[ep, width], 'rt', newline='') as raw_handle, \
                         gzip.open(csv_path, 'wt', newline='', compresslevel=args.gzip_level) as final_handle:
                        reader = csv.DictReader(raw_handle)
                        writer = csv.DictWriter(final_handle, fieldnames=fields[width] + extra_fields)
                        writer.writeheader()
                        for row in reader:
                            packets = int(row['packets'])
                            index = int(row['window_index'])
                            top_packets = int(row['top1_packets'])
                            s1, s5 = float(row['top1_share']), float(row['top5_share'])
                            high = packets >= threshold
                            concentrated = packets > 0 and s1 >= args.hot_share
                            hot = high and concentrated
                            duration_ns = max(0, min((index + 1) * width, span_end) -
                                              max(index * width, span_start))
                            row.update(partial_boundary_window=int(index * width < span_start or (index + 1) * width > span_end),
                                       high_load_threshold_packets=threshold, is_high_load=int(high),
                                       is_concentrated=int(concentrated), is_hotspot=int(hot),
                                       pps=packets * NS / width,
                                       wire_bytes_per_s=int(row['wire_bytes']) * NS / width,
                                       wire_bits_per_s=int(row['wire_bytes']) * 8 * NS / width,
                                       tx_pps=int(row['tx_packets']) * NS / width,
                                       rx_pps=int(row['rx_packets']) * NS / width,
                                       observed_duration_s=duration_ns / NS,
                                       pps_observed_partial=packets * NS / duration_ns if duration_ns else '')
                            writer.writerow(row)
                            emitted += packets
                            for metric in ('tx_packets', 'rx_packets', 'wire_bytes', 'tx_wire_bytes', 'rx_wire_bytes', 'payload_bytes', 'unknown_ports_packets'):
                                aggregate[metric] += int(row[metric])
                            if packets:
                                share1.append(s1)
                                share5.append(s5)
                                for (policy, k), values in core_values.items():
                                    values.append(float(row[f'{policy}_{k}_imbalance']))
                            if hot:
                                hot_count += 1
                                hot_packets += packets
                                hot_conn_packets += top_packets
                                if current is not None and (current['connection'] != row['top1_connection'] or current['_end_ns'] != index * width):
                                    finish_segment()
                                if current is None:
                                    current = {'endpoint': ep, 'window_s': width / NS,
                                               'connection': row['top1_connection'], 'start_ts': row['start_ts'],
                                               'end_ts': row['end_ts'], 'windows': 0, 'packets': 0,
                                               'connection_packets': 0, 'peak_endpoint_pps': 0,
                                               'peak_connection_pps': 0, '_start_ns': index * width,
                                               '_end_ns': (index + 1) * width}
                                current['end_ts'] = row['end_ts']
                                current['_end_ns'] = (index + 1) * width
                                current['windows'] += 1
                                current['packets'] += packets
                                current['connection_packets'] += top_packets
                                current['peak_endpoint_pps'] = max(current['peak_endpoint_pps'], packets * NS / width)
                                current['peak_connection_pps'] = max(current['peak_connection_pps'], top_packets * NS / width)
                            else:
                                finish_segment()
                        finish_segment()
                    if emitted != packet_total:
                        raise AssertionError('output packet count does not match window histogram')
                    window_summary = {'csv': str(csv_path), 'total_windows': n_windows,
                        'nonempty_windows': n_nonempty, 'empty_fraction': histogram[0] / n_windows,
                        'packets': packet_total, **dict(aggregate), 'mean_pps_aligned_span': packet_total / (n_windows * width / NS),
                        'mean_pps_observed_span': packet_total * NS / (span_end - span_start) if span_end > span_start else None,
                        'packets_all_windows': {f'p{int(q*100)}': nearest_rank_hist(histogram, q) for q in (.5, .9, .99)},
                        'packets_nonempty_windows': {f'p{int(q*100)}': nearest_rank_hist(histogram, q, True) for q in (.5, .9, .99)},
                        'packets_max': max(histogram),
                        'active_connections_all_windows': {f'p{int(q*100)}': nearest_rank_hist(active_histogram, q) for q in (.5, .9, .99)},
                        'active_connections_nonempty_windows': {f'p{int(q*100)}': nearest_rank_hist(active_histogram, q, True) for q in (.5, .9, .99)},
                        'active_connections_max': max(active_histogram),
                        'top1_share_nonempty': quantiles(share1), 'top5_share_nonempty': quantiles(share5),
                        'hotspot_packet_quantile_threshold': percentile_threshold,
                        'hotspot_effective_packet_threshold': threshold, 'hotspot_windows': hot_count,
                        'hotspot_window_fraction_all': hot_count / n_windows,
                        'hotspot_window_fraction_nonempty': hot_count / n_nonempty if n_nonempty else None,
                        'hotspot_packets': hot_packets, 'hotspot_dominant_connection_packets': hot_conn_packets,
                        'hotspot_segments': segment_count, 'longest_hotspot_segment_windows': longest_segment,
                        'longest_hotspot_segment_aligned_s': longest_segment * width / NS,
                        'core_imbalance_nonempty': {f'{policy}_{k}': quantiles(values) for (policy, k), values in core_values.items()}}
                    summary['endpoints'][ep]['windows'][label(width)] = window_summary
                    print(f'{ep} {label(width)}: {packet_total} packets, {n_windows} windows, {hot_count} hotspot windows', file=sys.stderr)
        summary['hotspot_segments_csv'] = str(segment_path)
        summary_path = output / 'summary.json'
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
        print(summary_path)
        return summary


if __name__ == '__main__':
    main()
