#!/usr/bin/env python3
"""Stream phase-3 packet events into descriptive, explicitly observational summaries.

Run from the project root. Only the small sessions table and current per-stream
episodes are kept in memory; packet events themselves are not accumulated.
Normal-event runs describe observed packet patterns, never a TCP fast path.
"""
import argparse
from collections import Counter, defaultdict
import csv
import gzip
import hashlib
import json
import math
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
ENDPOINTS = ['150.74.240.107', '203.42.121.173', '203.42.117.47',
             '2001:fab8:1071:93ea:700:1a:3fc1:7e80', '202.249.10.115', '43.15.244.195']
LETTERS = dict(zip(ENDPOINTS, 'ABCDEF'))
COHORTS = ['all', 'high_load', 'single_hot_all', 'single_hot_dominant',
           'few_hot_all', 'few_hot_dominant', 'hotspot_window_union',
           'hotspot_dominant_union', 'ordinary', 'balanced_high',
           'sample_hotspot', 'sample_balanced', 'sample_ordinary']
PACKET_TYPES = ['INVALID', 'RST', 'SYNACK', 'SYN', 'FIN', 'DATA', 'PURE_ACK', 'OTHER']
SEQ_EVENTS = ['NA', 'INVALID', 'BASELINE', 'IN_ORDER', 'AHEAD_GAP', 'GAP_FILL',
              'PREFIX_UNOBSERVED', 'DUP_FULL', 'OVERLAP_PARTIAL']
ACK_EVENTS = ['NA', 'INVALID', 'BASELINE', 'ADVANCE', 'REPEAT', 'WINDOW_UPDATE', 'SAME', 'BACKWARD']
CANDIDATE_SEQ = {'AHEAD_GAP', 'GAP_FILL', 'PREFIX_UNOBSERVED', 'DUP_FULL', 'OVERLAP_PARTIAL'}
CONDITIONAL_PREFIX = {'seq_event_given_data': 'data_', 'seq_event_given_payload': 'payload_bearing_',
                      'ack_event_given_ack': 'ack_bearing_'}
REQUIRED = {'endpoint', 'connection', 'session_id', 'ts', 'direction', 'packet_type',
            'payload_bytes', 'wire_bytes', 'seq', 'ack', 'flags', 'window',
            'seq_event', 'ack_event', 'uncertainty', 'cohorts', 'handshake_complete'}


def truth(value):
    return str(value).lower() in {'1', 'true', 'yes'}


def nanoseconds(value):
    whole, _, frac = value.partition('.')
    return int(whole) * 1_000_000_000 + int((frac + '000000000')[:9])


def open_text(path):
    return gzip.open(path, 'rt', encoding='utf-8', newline='') if path.suffix == '.gz' else path.open(encoding='utf-8', newline='')


def write_csv(path, fields, rows):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def fraction(a, b):
    return a / b if b else None


class Distribution:
    """Exact integer counts and deterministic bounded reservoir for durations."""
    __slots__ = ('count', 'total', 'maximum', 'sample', 'capacity', 'rng')

    def __init__(self, capacity=65536, seed=0):
        self.count = 0
        self.total = 0.0
        self.maximum = None
        self.sample = []
        self.capacity = capacity
        self.rng = random.Random(seed)

    def add(self, value):
        self.count += 1
        self.total += value
        self.maximum = value if self.maximum is None else max(self.maximum, value)
        if len(self.sample) < self.capacity:
            self.sample.append(value)
        else:
            index = self.rng.randrange(self.count)
            if index < self.capacity:
                self.sample[index] = value

    def summary(self, prefix):
        a = sorted(self.sample)
        answer = {f'{prefix}_count': self.count, f'{prefix}_mean': fraction(self.total, self.count),
                  f'{prefix}_max': self.maximum, f'{prefix}_quantile_sample_size': len(a),
                  f'{prefix}_quantiles_exact': self.count <= self.capacity}
        for q in [.5, .9, .99]:
            answer[f'{prefix}_p{int(q * 100)}'] = a[max(0, math.ceil(q * len(a)) - 1)] if a else None
        return answer


class RunStats:
    __slots__ = ('lengths', 'duration')

    def __init__(self, reservoir_size):
        self.lengths = Counter()
        self.duration = Distribution(reservoir_size)

    def add(self, packets, start, end):
        if packets:
            self.lengths[packets] += 1
            self.duration.add((end - start) / 1e9)

    def summary(self):
        n = sum(self.lengths.values())
        row = {'run_count': n, 'run_packet_total': sum(k * v for k, v in self.lengths.items()),
               'run_packets_mean': fraction(sum(k * v for k, v in self.lengths.items()), n),
               'run_packets_max': max(self.lengths, default=None)}
        for q in [.5, .9, .99]:
            target = max(1, math.ceil(n * q))
            cumulative = 0
            value = None
            for k, v in sorted(self.lengths.items()):
                cumulative += v
                if cumulative >= target:
                    value = k
                    break
            row[f'run_packets_p{int(q * 100)}'] = value
        row.update(self.duration.summary('duration_s'))
        return row


class Episode:
    __slots__ = ('n', 'm', 'previous_candidate', 'last_candidate_ts', 'last_ts',
                 'last_bin', 'run_n', 'run_start', 'run_last')

    def __init__(self):
        self.n = self.m = self.run_n = 0
        self.previous_candidate = ''
        self.last_candidate_ts = self.last_ts = self.last_bin = None
        self.run_start = self.run_last = None


def load_context(input_dir):
    contexts = {}
    expected_packets = Counter()
    path = input_dir / 'sessions.csv'
    if not path.exists():
        raise FileNotFoundError(f'{path}: final session context is required before summarization')
    with open_text(path) as stream:
        reader = csv.DictReader(stream)
        required = {'session_id', 'endpoint', 'connection', 'tx_packets', 'rx_packets', 'handshake_complete', 'tuple_reused'}
        if not required <= set(reader.fieldnames or []):
            raise ValueError(f'{path}: missing {sorted(required - set(reader.fieldnames or []))}')
        for row in reader:
            reasons = []
            if not int(row['tx_packets']) or not int(row['rx_packets']):
                reasons.append('ONE_DIRECTION_ONLY')
            if truth(row['tuple_reused']):
                reasons.append('TUPLE_REUSED')
            if not truth(row['handshake_complete']):
                reasons.append('HANDSHAKE_NOT_CONFIRMED')
            key = (row['endpoint'], row['connection'], row['session_id'])
            if key in contexts:
                raise ValueError(f'duplicate session key: {key}')
            contexts[key] = tuple(reasons)
            expected_packets[row['endpoint']] += int(row['tx_packets']) + int(row['rx_packets'])
    return contexts, expected_packets


def timeline_specs(phase2_dir):
    """Select existing real examples before streaming, without choosing on events."""
    result = []
    sample_path = phase2_dir / 'representative_samples.csv'
    segment_path = phase2_dir / 'hotspot_segments_complete.csv'
    if not sample_path.exists() or not segment_path.exists():
        return result
    with open_text(sample_path) as stream:
        samples = {row['name']: row for row in csv.DictReader(stream)}
    with open_text(segment_path) as stream:
        segments = [row for row in csv.DictReader(stream) if float(row['window_s']) == 1 and row['kind'] == 'single']
    if 'hotspot' in samples:
        sample = samples['hotspot']
        found = [s for s in segments if s['endpoint'] == sample['endpoint'] and float(s['start_ts']) == float(sample['start_ts']) and float(s['end_ts']) == float(sample['end_ts'])]
        if found:
            row = found[0]
            result.append({'example': 'D_hotspot', 'endpoint': row['endpoint'],
                           'connection': json.loads(row['connection_ids'])[0],
                           'start_ts': row['start_ts'], 'end_ts': row['end_ts'], 'selection': 'phase2 longest same-connection single hotspot'})
    profile_path = phase2_dir / 'window_profiles_1s.csv.gz'
    if 'balanced' in samples and profile_path.exists():
        sample = samples['balanced']
        with open_text(profile_path) as stream:
            for row in csv.DictReader(stream):
                if row['endpoint'] == sample['endpoint'] and float(row['start_ts']) == float(sample['start_ts']):
                    result.append({'example': 'A_balanced', 'endpoint': row['endpoint'],
                                   'connection': row['top1_connection'], 'start_ts': sample['start_ts'],
                                   'end_ts': sample['end_ts'], 'selection': 'phase2 balanced sample top1'})
                    break
    c = [s for s in segments if s['endpoint'] == ENDPOINTS[2]]
    if c:
        row = max(c, key=lambda s: (float(s['duration_s']), int(s['endpoint_packets'])))
        result.append({'example': 'C_hotspot', 'endpoint': row['endpoint'],
                       'connection': json.loads(row['connection_ids'])[0], 'start_ts': row['start_ts'],
                       'end_ts': row['end_ts'], 'selection': 'phase2 C longest same-connection single hotspot'})
    return result


def summarize(input_dir, out_dir, phase2_dir, reservoir_size=65536):
    out_dir.mkdir(parents=True, exist_ok=True)
    contexts, expected_packets = load_context(input_dir)
    specs = timeline_specs(phase2_dir)
    examples = defaultdict(list)
    for spec in specs:
        examples[(spec['endpoint'], spec['connection'])].append((nanoseconds(spec['start_ts']), nanoseconds(spec['end_ts']), spec['example']))
    counts = defaultdict(Counter)
    details = defaultdict(lambda: [0, 0, 0, 0, 0])
    runs = defaultdict(lambda: RunStats(reservoir_size))
    intervals = defaultdict(lambda: Distribution(reservoir_size))
    episodes = defaultdict(Counter)
    pairs = Counter()
    # One current session per observed tuple/direction, and at most one episode
    # per cohort. Prior session states are flushed on the next session packet.
    streams = {}
    seen_endpoints = set()
    seen_cohorts = set(COHORTS)
    total = 0
    missing_context = 0
    timeline_counts = Counter()
    event_path = input_dir / 'events.csv.gz'
    if not event_path.exists():
        event_path = input_dir / 'events.csv'

    def close_episode(ep, cohort, state):
        key = ep, cohort
        runs[key].add(state.run_n, state.run_start, state.run_last)
        if state.n:
            episodes[key]['episodes'] += 1
            episodes[key]['random_adjacent_expectation'] += state.m * (state.m - 1) / state.n

    timeline_path = out_dir / 'timeline_packets.csv.gz'
    with open_text(event_path) as stream, gzip.open(timeline_path, 'wt', encoding='utf-8', newline='') as timeline:
        reader = csv.DictReader(stream)
        if not REQUIRED <= set(reader.fieldnames or []):
            raise ValueError(f'{event_path}: missing {sorted(REQUIRED - set(reader.fieldnames or []))}')
        timeline_fields = ['example'] + list(reader.fieldnames) + ['final_uncertainty']
        timeline_writer = csv.DictWriter(timeline, timeline_fields)
        timeline_writer.writeheader()
        for row in reader:
            total += 1
            ts = nanoseconds(row['ts'])
            ep, conn, sid, direction = (row[k] for k in ['endpoint', 'connection', 'session_id', 'direction'])
            if direction not in {'TX', 'RX'}:
                raise ValueError(f'unknown direction: {direction}')
            if row['packet_type'] not in PACKET_TYPES or row['seq_event'] not in SEQ_EVENTS or row['ack_event'] not in ACK_EVENTS:
                raise ValueError(f'unknown event label at packet {total}')
            seen_endpoints.add(ep)
            cohort_names = set(filter(None, row['cohorts'].split(';')))
            cohort_names.add('all')
            seen_cohorts.update(cohort_names)
            reasons = set(filter(None, row['uncertainty'].split(';')))
            context_key = ep, conn, sid
            if context_key not in contexts:
                missing_context += 1
                raise ValueError(f'event references missing final session: {context_key}')
            reasons.update(contexts[context_key])
            payload, wire, flags = (int(row[k]) for k in ['payload_bytes', 'wire_bytes', 'flags'])
            wire_valid, payload_valid = wire >= 0, payload >= 0 and row['packet_type'] != 'INVALID'
            wire, payload = max(0, wire), max(0, payload) if payload_valid else 0
            routine = flags >= 0 and not flags & 7 and (
                (payload > 0 and row['seq_event'] == 'IN_ORDER') or
                (row['packet_type'] == 'PURE_ACK' and row['ack_event'] == 'ADVANCE'))
            candidate = []
            if row['seq_event'] in CANDIDATE_SEQ:
                candidate.append('SEQ_' + row['seq_event'])
            if row['ack_event'] == 'BACKWARD':
                candidate.append('ACK_BACKWARD')
            if 'ACK_UNOBSERVED' in reasons:
                candidate.append('ACK_UNOBSERVED')
            candidate_label = '+'.join(candidate)
            conditions = []
            dimensions = [('packet_type', [row['packet_type']]), ('seq_event', [row['seq_event']]),
                          ('ack_event', [row['ack_event']]), ('direction', [direction]),
                          ('uncertainty', sorted(reasons) if reasons else ['NONE'])]
            if row['packet_type'] == 'DATA':
                conditions.append('data_')
                dimensions.append(('seq_event_given_data', [row['seq_event']]))
            if payload_valid and payload > 0:
                conditions.append('payload_bearing_')
                dimensions.append(('seq_event_given_payload', [row['seq_event']]))
            if row['packet_type'] != 'INVALID' and flags >= 0 and flags & 16:
                conditions.append('ack_bearing_')
                dimensions.append(('ack_event_given_ack', [row['ack_event']]))
            for start, end, example in examples.get((ep, conn), ()):
                if start <= ts < end:
                    timeline_writer.writerow(dict(row, example=example, final_uncertainty=';'.join(sorted(reasons))))
                    timeline_counts[example] += 1
            stream_key = ep, conn, direction
            old = streams.get(stream_key)
            if old and old[1].get('all') and ts < old[1]['all'].last_ts:
                raise ValueError(f'{event_path}, packet {total}: directional stream timestamps are not sorted')
            if old is None or old[0] != sid:
                if old:
                    for cohort, state in old[1].items():
                        close_episode(ep, cohort, state)
                active = {}
                streams[stream_key] = sid, active
            else:
                active = old[1]
            for cohort in list(active):
                state = active[cohort]
                # Epoch-aligned 1s cohort windows are contiguous only when
                # consecutive observed bins differ by at most one.
                gap = cohort != 'all' and state.last_bin is not None and ts // 1_000_000_000 - state.last_bin > 1
                if cohort not in cohort_names or gap:
                    close_episode(ep, cohort, active.pop(cohort))
            for cohort in cohort_names:
                key = ep, cohort
                counter = counts[key]
                counter['packets'] += 1
                counter['wire_bytes'] += wire
                counter['valid_payload_bytes'] += payload
                counter['wire_valid_packets'] += wire_valid
                counter['payload_valid_packets'] += payload_valid
                counter['uncertain_packets'] += bool(reasons)
                counter['candidate_packets'] += bool(candidate_label)
                for prefix in conditions:
                    counter[prefix + 'packets'] += 1
                    counter[prefix + 'wire_bytes'] += wire
                    counter[prefix + 'valid_payload_bytes'] += payload
                for dimension, labels in dimensions:
                    for label in labels:
                        bucket = details[(ep, cohort, dimension, label)]
                        bucket[0] += 1
                        bucket[1] += wire
                        bucket[2] += payload
                        bucket[3] += wire_valid
                        bucket[4] += payload_valid
                state = active.get(cohort)
                if state is None:
                    state = active[cohort] = Episode()
                state.n += 1
                if routine:
                    if not state.run_n:
                        state.run_start = ts
                    state.run_n += 1
                    state.run_last = ts
                elif state.run_n:
                    runs[key].add(state.run_n, state.run_start, state.run_last)
                    state.run_n = 0
                if candidate_label:
                    state.m += 1
                    if state.last_candidate_ts is not None:
                        intervals[key].add((ts - state.last_candidate_ts) / 1e9)
                    if state.previous_candidate:
                        episodes[key]['adjacent_candidate_pairs'] += 1
                        pairs[(ep, cohort, state.previous_candidate, candidate_label)] += 1
                    state.last_candidate_ts = ts
                state.previous_candidate = candidate_label
                state.last_ts = ts
                state.last_bin = ts // 1_000_000_000
            if total % 500_000 == 0:
                print(f'phase3 summary: {total:,} packets; {len(streams):,} directional tuple streams', file=sys.stderr, flush=True)
    for (ep, _, _), (_, active) in streams.items():
        for cohort, state in active.items():
            close_episode(ep, cohort, state)

    # Explicit empty cohort rows prevent sparse endpoint cohorts from silently
    # disappearing. Zero denominators are represented by blank CSV / JSON null.
    for ep in seen_endpoints:
        for cohort in seen_cohorts:
            counts[ep, cohort]
    for ep in set(expected_packets) | seen_endpoints:
        if counts[ep, 'all']['packets'] != expected_packets[ep]:
            raise ValueError(f'{ep}: events/session packet conservation failed: '
                             f'{counts[ep, "all"]["packets"]} != {expected_packets[ep]}')
    for (ep, cohort), c in counts.items():
        for dimension in ['packet_type', 'seq_event', 'ack_event', 'direction', *CONDITIONAL_PREFIX]:
            values = [v for (e, co, dim, _), v in details.items() if (e, co, dim) == (ep, cohort, dimension)]
            prefix = CONDITIONAL_PREFIX.get(dimension, '')
            if any(sum(v[i] for v in values) != c[prefix + key] for i, key in enumerate(['packets', 'wire_bytes', 'valid_payload_bytes'])):
                raise ValueError(f'{ep}/{cohort}/{dimension}: category conservation failed')
    order = lambda key: (LETTERS.get(key[0], key[0]), COHORTS.index(key[1]) if key[1] in COHORTS else 100, key[1])
    summaries = []
    run_rows = []
    anomaly_rows = []
    histogram_rows = []
    for key in sorted(counts, key=order):
        ep, cohort = key
        c = counts[key]
        row = {'endpoint': ep, 'label': LETTERS.get(ep, ep), 'cohort': cohort,
               **{k: c[k] for k in ['packets', 'wire_bytes', 'valid_payload_bytes', 'wire_valid_packets',
                                   'payload_valid_packets', 'uncertain_packets', 'candidate_packets',
                                   *[prefix + metric for prefix in CONDITIONAL_PREFIX.values()
                                     for metric in ['packets', 'wire_bytes', 'valid_payload_bytes']]]},
               'uncertain_packet_fraction': fraction(c['uncertain_packets'], c['packets'])}
        summaries.append(row)
        run = runs[key]
        run_rows.append({'endpoint': ep, 'cohort': cohort, 'definition': 'routine_observed', **run.summary()})
        for length, count in sorted(run.lengths.items()):
            histogram_rows.append({'endpoint': ep, 'cohort': cohort, 'run_packets': length, 'runs': count})
        an = episodes[key]
        observed = an['adjacent_candidate_pairs']
        expected = an['random_adjacent_expectation']
        anomaly_rows.append({'endpoint': ep, 'cohort': cohort, 'packets': c['packets'],
                             'candidate_packets': c['candidate_packets'], 'stream_episodes': an['episodes'],
                             'adjacent_candidate_pairs': observed, 'random_adjacent_expectation': expected,
                             'observed_over_random_expectation': fraction(observed, expected),
                             **intervals[key].summary('candidate_interval_s')})
    detail_rows = []
    for (ep, cohort, dimension, label), value in sorted(details.items()):
        c = counts[ep, cohort]
        prefix = CONDITIONAL_PREFIX.get(dimension, '')
        packet_denominator, wire_denominator, payload_denominator = (c[prefix + k] for k in ['packets', 'wire_bytes', 'valid_payload_bytes'])
        detail_rows.append({'endpoint': ep, 'cohort': cohort, 'dimension': dimension, 'event': label,
                            'packets': value[0], 'wire_bytes': value[1], 'valid_payload_bytes': value[2],
                            'wire_valid_packets': value[3], 'payload_valid_packets': value[4],
                            'denominator_kind': prefix.rstrip('_') if prefix else 'cohort',
                            'packet_denominator': packet_denominator, 'wire_byte_denominator': wire_denominator,
                            'valid_payload_byte_denominator': payload_denominator,
                            'packet_fraction': fraction(value[0], packet_denominator),
                            'wire_byte_fraction': fraction(value[1], wire_denominator),
                            'valid_payload_byte_fraction': fraction(value[2], payload_denominator)})
    outputs = []
    for name, rows in [('cohort_summary', summaries), ('event_summary', detail_rows),
                       ('normal_runs', run_rows), ('normal_run_histogram', histogram_rows),
                       ('anomaly_clustering', anomaly_rows)]:
        path = out_dir / f'{name}.csv'
        # An entirely empty event input is a mistake; ordinary empty cohorts are
        # still explicitly emitted above when there are other input events.
        fields = list(rows[0]) if rows else ['endpoint', 'cohort', 'run_packets', 'runs']
        write_csv(path, fields, rows)
        outputs.append(path.name)
    pair_rows = [{'endpoint': ep, 'cohort': cohort, 'previous_event': prev, 'event': event, 'pairs': n}
                 for (ep, cohort, prev, event), n in sorted(pairs.items())]
    write_csv(out_dir / 'anomaly_adjacent_pairs.csv', ['endpoint', 'cohort', 'previous_event', 'event', 'pairs'], pair_rows)
    outputs += ['anomaly_adjacent_pairs.csv', timeline_path.name]
    spec_path = out_dir / 'timeline_examples.json'
    spec_path.write_text(json.dumps([dict(s, observed_packets=timeline_counts[s['example']]) for s in specs], ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    outputs.append(spec_path.name)
    if not total:
        raise ValueError('events input contains no packets')
    manifest = {'status': 'event_classification_summarized', 'fast_path_status': 'deferred_by_user',
                'input_events': str(event_path.resolve()), 'input_sessions': str((input_dir / 'sessions.csv').resolve()),
                'input_packets': total, 'sessions': len(contexts), 'missing_session_context_packets': missing_context,
                'conservation_checks_passed': True,
                'endpoint_labels': LETTERS, 'outputs': outputs,
                'definitions': {
                    'cohorts': 'phase2 1s tags; cohorts may overlap and cannot be summed; all includes partial boundary windows',
                    'wire_bytes': 'sum of available original pcap record lengths; no invented link overhead',
                    'valid_payload_bytes': 'sum of nonnegative inferred TCP payload lengths for non-INVALID packets; not deduplicated goodput; payload_valid_packets excludes INVALID even when unknown length was exported as zero',
                    'conditional_denominators': 'seq_event_given_data: morphology DATA; seq_event_given_payload: all valid payload>0 including payload on SYN/FIN/RST; ack_event_given_ack: valid fixed TCP fields with ACK bit. Each row uses packet, wire and valid-payload sums of its own condition set, not all-cohort totals',
                    'uncertainty': 'packet flags plus final ONE_DIRECTION_ONLY, TUPLE_REUSED, HANDSHAKE_NOT_CONFIRMED; reasons can overlap; no flag proves actual capture loss',
                    'routine_observed': 'no SYN/FIN/RST; payload>0 with seq_event IN_ORDER, or PURE_ACK with ack_event ADVANCE; only used to describe normal-event runs; not a fast path',
                    'normal_runs': 'same session and direction; break on any non-routine packet, cohort exit, session change, or skipped 1s cohort bin; all cohort permits idle time; durations are last-first observed packet times',
                    'candidate': 'seq AHEAD_GAP/GAP_FILL/PREFIX_UNOBSERVED/DUP_FULL/OVERLAP_PARTIAL, ack BACKWARD, or ACK_UNOBSERVED uncertainty; candidates are not established network faults',
                    'anomaly_adjacency': 'candidate packets adjacent in the original same-session same-direction stream within a contiguous cohort episode; no intervening packet is removed',
                    'candidate_intervals': 'time between successive candidates in each same-stream cohort episode, including intervening ordinary packets',
                    'random_baseline': 'sum of m*(m-1)/n over same-stream contiguous cohort episodes with n packets and m candidate packets; descriptive permutation expectation, not a significance test',
                    'quantiles': f'nearest-rank; run packet counts exact; duration and candidate interval quantiles use deterministic reservoir size {reservoir_size}, exact if the event count fits reservoir; counts, means and maxima exact',
                    'fast_path': 'user deferred all fast-path classification and proportions; no deployable parallel fraction inferred'},
                'reservoir_size': reservoir_size}
    (out_dir / 'summary_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (out_dir / 'summary.json').write_text(json.dumps({'cohorts': summaries, 'normal_runs': run_rows, 'anomaly_clustering': anomaly_rows}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'phase3 summary complete: {total:,} packets; {len(summaries)} endpoint/cohort rows', file=sys.stderr)
    return manifest


def self_test():
    """Small behavioral checks for cohort breaks, final context and adjacency."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix='phase3-summary-test-') as directory:
        p = Path(directory)
        ep = ENDPOINTS[0]
        conn = json.dumps([ep, 1, 'peer', 2], separators=(',', ':'))
        write_csv(p / 'sessions.csv', ['session_id', 'endpoint', 'connection', 'tx_packets', 'rx_packets', 'handshake_complete', 'tuple_reused'],
                  [dict(session_id='1', endpoint=ep, connection=conn, tx_packets=7, rx_packets=0, handshake_complete=0, tuple_reused=1)])
        rows = []
        for i, (ts, seq, cohort) in enumerate([('1.0', 'IN_ORDER', 'all;ordinary'), ('1.1', 'IN_ORDER', 'all;ordinary'),
                                             ('1.2', 'AHEAD_GAP', 'all;ordinary'), ('1.3', 'DUP_FULL', 'all;ordinary'),
                                             ('1.4', 'IN_ORDER', 'all'), ('4.0', 'IN_ORDER', 'all;ordinary'),
                                             ('4.1', 'IN_ORDER', 'all;ordinary')]):
            rows.append(dict(endpoint=ep, connection=conn, session_id='1', ts=ts, direction='TX', packet_type='DATA',
                             payload_bytes=10, wire_bytes=50, seq=i * 10, ack=0, flags=16, window=1, seq_event=seq,
                             ack_event='NA', uncertainty='', cohorts=cohort, handshake_complete=0))
        write_csv(p / 'events.csv', list(rows[0]), rows)
        summarize(p, p / 'out', p / 'absent', reservoir_size=100)
        with (p / 'out' / 'cohort_summary.csv').open() as h:
            c = {r['cohort']: r for r in csv.DictReader(h)}
        assert int(c['all']['packets']) == 7 and int(c['all']['wire_bytes']) == 350
        assert int(c['all']['uncertain_packets']) == 7 and int(c['ordinary']['packets']) == 6
        assert all(int(c['all'][field]) == 7 for field in ['data_packets', 'payload_bearing_packets', 'ack_bearing_packets'])
        with (p / 'out' / 'event_summary.csv').open() as h:
            event_rows = list(csv.DictReader(h))
            reasons = {r['event']: int(r['packets']) for r in event_rows if r['cohort'] == 'all' and r['dimension'] == 'uncertainty'}
        assert all(reasons[reason] == 7 for reason in ['ONE_DIRECTION_ONLY', 'TUPLE_REUSED', 'HANDSHAKE_NOT_CONFIRMED'])
        for dimension in CONDITIONAL_PREFIX:
            conditional = [r for r in event_rows if r['cohort'] == 'all' and r['dimension'] == dimension]
            assert sum(int(r['packets']) for r in conditional) == 7
            assert all(int(r['packet_denominator']) == 7 and int(r['wire_byte_denominator']) == 350
                       and int(r['valid_payload_byte_denominator']) == 70 for r in conditional)
        with (p / 'out' / 'normal_runs.csv').open() as h:
            r = {r['cohort']: r for r in csv.DictReader(h)}
        assert int(r['ordinary']['run_count']) == 2 and int(r['ordinary']['run_packets_max']) == 2
        with (p / 'out' / 'anomaly_clustering.csv').open() as h:
            a = {r['cohort']: r for r in csv.DictReader(h)}
        assert int(a['all']['adjacent_candidate_pairs']) == 1
        assert abs(float(a['all']['random_adjacent_expectation']) - 2 / 7) < 1e-12
        assert abs(float(a['ordinary']['random_adjacent_expectation']) - .5) < 1e-12
        # A new endpoint may start earlier in time when independently sorted
        # input groups are concatenated. A cohort bin gap must still end a run.
        rows = rows[:2]
        rows[0]['ts'], rows[1]['ts'] = '10.0', '13.0'
        rows[0]['uncertainty'] = rows[1]['uncertainty'] = ''
        other = dict(rows[0], endpoint=ENDPOINTS[1], session_id='2', ts='1.0', packet_type='SYN', flags=2, seq_event='BASELINE', payload_bytes=10)
        rows.extend([other, dict(other, ts='1.1', packet_type='INVALID', flags=16, seq_event='INVALID', payload_bytes=777)])
        write_csv(p / 'sessions.csv', ['session_id', 'endpoint', 'connection', 'tx_packets', 'rx_packets', 'handshake_complete', 'tuple_reused'],
                  [dict(session_id='1', endpoint=ep, connection=conn, tx_packets=2, rx_packets=0, handshake_complete=0, tuple_reused=0),
                   dict(session_id='2', endpoint=ENDPOINTS[1], connection=conn, tx_packets=2, rx_packets=0, handshake_complete=0, tuple_reused=0)])
        write_csv(p / 'events.csv', list(rows[0]), rows)
        summarize(p, p / 'out2', p / 'absent', reservoir_size=100)
        with (p / 'out2' / 'normal_runs.csv').open() as h:
            r = {(r['endpoint'], r['cohort']): r for r in csv.DictReader(h)}
        assert int(r[ep, 'ordinary']['run_count']) == 2
        assert int(r[ep, 'all']['run_count']) == 1 and int(r[ep, 'all']['run_packets_max']) == 2
        assert int(r[ENDPOINTS[1], 'all']['run_count']) == 0
        with (p / 'out2' / 'cohort_summary.csv').open() as h:
            r = {(r['endpoint'], r['cohort']): r for r in csv.DictReader(h)}
        row = r[ENDPOINTS[1], 'all']
        assert int(row['data_packets']) == 0 and int(row['payload_bearing_packets']) == 1 and int(row['ack_bearing_packets']) == 0
        assert int(row['valid_payload_bytes']) == 10 and int(row['payload_valid_packets']) == 1
    print('summarize_phase3 self-test passed', file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', type=Path, default=ROOT / 'report/phase3_mawi')
    parser.add_argument('--out-dir', type=Path, default=ROOT / 'report/phase3_mawi')
    parser.add_argument('--phase2-dir', type=Path, default=ROOT / 'report/phase2_mawi')
    parser.add_argument('--reservoir-size', type=int, default=65536)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.reservoir_size < 1:
        parser.error('--reservoir-size must be positive')
    summarize(args.input_dir, args.out_dir, args.phase2_dir, args.reservoir_size)


if __name__ == '__main__':
    main()
