#!/usr/bin/env python3
"""Conservative, observational TCP event classification over full endpoint traces.

Sequence ranges describe captured headers, not verified payload identity or a
receiver TCP stack. Repeated ranges are not diagnosed as retransmissions. The
normal-run analysis is separate from the explicitly deferred fast-path task.
Only the Python standard library is required by this classifier.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
import csv
from dataclasses import dataclass, field
import gzip
import hashlib
import json
import math
from pathlib import Path
import sys
import time

MOD = 1 << 32
HALF = 1 << 31
SYN, FIN, RST, ACK = 2, 1, 4, 16
ROOT = Path(__file__).resolve().parents[1]
PRIMARY = ('150.74.240.107', '203.42.121.173', '203.42.117.47')
CONTROL = ('2001:fab8:1071:93ea:700:1a:3fc1:7e80', '202.249.10.115', '43.15.244.195')
EVENT_FIELDS = ('endpoint connection session_id ts direction packet_type '
                'payload_bytes wire_bytes seq ack flags window seq_event ack_event '
                'uncertainty cohorts handshake_complete seq_unwrapped ack_unwrapped '
                'seq_frontier seq_highwater advertised_window').split()
SESSION_FIELDS = ('session_id endpoint connection tx_packets rx_packets first_ts '
                  'last_ts syn_tx syn_rx handshake_complete closed tuple_reused '
                  'handshake_ts fin_tx fin_rx payload_bytes').split()


def unwrap32(raw: int, reference: int | None) -> tuple[int, bool]:
    """Nearest serial-number representative; half-space is explicitly ambiguous."""
    if reference is None:
        return raw, False
    delta = (raw - (reference % MOD)) % MOD
    return reference + (delta if delta < HALF else delta - MOD), delta == HALF


class SequenceSet:
    """Exact union of half-open observed intervals, including holes."""
    __slots__ = ('ranges',)

    def __init__(self):
        self.ranges: list[tuple[int, int]] = []

    def overlap(self, lo, hi):
        if hi <= lo:
            return 0
        i = max(0, bisect_right(self.ranges, (lo, float('inf'))) - 1)
        overlap = 0
        while i < len(self.ranges) and self.ranges[i][0] < hi:
            a, b = self.ranges[i]
            overlap += max(0, min(b, hi) - max(a, lo))
            i += 1
        return overlap

    def add(self, lo, hi):
        overlap = self.overlap(lo, hi)
        if hi <= lo:
            return overlap
        i = bisect_left(self.ranges, (lo,))
        if i and self.ranges[i - 1][1] >= lo:
            i -= 1
        j = i
        while j < len(self.ranges) and self.ranges[j][0] <= hi:
            lo = min(lo, self.ranges[j][0])
            hi = max(hi, self.ranges[j][1])
            j += 1
        self.ranges[i:j] = [(lo, hi)]
        return overlap

    def covers(self, lo, hi):
        return hi <= lo or self.overlap(lo, hi) == hi - lo

    def contiguous_from(self, anchor):
        if anchor is None:
            return None
        i = bisect_right(self.ranges, (anchor, float('inf'))) - 1
        return self.ranges[i][1] if i >= 0 and self.ranges[i][0] <= anchor <= self.ranges[i][1] else anchor


@dataclass(slots=True)
class Packet:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    plen: int
    flags: int
    seq: int
    ack: int
    win: int = 65535
    thl: int = 20
    caplen: int = 54
    wirelen: int = 54
    opts_trunc: int = 0
    payload_adjusted: bool = False


def parse_packet(line, syn_payload_zero=False):
    cols = line.rstrip('\n').split('\t')
    if len(cols) != 16 or cols[1] != '6':
        raise ValueError('expected one standard 16-column TCP TSV row')
    p = Packet(float(cols[0]), cols[2], cols[3], int(cols[4]), int(cols[5]),
               int(cols[7]), int(cols[8]), int(cols[9]), int(cols[10]),
               int(cols[11]), int(cols[12]), int(cols[13]), int(cols[14]), int(cols[15]))
    if syn_payload_zero and p.flags >= 0 and p.flags & SYN and p.plen > 0:
        p.plen = 0
        p.payload_adjusted = True
    return p


def shape(flags, plen):
    if flags < 0 or plen < 0:
        return 'INVALID'
    if flags & RST:
        return 'RST'
    if flags & SYN:
        return 'SYNACK' if flags & ACK else 'SYN'
    if flags & FIN:
        return 'FIN'
    if plen > 0:
        return 'DATA'
    return 'PURE_ACK' if flags & ACK else 'OTHER'


@dataclass(slots=True)
class Direction:
    seqs: SequenceSet = field(default_factory=SequenceSet)
    payload: SequenceSet = field(default_factory=SequenceSet)
    anchor: int | None = None
    high: int | None = None
    syn_isn: int | None = None
    syn_start: int | None = None
    syn_end: int | None = None
    max_ack: int | None = None
    last_window: int | None = None
    fin: bool = False
    ambiguous: bool = False


@dataclass(slots=True)
class Session:
    session_id: str
    endpoint: str
    key: tuple
    connection: str
    first_ts: float
    last_ts: float
    dirs: list = field(default_factory=lambda: [Direction(), Direction()])
    counts: list = field(default_factory=lambda: [0, 0])
    initial_syn_direction: int | None = None
    synack_verified: bool = False
    handshake_complete: bool = False
    handshake_ts: float | None = None
    closed: bool = False
    closing: bool = False
    tuple_reused: bool = False
    simultaneous_open: bool = False
    payload_bytes: int = 0


class TCPClassifier:
    def __init__(self, order_sensitive_seconds=0.0002, idle_uncertainty_seconds=60.0):
        self.order_sensitive_seconds = order_sensitive_seconds
        self.idle_uncertainty_seconds = idle_uncertainty_seconds
        self.sessions: dict[str, Session] = {}
        self.current: dict[tuple, Session] = {}

    def _session(self, endpoint, p, direction, key, valid):
        old = self.current.get(key)
        reuse = False
        if old and valid and p.flags & SYN:
            d = old.dirs[direction]
            different_isn = d.syn_isn is not None and p.seq != d.syn_isn
            new_bare = not (p.flags & ACK) and (
                old.closed or old.handshake_complete or (d.syn_isn is None and old.payload_bytes > 0))
            # A same-ISN retransmitted SYN during the handshake stays in its fragment.
            reuse = different_isn or new_bare
        if old is None or reuse:
            if reuse:
                old.tuple_reused = True
            sid = f's{len(self.sessions) + 1:07d}'
            old = Session(sid, endpoint, key, json.dumps(key, separators=(',', ':')),
                          p.ts, p.ts, tuple_reused=reuse)
            self.current[key] = old
            self.sessions[sid] = old
        return old

    def classify(self, endpoint: str, p: Packet) -> dict:
        if p.src == endpoint:
            direction, key = 0, (endpoint, p.sport, p.dst, p.dport)
        elif p.dst == endpoint:
            direction, key = 1, (endpoint, p.dport, p.src, p.sport)
        else:
            raise ValueError('packet does not belong to requested endpoint')
        valid = (0 <= p.flags <= 255 and p.plen >= 0 and 0 <= p.seq < MOD
                 and (not p.flags & ACK or 0 <= p.ack < MOD)
                 and p.thl >= 20 and p.thl <= 60 and p.thl % 4 == 0
                 and 0 <= p.sport <= 65535 and 0 <= p.dport <= 65535
                 and 0 <= p.win <= 65535
                 and not (p.flags & SYN and p.flags & (RST | FIN)))
        s = self._session(endpoint, p, direction, key, valid)
        d, peer = s.dirs[direction], s.dirs[1 - direction]
        reasons = set()
        delta = p.ts - s.last_ts if sum(s.counts) else None
        s.counts[direction] += 1
        s.last_ts = max(s.last_ts, p.ts)
        s.payload_bytes += max(p.plen, 0)
        packet_type = shape(p.flags, p.plen) if valid else 'INVALID'
        seq_event, ack_event = ('NA', 'NA') if valid else ('INVALID', 'INVALID')
        seq_value = ack_value = None
        if not valid:
            reasons.add('FIXED_FIELDS_INVALID')
        else:
            if delta is not None and delta > self.idle_uncertainty_seconds:
                d.ambiguous = peer.ambiguous = True
                reasons.add('LONG_IDLE_CONTEXT')
            if delta is not None and delta <= self.order_sensitive_seconds:
                reasons.add('TIMESTAMP_ORDER_SENSITIVE')
            if p.opts_trunc != 0:
                reasons.add('OPTIONS_TRUNCATED')
            if p.payload_adjusted:
                reasons.add('ANONYMIZED_SYN_PAYLOAD_ADJUSTED')
            if s.closed:
                reasons.add('AFTER_OBSERVED_CLOSE')
            if s.simultaneous_open:
                reasons.add('SIMULTANEOUS_OPEN')
            seq_reference = max((x for x in (d.high, peer.max_ack) if x is not None), default=None)
            seq_value, ambiguous = unwrap32(p.seq, seq_reference)
            if ambiguous:
                d.ambiguous = True
            if d.ambiguous:
                reasons.add('SEQ_ROUND_AMBIGUOUS')

            if not ambiguous:
                if p.flags & SYN:
                    if d.syn_isn is None:
                        d.syn_isn = p.seq
                        d.syn_start = seq_value
                        d.syn_end = seq_value + 1 + p.plen
                    if not p.flags & ACK:
                        if s.initial_syn_direction is None:
                            s.initial_syn_direction = direction
                        elif s.initial_syn_direction != direction:
                            s.simultaneous_open = True
                            reasons.add('SIMULTANEOUS_OPEN')
                    if d.anchor is None:
                        d.anchor = seq_value
                    d.seqs.add(seq_value, seq_value + 1)
                    d.high = max(d.high if d.high is not None else seq_value, seq_value + 1)
                if p.plen > 0:
                    lo = seq_value + int(bool(p.flags & SYN))
                    hi = lo + p.plen
                    overlap = d.payload.overlap(lo, hi)
                    frontier = d.seqs.contiguous_from(d.anchor)
                    old_high = d.high
                    if overlap == p.plen:
                        seq_event = 'DUP_FULL'
                    elif overlap:
                        seq_event = 'OVERLAP_PARTIAL'
                    elif d.anchor is None:
                        seq_event = 'BASELINE'
                        d.anchor = lo
                    elif lo < d.anchor:
                        seq_event = 'PREFIX_UNOBSERVED'
                    elif old_high is not None and frontier < old_high and lo < old_high:
                        seq_event = 'GAP_FILL'
                    elif lo == frontier:
                        seq_event = 'IN_ORDER'
                    elif lo > frontier:
                        seq_event = 'AHEAD_GAP'
                    else:
                        seq_event = 'PREFIX_UNOBSERVED'
                    if seq_event in ('DUP_FULL', 'OVERLAP_PARTIAL'):
                        reasons.add('REPEATED_RANGE_CAUSE_UNKNOWN')
                    if seq_event in ('AHEAD_GAP', 'GAP_FILL', 'PREFIX_UNOBSERVED'):
                        reasons.add('SEQUENCE_DISCONTINUITY_CAUSE_UNKNOWN')
                    if seq_event not in ('IN_ORDER', 'BASELINE') and delta is not None and delta <= self.order_sensitive_seconds:
                        reasons.add('TIMESTAMP_ORDER_SENSITIVE')
                    d.payload.add(lo, hi)
                consumed = p.plen + int(bool(p.flags & SYN)) + int(bool(p.flags & FIN))
                if consumed:
                    if d.anchor is None:
                        d.anchor = seq_value
                    d.seqs.add(seq_value, seq_value + consumed)
                    d.high = max(d.high if d.high is not None else seq_value, seq_value + consumed)
                if d.high is not None and d.seqs.contiguous_from(d.anchor) < d.high:
                    reasons.add('SEQ_GAP_UNRESOLVED')
            elif p.plen > 0:
                seq_event = 'INVALID'

            if p.flags & ACK:
                # Follow this direction's cumulative ACK history. An old peer
                # capture frontier must not turn later serial progress backward.
                reference = d.max_ack if d.max_ack is not None else peer.high
                ack_value, ack_ambiguous = unwrap32(p.ack, reference)
                if ack_ambiguous:
                    ack_event = 'INVALID'
                    reasons.add('ACK_ROUND_AMBIGUOUS')
                else:
                    previous_ack = d.max_ack
                    if previous_ack is None:
                        ack_event = 'BASELINE'
                    elif ack_value > previous_ack:
                        ack_event = 'ADVANCE'
                    elif ack_value < previous_ack:
                        ack_event = 'BACKWARD'
                        reasons.add('ACK_BACKWARD_CAUSE_UNKNOWN')
                    elif packet_type == 'PURE_ACK':
                        ack_event = 'WINDOW_UPDATE' if d.last_window is not None and p.win != d.last_window else 'REPEAT'
                    else:
                        ack_event = 'SAME'
                    if peer.high is None or ack_value > peer.high:
                        reasons.add('ACK_UNOBSERVED')
                    elif previous_ack is None and peer.anchor is not None and (
                            ack_value < peer.anchor or not peer.seqs.covers(peer.anchor, ack_value)):
                        reasons.add('ACK_UNOBSERVED')
                    elif previous_ack is not None and ack_value > previous_ack and not peer.seqs.covers(previous_ack, ack_value):
                        reasons.add('ACK_UNOBSERVED')
                    if peer.ambiguous:
                        reasons.add('ACK_PEER_SEQUENCE_AMBIGUOUS')
                    if previous_ack is None or ack_value >= previous_ack:
                        d.max_ack = ack_value
                        d.last_window = p.win
                    if (p.flags & SYN and s.initial_syn_direction == 1 - direction
                            and peer.syn_start is not None
                            and peer.syn_start + 1 <= ack_value <= peer.syn_end):
                        s.synack_verified = True
                    if (not s.closed and not s.closing
                            and not p.flags & (SYN | RST | FIN) and s.synack_verified
                            and s.initial_syn_direction == direction and peer.syn_start is not None
                            and d.syn_start is not None and d.syn_start + 1 <= seq_value <= d.syn_end
                            and peer.syn_start + 1 <= ack_value <= peer.syn_end and not s.handshake_complete):
                        s.handshake_complete = True
                        s.handshake_ts = p.ts
            if p.flags & FIN:
                d.fin = True
                s.closing = True
            if p.flags & RST or all(side.fin for side in s.dirs):
                s.closed = True
            if p.flags & 0xE0:
                reasons.add('URG_ECN_FLAGS_PRESENT')
            if p.win == 0:
                reasons.add('ZERO_ADVERTISED_WINDOW')
        if any(side.syn_isn is None for side in s.dirs):
            reasons.add('NO_INITIAL_SYN')
        if not s.handshake_complete:
            reasons.add('HANDSHAKE_NOT_OBSERVED')
        if s.tuple_reused:
            reasons.add('TUPLE_REUSED')
        return dict(endpoint=endpoint, connection=s.connection, session_id=s.session_id,
                    ts=f'{p.ts:.6f}', direction='TX' if direction == 0 else 'RX',
                    packet_type=packet_type, payload_bytes=max(0, p.plen), wire_bytes=max(0, p.wirelen),
                    seq=p.seq, ack=p.ack, flags=p.flags, window=math.floor(p.ts),
                    seq_event=seq_event, ack_event=ack_event, uncertainty=';'.join(sorted(reasons)),
                    cohorts='all', handshake_complete=int(s.handshake_complete),
                    seq_unwrapped='' if seq_value is None else seq_value,
                    ack_unwrapped='' if ack_value is None else ack_value,
                    seq_frontier='' if d.anchor is None else d.seqs.contiguous_from(d.anchor),
                    seq_highwater='' if d.high is None else d.high, advertised_window=p.win)


def nearest(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)] if ordered else 0


class CohortSelector:
    def __init__(self, phase2_dir):
        self.profiles = {}
        self.samples = []
        self.expectations = {}
        profile_path = Path(phase2_dir) / 'window_profiles_1s.csv.gz'
        with gzip.open(profile_path, 'rt', newline='') as handle:
            rows = list(csv.DictReader(handle))
        endpoints = sorted({r['endpoint'] for r in rows})
        for ep in endpoints:
            own = [r for r in rows if r['endpoint'] == ep]
            p40, p60 = (nearest([int(r['packets']) for r in own], p) for p in (.4, .6))
            for r in own:
                single, few, high = (r[key] in ('1', 'True', 'true') for key in ('is_hotspot', 'few_hot', 'is_high_load'))
                connection = tuple(json.loads(r['top1_connection'])) if r['top1_connection'] else None
                top5 = {tuple(json.loads(item)) for item in json.loads(r['top5_connections'])} if r['top5_connections'] else set()
                ordinary = p40 <= int(r['packets']) <= p60 and int(r['packets']) > 0
                balanced = high and int(r['active_connections']) >= 10 and float(r['top1_share']) <= .2 and float(r['top5_share']) <= .5
                self.profiles[ep, int(float(r['start_ts']))] = (high, single, few, connection, top5, ordinary, balanced)
                expected = {'high_load': high, 'single_hot_all': single, 'few_hot_all': few,
                            'hotspot_window_union': single or few, 'ordinary': ordinary, 'balanced_high': balanced}
                for name, selected in expected.items():
                    if selected:
                        self.expectations[ep, name] = self.expectations.get((ep, name), 0) + int(r['packets'])
                for name, selected, field in [('single_hot_dominant', single, 'top1_packets'), ('few_hot_dominant', few, 'top5_packets')]:
                    if selected:
                        self.expectations[ep, name] = self.expectations.get((ep, name), 0) + int(r[field])
        with (Path(phase2_dir) / 'representative_samples.csv').open(newline='') as handle:
            self.samples = list(csv.DictReader(handle))
        for r in self.samples:
            self.expectations[r['endpoint'], 'sample_' + r['name']] = int(r['endpoint_packets'])

    def labels(self, event):
        ep, second = event['endpoint'], event['window']
        result = ['all']
        profile = self.profiles.get((ep, second))
        if profile:
            high, single, few, top1, top5, ordinary, balanced = profile
            key = tuple(json.loads(event['connection']))
            if high:
                result.append('high_load')
            if single:
                result.append('single_hot_all')
                if key == top1:
                    result.append('single_hot_dominant')
            if few:
                result.append('few_hot_all')
                if key in top5:
                    result.append('few_hot_dominant')
            if single or few:
                result.append('hotspot_window_union')
            if (single and key == top1) or (few and key in top5):
                result.append('hotspot_dominant_union')
            if ordinary:
                result.append('ordinary')
            if balanced:
                result.append('balanced_high')
        ts = float(event['ts'])
        for sample in self.samples:
            if sample['endpoint'] == ep and float(sample['start_ts']) <= ts < float(sample['end_ts']):
                result.append('sample_' + sample['name'])
        return result


def write_sessions(engine, destination):
    with destination.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=SESSION_FIELDS)
        writer.writeheader()
        for s in engine.sessions.values():
            writer.writerow(dict(session_id=s.session_id, endpoint=s.endpoint, connection=s.connection,
                                 tx_packets=s.counts[0], rx_packets=s.counts[1], first_ts=f'{s.first_ts:.6f}',
                                 last_ts=f'{s.last_ts:.6f}', syn_tx=int(s.dirs[0].syn_isn is not None),
                                 syn_rx=int(s.dirs[1].syn_isn is not None), handshake_complete=int(s.handshake_complete),
                                 handshake_ts='' if s.handshake_ts is None else f'{s.handshake_ts:.6f}',
                                 closed=int(s.closed), tuple_reused=int(s.tuple_reused),
                                 fin_tx=int(s.dirs[0].fin), fin_rx=int(s.dirs[1].fin), payload_bytes=s.payload_bytes))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', action='append', type=Path)
    parser.add_argument('--endpoint-group', action='append', help='comma-separated endpoints for each --input')
    parser.add_argument('--out-dir', type=Path, default=ROOT / 'report/phase3_mawi')
    parser.add_argument('--phase2-dir', type=Path, default=ROOT / 'report/phase2_mawi')
    parser.add_argument('--skip-cohorts', action='store_true')
    parser.add_argument('--uni2-syn-payload-zero', action='store_true')
    parser.add_argument('--gzip-level', type=int, default=3)
    args = parser.parse_args()
    if args.input:
        if not args.endpoint_group or len(args.input) != len(args.endpoint_group):
            parser.error('provide one --endpoint-group for every --input')
        sources = list(zip(args.input, (tuple(s.split(',')) for s in args.endpoint_group)))
    else:
        sources = [(ROOT / 'data/mawi/mawi_endpoints.tsv', PRIMARY),
                   (ROOT / 'data/mawi/phase2_controls.tsv', CONTROL)]
    assigned = [ep for _, group in sources for ep in group]
    if len(assigned) != len(set(assigned)):
        parser.error('endpoint groups must be disjoint to avoid double counting')
    args.out_dir.mkdir(parents=True, exist_ok=True)
    selector = None if args.skip_cohorts else CohortSelector(args.phase2_dir)
    engine = TCPClassifier()
    counts = {ep: 0 for ep in assigned}
    cohort_counts = {}
    input_manifest = []
    start = time.monotonic()
    temporary = args.out_dir / 'events.csv.gz.partial'
    with gzip.open(temporary, 'wt', newline='', compresslevel=args.gzip_level) as target:
        writer = csv.DictWriter(target, fieldnames=EVENT_FIELDS)
        writer.writeheader()
        for path, endpoints in sources:
            digest, rows, selected = hashlib.sha256(), 0, set(endpoints)
            previous = None
            opener = gzip.open if str(path).endswith('.gz') else open
            with opener(path, 'rt') as source:
                for line in source:
                    digest.update(line.encode())
                    p = parse_packet(line, syn_payload_zero=args.uni2_syn_payload_zero)
                    if previous is not None and p.ts < previous:
                        raise ValueError(f'{path}: unsorted input at row {rows + 1}')
                    previous = p.ts
                    rows += 1
                    incidents = []
                    if p.src in selected:
                        incidents.append(p.src)
                    if p.dst in selected and p.dst != p.src:
                        incidents.append(p.dst)
                    for ep in incidents:
                        event = engine.classify(ep, p)
                        labels = selector.labels(event) if selector else ['all']
                        event['cohorts'] = ';'.join(labels)
                        writer.writerow(event)
                        counts[ep] += 1
                        for name in labels:
                            cohort_counts[ep, name] = cohort_counts.get((ep, name), 0) + 1
                    if rows % 1_000_000 == 0:
                        print(f'classified {path.name}: {rows:,} source rows; {sum(counts.values()):,} endpoint packets; '
                              f'{len(engine.sessions):,} fragments; elapsed {time.monotonic() - start:.1f}s', flush=True)
            input_manifest.append({'path': str(path), 'source_rows': rows, 'uncompressed_sha256': digest.hexdigest(),
                                   'endpoints': endpoints})
    checks = []
    if selector:
        for (ep, name), expected in selector.expectations.items():
            actual = cohort_counts.get((ep, name), 0)
            checks.append({'endpoint': ep, 'cohort': name, 'expected_packets': expected,
                           'actual_packets': actual, 'passed': actual == expected})
            if actual != expected:
                raise AssertionError(f'phase-2 cohort mismatch: {ep} {name}: {actual} != {expected}')
        with (args.phase2_dir / 'endpoint_statistics.csv').open(newline='') as handle:
            for r in csv.DictReader(handle):
                ep = r['endpoint']
                if ep in counts:
                    expected = int(r['packets'])
                    checks.append({'endpoint': ep, 'cohort': 'all', 'expected_packets': expected,
                                   'actual_packets': counts[ep], 'passed': counts[ep] == expected})
                    assert counts[ep] == expected, (ep, counts[ep], expected)
    write_sessions(engine, args.out_dir / 'sessions.csv')
    temporary.replace(args.out_dir / 'events.csv.gz')
    metadata = {'status': 'classified', 'phase3_real_trace_analysis_run': True,
                'fast_path_status': 'deferred_by_user', 'endpoint_packets': counts,
                'total_endpoint_packets': sum(counts.values()), 'session_fragments': len(engine.sessions),
                'inputs': input_manifest, 'cohort_checks': checks, 'all_checks_passed': all(r['passed'] for r in checks),
                'elapsed_seconds': time.monotonic() - start,
                'sequence_order': 'stable timestamp order, not verified receiver arrival order',
                'order_sensitivity_seconds': engine.order_sensitive_seconds,
                'idle_uncertainty_seconds': engine.idle_uncertainty_seconds,
                'session_split': 'changed ISN in observed SYN or SYNACK; or new bare SYN after observed close/establishment/midstream data; heuristic fragments only',
                'payload_basis': 'inferred original TCP payload length; not unique goodput or verified payload content',
                'wire_byte_basis': 'original pcap recorded packet length; no additional Ethernet overhead',
                'uni2_syn_payload_zero': args.uni2_syn_payload_zero,
                'references': ['https://www.rfc-editor.org/rfc/rfc9293.html#section-3.4',
                               'https://www.rfc-editor.org/rfc/rfc5681.html#section-2']}
    (args.out_dir / 'classification_manifest.json').write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'packets': sum(counts.values()), 'fragments': len(engine.sessions),
                      'elapsed_s': round(time.monotonic() - start, 1), 'cohort_checks': len(checks)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
