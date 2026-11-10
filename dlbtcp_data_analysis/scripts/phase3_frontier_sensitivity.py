#!/usr/bin/env python3
"""Explain persistent historical gaps using the already selected timelines.

This is a local observation diagnostic, not a new TCP/fast-path classification.
Read only the 145k representative packets, never reinitialize their TCP state.
"""
import argparse
from collections import Counter, defaultdict
import csv
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(4 * 1024 * 1024):
            h.update(block)
    return h.hexdigest()


def analyze(rows):
    previous = {}
    counts = defaultdict(Counter)
    for row in rows:
        c = counts[row['example']]
        c['packets'] += 1
        key = row['example'], row['session_id'], row['direction']
        old_high = previous.get(key)
        if int(row['payload_bytes']) > 0 and row['seq_unwrapped'] != '':
            c['payload_packets'] += 1
            lo = int(row['seq_unwrapped']) + int(bool(int(row['flags']) & 2))
            c['strict_in_order_packets'] += row['seq_event'] == 'IN_ORDER'
            c['ahead_gap_packets'] += row['seq_event'] == 'AHEAD_GAP'
            if old_high is None:
                c['unknown_previous_highwater_payload_packets'] += 1
            elif lo == old_high:
                c['adjacent_highwater_packets'] += 1
                if row['seq_event'] == 'AHEAD_GAP':
                    assert row['seq_frontier'] and int(row['seq_frontier']) < old_high
                    c['adjacent_after_historical_gap_packets'] += 1
            elif lo > old_high:
                c['new_forward_gap_packets'] += 1
        if row['seq_highwater'] != '':
            previous[key] = int(row['seq_highwater'])
    fields = ['packets', 'payload_packets', 'strict_in_order_packets', 'ahead_gap_packets',
              'adjacent_highwater_packets', 'adjacent_after_historical_gap_packets',
              'new_forward_gap_packets', 'unknown_previous_highwater_payload_packets']
    result = []
    for example, c in sorted(counts.items()):
        r = dict(example=example, **{field: c[field] for field in fields})
        for field in ['strict_in_order_packets', 'adjacent_highwater_packets', 'new_forward_gap_packets']:
            r[field.replace('_packets', '_fraction')] = c[field] / c['payload_packets'] if c['payload_packets'] else None
        assert c['adjacent_after_historical_gap_packets'] <= c['ahead_gap_packets']
        result.append(r)
    return result


def self_test():
    values = [(100, 0, 2, 'NA', 101, 101), (201, 100, 16, 'AHEAD_GAP', 301, 101),
              (301, 100, 16, 'AHEAD_GAP', 401, 101), (101, 100, 16, 'GAP_FILL', 401, 401),
              (401, 50, 16, 'IN_ORDER', 451, 451), (201, 100, 16, 'DUP_FULL', 451, 451)]
    rows = [dict(example='fixture', session_id='s1', direction='TX', seq_unwrapped=str(seq),
                 payload_bytes=str(length), flags=str(flags), seq_event=event,
                 seq_highwater=str(high), seq_frontier=str(frontier))
            for seq, length, flags, event, high, frontier in values]
    result = analyze(rows)[0]
    assert result['payload_packets'] == 5
    assert result['strict_in_order_packets'] == 1
    assert result['adjacent_highwater_packets'] == 2
    assert result['adjacent_after_historical_gap_packets'] == 1
    assert result['new_forward_gap_packets'] == 1
    print('frontier sensitivity fixture passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', type=Path, default=ROOT / 'report/phase3_mawi')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    path = args.input_dir / 'timeline_packets.csv.gz'
    validation = json.loads((args.input_dir / 'validation.json').read_text())
    source_hash = digest(path)
    if not validation['all_checks_passed'] or validation['input_sha256'].get(str(path.resolve())) != source_hash:
        raise ValueError('timeline must match passed independent validation')
    with gzip.open(path, 'rt', newline='') as source:
        rows = analyze(csv.DictReader(source))
    examples = json.loads((args.input_dir / 'timeline_examples.json').read_text())
    expected = {r['example']: int(r['observed_packets']) for r in examples}
    assert {r['example']: r['packets'] for r in rows} == expected
    with (args.input_dir / 'frontier_sensitivity.csv').open('w', newline='') as target:
        writer = csv.DictWriter(target, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    meta = {'source_timeline_sha256': source_hash, 'all_checks_passed': True,
            'fast_path_status': 'deferred_by_user', 'rows': rows,
            'definition': 'payload start equals previous same-session same-direction observed highwater; strict frontier remains separate',
            'scope': 'three preselected individual connections only; no extrapolation to all endpoint traffic',
            'unknown': 'first payload without an earlier timeline-row highwater is left unclassified for this diagnostic'}
    (args.input_dir / 'frontier_sensitivity.json').write_text(json.dumps(meta, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps(rows, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
