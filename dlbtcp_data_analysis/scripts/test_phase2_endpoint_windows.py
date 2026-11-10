#!/usr/bin/env python3
"""Small semantic fixture for streaming counts, stable RR, and hotspot gaps."""
import csv
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('phase2_windows', Path(__file__).with_name('phase2_endpoint_windows.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def read_csv(path):
    with gzip.open(path, 'rt', newline='') as handle:
        return list(csv.DictReader(handle))


def packet(ts, port=10, reverse=False):
    src, dst, sport, dport = ('198.51.100.2', '192.0.2.1', 20, port) if reverse else ('192.0.2.1', '198.51.100.2', port, 20)
    return '\t'.join(map(str, [ts, 6, src, dst, sport, dport, 60, 40, 16,
                              1000, 1000, 2048, 20, 96, 100, 0])) + '\n'


class EndpointWindowsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.trace = self.root / 'fixture.tsv'
        lines = []
        for second, port in [(0, 10), (1, 10), (3, 10), (4, 11)]:
            lines.extend(packet(f'{second}.100000', port) for _ in range(20))
            lines.extend(packet(f'{second}.100000', port, True) for _ in range(10))
        lines.extend(packet('5.100000', 12) for _ in range(10))
        self.trace.write_text(''.join(lines))

    def tearDown(self):
        self.temp.cleanup()

    def run_fixture(self, path=None, directory='out'):
        return module.main([str(path or self.trace), '--endpoints', '192.0.2.1',
            '--windows', '1,2', '--out-dir', str(self.root / directory),
            '--span-start', '0', '--span-end', '5.999999', '--core-counts', '2,4'])

    def test_packet_bytes_and_core_conservation_and_rr_stability(self):
        summary = self.run_fixture()
        windows = summary['endpoints']['192.0.2.1']['windows']
        for width, stats in windows.items():
            self.assertEqual(stats['packets'], 130)
            self.assertEqual(stats['tx_packets'], 90)
            self.assertEqual(stats['rx_packets'], 40)
            self.assertEqual(stats['wire_bytes'], 13000)
            self.assertEqual(stats['payload_bytes'], 5200)
            rows = read_csv(stats['csv'])
            self.assertEqual(sum(int(row['packets']) for row in rows), 130)
            for row in rows:
                self.assertEqual(int(row['tx_packets']) + int(row['rx_packets']), int(row['packets']))
                self.assertEqual(int(row['tx_wire_bytes']) + int(row['rx_wire_bytes']), int(row['wire_bytes']))
                for policy in ('hash', 'rr', 'lpt'):
                    for k in (2, 4):
                        loads = json.loads(row[f'{policy}_{k}_loads'])
                        self.assertEqual(sum(loads), int(row['packets']))
                        self.assertGreaterEqual(max(loads), int(row['top1_packets']))
        rows = read_csv(windows['1s']['csv'])
        self.assertEqual(len(rows), 6)
        self.assertEqual(int(rows[2]['packets']), 0)
        self.assertEqual(json.loads(rows[0]['rr_2_loads']), [30, 0])
        self.assertEqual(json.loads(rows[1]['rr_2_loads']), [30, 0])
        self.assertEqual(json.loads(rows[3]['rr_2_loads']), [30, 0])
        self.assertEqual(json.loads(rows[4]['rr_2_loads']), [0, 30])
        self.assertEqual(json.loads(rows[5]['rr_2_loads']), [10, 0])

    def test_hotspots_require_load_and_same_connection_and_break_on_empty(self):
        summary = self.run_fixture()
        stats = summary['endpoints']['192.0.2.1']['windows']['1s']
        self.assertEqual(stats['hotspot_effective_packet_threshold'], 30)
        self.assertEqual(stats['hotspot_windows'], 4)
        self.assertEqual(stats['hotspot_segments'], 3)
        self.assertEqual(stats['longest_hotspot_segment_windows'], 2)
        segments = [row for row in read_csv(summary['hotspot_segments_csv']) if float(row['window_s']) == 1]
        self.assertEqual([(row['start_ts'], row['end_ts'], row['windows']) for row in segments],
                         [('0.000000000', '2.000000000', '2'),
                          ('3.000000000', '4.000000000', '1'),
                          ('4.000000000', '5.000000000', '1')])
        self.assertEqual(segments[0]['connection'], segments[1]['connection'])
        self.assertNotEqual(segments[1]['connection'], segments[2]['connection'])
        rows = read_csv(stats['csv'])
        self.assertEqual(int(rows[5]['is_concentrated']), 1)
        self.assertEqual(int(rows[5]['is_hotspot']), 0)

    def test_gzip_input_matches_plain_and_hash_is_deterministic(self):
        plain = self.run_fixture()
        compressed = self.root / 'fixture.tsv.gz'
        with gzip.open(compressed, 'wt') as handle:
            handle.write(self.trace.read_text())
        zipped = self.run_fixture(compressed, 'out_gzip')
        a = read_csv(plain['endpoints']['192.0.2.1']['windows']['1s']['csv'])
        b = read_csv(zipped['endpoints']['192.0.2.1']['windows']['1s']['csv'])
        self.assertEqual(a, b)

    def test_unsorted_input_is_rejected(self):
        self.trace.write_text(packet('1.1') + packet('0.1'))
        with self.assertRaisesRegex(ValueError, 'timestamps are not sorted'):
            self.run_fixture()

    def test_multiple_hash_seeds_conserve_packets_and_match_summary_bounds(self):
        sizes = [11, 9, 7, 5, 3, 2]
        fixture = self.root / 'many_connections.tsv'
        fixture.write_text(''.join(packet('0.250000', 100 + i)
                                  for i, size in enumerate(sizes) for _ in range(size)))
        summary = module.main([str(fixture), '--endpoints', '192.0.2.1',
            '--windows', '1', '--out-dir', str(self.root / 'many_out'),
            '--span-start', '0.1', '--span-end', '0.9',
            '--core-counts', '2,4,8', '--hash-repeats', '16'])
        row, = read_csv(summary['endpoints']['192.0.2.1']['windows']['1s']['csv'])
        ranked = [((100 + i, '198.51.100.2', 20), size) for i, size in enumerate(sizes)]
        assignments = {conn: module.connection_assignment('192.0.2.1', conn, i, 16)
                       for i, (conn, _) in enumerate(ranked)}
        for conn, assignment in assignments.items():
            original = int.from_bytes(hashlib.blake2b(
                module.conn_text('192.0.2.1', conn).encode(), digest_size=8).digest(), 'big')
            self.assertEqual(assignment[1], original)
            self.assertEqual(assignment[2][0], original)
            self.assertEqual(assignment, module.connection_assignment(
                '192.0.2.1', conn, assignment[0], 16))
        for k in (2, 4, 8):
            vectors = list(module.repeated_hash_allocations(ranked, assignments, k, 16))
            self.assertEqual(len(vectors), 16)
            self.assertEqual(vectors[0], json.loads(row[f'hash_{k}_loads']))
            bound = max(1, k * max(sizes) / sum(sizes))
            imbalances = []
            for vector in vectors:
                self.assertEqual(sum(vector), sum(sizes))
                self.assertGreaterEqual(max(vector), max(sizes))
                imbalance = max(vector) * k / sum(sizes)
                self.assertGreaterEqual(imbalance, bound)
                self.assertLessEqual(imbalance, k)
                imbalances.append(imbalance)
            ordered = sorted(imbalances)
            expected = {'min': ordered[0], 'p50': ordered[7],
                        'p90': ordered[14], 'max': ordered[-1]}
            for metric, value in expected.items():
                self.assertAlmostEqual(float(row[f'hash_{k}_repeat_imbalance_{metric}']), value)
            self.assertLessEqual(expected['min'], float(row[f'hash_{k}_imbalance']))
            self.assertGreaterEqual(expected['max'], float(row[f'hash_{k}_imbalance']))
        self.assertLess(float(row['hash_2_repeat_imbalance_min']), float(row['hash_2_repeat_imbalance_max']))
        self.assertEqual(json.loads(row['top5_connection_packets']), sizes[:5])
        self.assertEqual(json.loads(row['top5_connections']),
                         [module.conn_text('192.0.2.1', conn) for conn, _ in ranked[:5]])
        self.assertEqual(sum(json.loads(row['top5_connection_packets'])), int(row['top5_packets']))
        self.assertEqual(float(row['pps']), 37)
        self.assertEqual(float(row['wire_bytes_per_s']), 3700)
        self.assertEqual(float(row['wire_bits_per_s']), 29600)
        self.assertEqual(float(row['tx_pps']), 37)
        self.assertEqual(float(row['rx_pps']), 0)
        self.assertEqual(float(row['observed_duration_s']), .8)
        self.assertEqual(float(row['pps_observed_partial']), 46.25)
        self.assertEqual(int(row['partial_boundary_window']), 1)


if __name__ == '__main__':
    unittest.main()
