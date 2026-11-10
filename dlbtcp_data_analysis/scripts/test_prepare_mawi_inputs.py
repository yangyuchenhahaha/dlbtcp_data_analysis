#!/usr/bin/env python3
"""Semantic recovery fixture: exact tuples, backwards time, validity, stable ties."""
import gzip
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


def packet(ts, src, dst, sport, dport, flags=16, thl=20, opts=0,
           proto=6, seq=1, plen=40):
    return '\t'.join(map(str, [ts, proto, src, dst, sport, dport, 60, plen,
        flags, seq, 0, 2048, thl, 96, 100, opts])) + '\n'


class PrepareMawiTest(unittest.TestCase):
    def test_exact_counts_backwards_invalid_header_and_stable_sort(self):
        with tempfile.TemporaryDirectory(prefix='mawi-prepare-test-') as temp:
            base = Path(temp)
            source = base / 'fixture.tsv'
            a, b = '192.0.2.1', '198.51.100.2'
            source.write_text(''.join([
                packet('1.000000', a, b, 10, 20, seq=101),
                packet('0.500000', b, a, 20, 10, seq=102),
                packet('1.000000', a, b, 10, 20, seq=103),
                packet('2.000000', a, b, -1, -1, flags=-1, thl=-1, opts=1, plen=-1),
                packet('2.100000', a, b, 10, 20, proto=17, thl=8, seq=0, plen=52)]))
            subprocess.run(['python3', str(Path(__file__).with_name('prepare_mawi_inputs.py')),
                str(source), '--data-dir', str(base / 'data'), '--report-dir', str(base / 'report'),
                '--endpoints', a, '--sort-memory', '16M', '--sort-parallel', '1'], check=True)
            stats = json.loads((base / 'report/phase1_mawi_bidir.json').read_text())
            self.assertEqual((stats['rows_total'], stats['tcp_pkts'], stats['udp_pkts']), (5, 4, 1))
            self.assertEqual((stats['tcp_connections'], stats['tcp_connections_both_dirs'],
                              stats['pkts_in_both_dir_conns']), (2, 1, 3))
            self.assertEqual(stats['capture_order_timestamps']['tcp']['timestamp_backwards'], 1)
            self.assertEqual(stats['capture_order_timestamps']['tcp']['max_backward_ns'], 500000000)
            self.assertEqual(stats['tcp_options_truncated_known_tcp_header'], 0)
            self.assertEqual(stats['tcp_options_truncated_unknown_tcp_header'], 1)
            self.assertEqual((stats['tcp_negative_flags'], stats['tcp_invalid_thl'],
                              stats['tcp_unknown_ports_packets'], stats['tcp_invalid_fixed_header_packets']), (1, 1, 1, 1))
            self.assertEqual(stats['tcp_field_validity']['flags']['valid_rows'], 3)
            self.assertEqual(stats['tcp_field_validity']['flags']['total_rows'], 4)
            subset = (base / 'data/mawi_endpoints.tsv').read_text()
            rows = [line.split('\t') for line in subset.splitlines()]
            self.assertEqual([r[0] for r in rows], ['0.500000', '1.000000', '1.000000', '2.000000'])
            self.assertEqual([r[9] for r in rows[1:3]], ['101', '103'])
            with gzip.open(base / 'data/mawi_tcp_sorted.tsv.gz', 'rt') as handle:
                self.assertEqual(handle.read(), subset)
            self.assertFalse(json.loads((base / 'report/mawi_prepared_inputs.json').read_text())['phase2_or_phase3_analysis_run'])


if __name__ == '__main__':
    unittest.main()
