#!/usr/bin/env python3
"""Semantic fixtures for passive TCP observations, without fast-path inference."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phase3_tcp_events as events


ENDPOINT = "192.0.2.10"
PEER = "198.51.100.20"
MOD32 = 1 << 32
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


def packet(ts, seq=1000, plen=0, flags=ACK, ack=0, *, reverse=False,
           sport=12345, dport=443, **kwargs):
    src, dst = (PEER, ENDPOINT) if reverse else (ENDPOINT, PEER)
    if reverse:
        sport, dport = dport, sport
    return events.Packet(ts=ts, src=src, dst=dst, sport=sport, dport=dport,
                         plen=plen, flags=flags, seq=seq, ack=ack, **kwargs)


def reasons(row):
    return set(filter(None, row["uncertainty"].split(";")))


class SequenceSetTest(unittest.TestCase):
    def test_disjoint_intervals_do_not_cover_the_hole(self):
        seen = events.SequenceSet()
        self.assertEqual(seen.add(100, 200), 0)
        self.assertEqual(seen.add(300, 400), 0)
        self.assertFalse(seen.covers(150, 350))
        self.assertEqual(seen.overlap(150, 350), 100)
        self.assertEqual(seen.contiguous_from(100), 200)
        self.assertEqual(seen.contiguous_from(250), 250)

    def test_bridging_intervals_counts_overlap_once_and_advances_frontier(self):
        seen = events.SequenceSet()
        seen.add(100, 200)
        seen.add(300, 400)
        self.assertEqual(seen.add(150, 350), 100)
        self.assertTrue(seen.covers(100, 400))
        self.assertEqual(seen.overlap(50, 450), 300)
        self.assertEqual(seen.contiguous_from(100), 400)
        self.assertEqual(seen.contiguous_from(175), 400)

    def test_half_open_adjacency_and_repeated_insertions(self):
        seen = events.SequenceSet()
        seen.add(10, 20)
        self.assertEqual(seen.overlap(20, 30), 0)
        self.assertEqual(seen.add(20, 30), 0)
        self.assertEqual(seen.contiguous_from(10), 30)
        self.assertEqual(seen.add(12, 28), 16)
        self.assertEqual(seen.overlap(10, 30), 20)
        self.assertFalse(seen.covers(9, 30))


class UnwrapTest(unittest.TestCase):
    def test_initial_and_both_directions_across_wrap(self):
        self.assertEqual(events.unwrap32(0, None), (0, False))
        self.assertEqual(events.unwrap32(3, MOD32 - 2), (MOD32 + 3, False))
        self.assertEqual(events.unwrap32(MOD32 - 2, MOD32 + 3),
                         (MOD32 - 2, False))
        self.assertEqual(events.unwrap32(15, 2 * MOD32 + 10),
                         (2 * MOD32 + 15, False))

    def test_exact_half_space_is_explicitly_ambiguous(self):
        self.assertTrue(events.unwrap32(1 << 31, 0)[1])
        self.assertTrue(events.unwrap32(0, 1 << 31)[1])


class ParsingAndShapeTest(unittest.TestCase):
    def test_parse_raw_sequence_and_record_length_fields(self):
        line = ("1.250000\t6\t192.0.2.10\t198.51.100.20\t12345\t443"
                "\t140\t100\t24\t4294967295\t0\t4096\t40\t96\t154\t1\n")
        p = events.parse_packet(line)
        self.assertEqual((p.ts, p.src, p.dst, p.sport, p.dport),
                         (1.25, ENDPOINT, PEER, 12345, 443))
        self.assertEqual((p.plen, p.flags, p.seq, p.ack, p.win),
                         (100, 24, MOD32 - 1, 0, 4096))
        self.assertEqual((p.thl, p.caplen, p.wirelen, p.opts_trunc),
                         (40, 96, 154, 1))

    def test_syn_payload_is_retained_unless_uni2_option_is_requested(self):
        line = ("1.0\t6\t192.0.2.10\t198.51.100.20\t12345\t443"
                "\t60\t20\t2\t100\t0\t4096\t20\t74\t74\t0\n")
        self.assertEqual(events.parse_packet(line).plen, 20)
        self.assertEqual(events.parse_packet(line, syn_payload_zero=True).plen, 0)

    def test_packet_shapes_and_fin_with_payload(self):
        cases = [(SYN, 0, "SYN"), (SYN | ACK, 0, "SYNACK"),
                 (FIN | ACK, 20, "FIN"), (RST | ACK, 0, "RST"),
                 (ACK | 8, 20, "DATA"), (ACK, 0, "PURE_ACK"),
                 (0, 0, "OTHER"), (-1, -1, "INVALID")]
        for flags, plen, expected in cases:
            with self.subTest(flags=flags, plen=plen):
                self.assertEqual(events.shape(flags, plen), expected)


class ClassifierTest(unittest.TestCase):
    def setUp(self):
        self.classifier = events.TCPClassifier()

    def classify(self, p, endpoint=ENDPOINT):
        return self.classifier.classify(endpoint, p)

    def handshake(self, client_seq=1000, server_seq=9000, base=1.0):
        rows = [
            self.classify(packet(base, seq=client_seq, flags=SYN)),
            self.classify(packet(base + .01, seq=server_seq,
                                 ack=(client_seq + 1) % MOD32,
                                 flags=SYN | ACK, reverse=True)),
            self.classify(packet(base + .02, seq=(client_seq + 1) % MOD32,
                                 ack=(server_seq + 1) % MOD32, flags=ACK)),
        ]
        return rows

    def test_observed_handshake_then_contiguous_payload(self):
        rows = self.handshake()
        self.assertEqual([int(r["handshake_complete"]) for r in rows], [0, 0, 1])
        self.assertEqual(len(set(r["session_id"] for r in rows)), 1)
        row = self.classify(packet(1.03, seq=1001, plen=100, ack=9001))
        self.assertEqual(row["seq_event"], "IN_ORDER")
        self.assertNotIn("NO_INITIAL_SYN", reasons(row))
        self.assertNotIn("HANDSHAKE_NOT_OBSERVED", reasons(row))

    def test_wrong_final_ack_does_not_complete_handshake(self):
        self.classify(packet(1.0, seq=1000, flags=SYN))
        self.classify(packet(1.01, seq=9000, ack=1001,
                             flags=SYN | ACK, reverse=True))
        wrong = self.classify(packet(1.02, seq=1001, ack=9000))
        self.assertEqual(int(wrong["handshake_complete"]), 0)
        self.assertIn("HANDSHAKE_NOT_OBSERVED", reasons(wrong))

    def test_final_ack_with_wrong_sequence_does_not_complete_handshake(self):
        self.classify(packet(1.0, seq=1000, flags=SYN))
        self.classify(packet(1.01, seq=9000, ack=1001,
                             flags=SYN | ACK, reverse=True))
        wrong = self.classify(packet(1.02, seq=5000, ack=9001))
        self.assertEqual(int(wrong["handshake_complete"]), 0)

    def test_reset_ack_after_synack_does_not_complete_handshake(self):
        self.classify(packet(1.0, seq=1000, flags=SYN))
        self.classify(packet(1.01, seq=9000, ack=1001,
                             flags=SYN | ACK, reverse=True))
        reset = self.classify(packet(1.02, seq=1001, ack=9001, flags=RST | ACK))
        self.assertEqual(reset["packet_type"], "RST")
        self.assertEqual(int(reset["handshake_complete"]), 0)

    def test_delayed_final_ack_after_reset_cannot_revive_handshake_in_either_view(self):
        for endpoint in (ENDPOINT, PEER):
            with self.subTest(endpoint=endpoint):
                engine = events.TCPClassifier()
                observed = [packet(1.0, seq=1000, flags=SYN),
                            packet(1.01, seq=9000, ack=1001, flags=SYN | ACK,
                                   reverse=True),
                            packet(1.02, seq=1001, flags=RST),
                            packet(1.03, seq=1001, ack=9001)]
                rows = [engine.classify(endpoint, p) for p in observed]
                self.assertEqual([int(r["handshake_complete"]) for r in rows], [0, 0, 0, 0])
                self.assertIn("AFTER_OBSERVED_CLOSE", reasons(rows[-1]))
                self.assertIn("HANDSHAKE_NOT_OBSERVED", reasons(rows[-1]))

    def test_capture_beginning_at_synack_is_not_a_complete_handshake(self):
        self.classify(packet(1.0, seq=9000, ack=1001,
                             flags=SYN | ACK, reverse=True))
        response = self.classify(packet(1.01, seq=1001, ack=9001))
        data = self.classify(packet(1.02, seq=9001, plen=100,
                                    ack=1001, reverse=True))
        self.assertEqual(int(response["handshake_complete"]), 0)
        self.assertEqual(int(data["handshake_complete"]), 0)
        self.assertIn("HANDSHAKE_NOT_OBSERVED", reasons(data))

    def test_midstream_first_payload_is_baseline_and_context_stays_uncertain(self):
        first = self.classify(packet(1.0, seq=100, plen=100))
        second = self.classify(packet(1.01, seq=200, plen=100))
        self.assertEqual(first["seq_event"], "BASELINE")
        self.assertEqual(second["seq_event"], "IN_ORDER")
        self.assertIn("NO_INITIAL_SYN", reasons(first))
        self.assertIn("NO_INITIAL_SYN", reasons(second))
        self.assertEqual(int(second["handshake_complete"]), 0)

    def test_forward_gap_keeps_frontier_until_missing_range_is_observed(self):
        self.classify(packet(1.0, seq=100, plen=100))
        ahead = self.classify(packet(1.01, seq=300, plen=100))
        beyond = self.classify(packet(1.02, seq=400, plen=100))
        filled = self.classify(packet(1.03, seq=200, plen=100))
        next_row = self.classify(packet(1.04, seq=500, plen=100))
        self.assertEqual(ahead["seq_event"], "AHEAD_GAP")
        self.assertEqual(beyond["seq_event"], "AHEAD_GAP")
        self.assertIn("SEQ_GAP_UNRESOLVED", reasons(beyond))
        self.assertEqual(filled["seq_event"], "GAP_FILL")
        self.assertEqual(next_row["seq_event"], "IN_ORDER")
        self.assertNotIn("SEQ_GAP_UNRESOLVED", reasons(next_row))

    def test_full_and_partial_seen_ranges_are_not_confirmed_retransmissions(self):
        self.classify(packet(1.0, seq=100, plen=100))
        full = self.classify(packet(1.01, seq=120, plen=40))
        partial = self.classify(packet(1.02, seq=180, plen=100))
        next_row = self.classify(packet(1.03, seq=280, plen=20))
        self.assertEqual(full["seq_event"], "DUP_FULL")
        self.assertEqual(partial["seq_event"], "OVERLAP_PARTIAL")
        self.assertEqual(next_row["seq_event"], "IN_ORDER")
        for row in (full, partial):
            self.assertIn("REPEATED_RANGE_CAUSE_UNKNOWN", reasons(row))

    def test_range_spanning_unseen_hole_is_partial_not_full_duplicate(self):
        self.classify(packet(1.0, seq=100, plen=100))
        self.classify(packet(1.01, seq=300, plen=100))
        bridge = self.classify(packet(1.02, seq=150, plen=200))
        after = self.classify(packet(1.03, seq=400, plen=100))
        self.assertEqual(bridge["seq_event"], "OVERLAP_PARTIAL")
        self.assertEqual(after["seq_event"], "IN_ORDER")

    def test_unseen_prefix_before_midstream_anchor_is_not_a_duplicate(self):
        self.classify(packet(1.0, seq=100, plen=100))
        prefix = self.classify(packet(1.01, seq=50, plen=50))
        self.assertEqual(prefix["seq_event"], "PREFIX_UNOBSERVED")
        self.assertIn("NO_INITIAL_SYN", reasons(prefix))

    def test_payload_crosses_zero_without_becoming_backward_or_duplicate(self):
        self.classify(packet(1.0, seq=MOD32 - 4, plen=4))
        row = self.classify(packet(1.01, seq=0, plen=10))
        self.assertEqual(row["seq_event"], "IN_ORDER")
        self.assertNotIn("SEQ_ROUND_AMBIGUOUS", reasons(row))

    def test_half_space_sequence_distance_is_not_silently_decided(self):
        self.classify(packet(1.0, seq=0, plen=1))
        row = self.classify(packet(1.01, seq=(1 << 31) + 1, plen=1))
        self.assertIn("SEQ_ROUND_AMBIGUOUS", reasons(row))

    def test_syn_payload_and_syn_wrap_both_consume_correct_sequence_space(self):
        self.classify(packet(1.0, seq=MOD32 - 1, plen=20, flags=SYN))
        row = self.classify(packet(1.01, seq=20, plen=10))
        self.assertEqual(row["seq_event"], "IN_ORDER")

    def test_syn_data_may_be_rejected_partly_accepted_or_fully_accepted(self):
        for acknowledged in (1001, 1011, 1021):
            with self.subTest(acknowledged=acknowledged):
                engine = events.TCPClassifier()
                engine.classify(ENDPOINT, packet(1.0, seq=1000, plen=20, flags=SYN))
                engine.classify(ENDPOINT, packet(1.01, seq=9000, ack=acknowledged,
                                                 flags=SYN | ACK, reverse=True))
                final = engine.classify(ENDPOINT, packet(1.02, seq=acknowledged,
                                                         ack=9001))
                self.assertEqual(int(final["handshake_complete"]), 1)

    def test_synack_payload_can_also_be_declined_in_final_ack(self):
        self.classify(packet(1.0, seq=1000, flags=SYN))
        self.classify(packet(1.01, seq=9000, plen=20, ack=1001,
                             flags=SYN | ACK, reverse=True))
        row = self.classify(packet(1.02, seq=1001, ack=9001))
        self.assertEqual(int(row["handshake_complete"]), 1)

    def test_fin_payload_is_classified_and_fin_is_visible_to_reverse_ack(self):
        self.handshake()
        self.classify(packet(1.03, seq=1001, plen=100, ack=9001))
        fin = self.classify(packet(1.04, seq=1101, plen=10,
                                   flags=FIN | ACK, ack=9001))
        acknowledged = self.classify(packet(1.05, seq=9001, ack=1112,
                                            reverse=True))
        self.assertEqual(fin["packet_type"], "FIN")
        self.assertEqual(fin["seq_event"], "IN_ORDER")
        self.assertNotIn("ACK_UNOBSERVED", reasons(acknowledged))

    def test_pure_ack_does_not_advance_own_payload_frontier(self):
        self.classify(packet(1.0, seq=100, plen=10))
        self.classify(packet(1.01, seq=110, ack=500))
        row = self.classify(packet(1.02, seq=110, plen=10, ack=500))
        self.assertEqual(row["seq_event"], "IN_ORDER")

    def test_syn_retransmission_and_synack_do_not_start_new_sessions(self):
        syn = self.classify(packet(1.0, seq=1000, flags=SYN))
        retry = self.classify(packet(1.01, seq=1000, flags=SYN))
        synack = self.classify(packet(1.02, seq=9000, ack=1001,
                                      flags=SYN | ACK, reverse=True))
        synack_retry = self.classify(packet(1.03, seq=9000, ack=1001,
                                            flags=SYN | ACK, reverse=True))
        self.assertEqual(len({r["session_id"] for r in
                              (syn, retry, synack, synack_retry)}), 1)
        self.assertEqual(len(self.classifier.sessions), 1)

    def test_new_initial_sequence_reuses_tuple_with_fresh_direction_state(self):
        old = self.handshake()[0]
        self.classify(packet(1.03, seq=1001, plen=100, ack=9001))
        new = self.classify(packet(2.0, seq=4000, flags=SYN))
        data = self.classify(packet(2.01, seq=4001, plen=10))
        self.assertNotEqual(old["session_id"], new["session_id"])
        self.assertEqual(new["session_id"], data["session_id"])
        self.assertIn("TUPLE_REUSED", reasons(new))
        self.assertEqual(data["seq_event"], "IN_ORDER")
        self.assertEqual(int(data["handshake_complete"]), 0)
        self.assertEqual(len(self.classifier.sessions), 2)

    def test_same_isn_syn_after_completed_handshake_is_only_a_reuse_hint(self):
        old = self.handshake()[0]
        observed_syn = self.classify(packet(2.0, seq=1000, flags=SYN))
        self.assertNotEqual(old["session_id"], observed_syn["session_id"])
        self.assertIn("TUPLE_REUSED", reasons(observed_syn))
        self.assertEqual(int(observed_syn["handshake_complete"]), 0)

    def test_first_ack_then_repeat_window_change_backward_and_advance(self):
        inputs = [(100, 4096), (100, 4096), (100, 8192),
                  (90, 8192), (110, 8192)]
        rows = [self.classify(packet(1 + i * .01, seq=500,
                                    ack=ack, win=win))
                for i, (ack, win) in enumerate(inputs)]
        self.assertEqual([r["ack_event"] for r in rows],
                         ["BASELINE", "REPEAT", "WINDOW_UPDATE", "BACKWARD", "ADVANCE"])

    def test_ack_zero_is_valid_after_wrap_and_ack_flag_controls_interpretation(self):
        self.classify(packet(1.0, ack=MOD32 - 1))
        zero = self.classify(packet(1.01, ack=0))
        ignored = self.classify(packet(1.02, ack=200, flags=0))
        after = self.classify(packet(1.03, ack=1))
        self.assertEqual(zero["ack_event"], "ADVANCE")
        self.assertEqual(ignored["ack_event"], "NA")
        self.assertEqual(after["ack_event"], "ADVANCE")

    def test_ack_progress_uses_own_history_when_observed_peer_data_is_stale(self):
        self.classify(packet(1.0, seq=100, plen=1))
        baseline = self.classify(packet(1.01, seq=900, ack=101, reverse=True))
        advance = self.classify(packet(1.02, seq=900, ack=2_000_000_000,
                                       reverse=True))
        across_half = self.classify(packet(1.03, seq=900, ack=3_000_000_000,
                                           reverse=True))
        self.assertEqual(baseline["ack_event"], "BASELINE")
        self.assertEqual(advance["ack_event"], "ADVANCE")
        self.assertEqual(across_half["ack_event"], "ADVANCE")
        self.assertIn("ACK_UNOBSERVED", reasons(across_half))

    def test_data_piggyback_same_ack_is_same_not_pure_ack_repeat(self):
        self.classify(packet(1.0, seq=100, plen=10, ack=500))
        row = self.classify(packet(1.01, seq=110, plen=10, ack=500))
        self.assertEqual(row["packet_type"], "DATA")
        self.assertEqual(row["ack_event"], "SAME")

    def test_ack_coverage_uses_opposite_direction_and_reveals_unseen_data(self):
        self.handshake()
        self.classify(packet(1.03, seq=1001, plen=100, ack=9001))
        known = self.classify(packet(1.04, seq=9001, ack=1101, reverse=True))
        unknown = self.classify(packet(1.05, seq=9001, ack=1201, reverse=True))
        self.assertNotIn("ACK_UNOBSERVED", reasons(known))
        self.assertIn("ACK_UNOBSERVED", reasons(unknown))

    def test_ack_over_a_hole_is_unobserved_even_below_highest_seen_end(self):
        self.handshake()
        self.classify(packet(1.03, seq=1001, plen=100, ack=9001))
        self.classify(packet(1.04, seq=1201, plen=100, ack=9001))
        row = self.classify(packet(1.05, seq=9001, ack=1301, reverse=True))
        self.assertIn("ACK_UNOBSERVED", reasons(row))

    def test_first_ack_over_known_hole_is_also_unobserved(self):
        self.classify(packet(1.0, seq=100, plen=100))
        self.classify(packet(1.01, seq=300, plen=100))
        first_ack = self.classify(packet(1.02, seq=900, ack=400, reverse=True))
        self.assertEqual(first_ack["ack_event"], "BASELINE")
        self.assertIn("ACK_UNOBSERVED", reasons(first_ack))

    def test_data_and_ack_state_are_independent_between_directions(self):
        left = self.classify(packet(1.0, seq=100, plen=10, ack=900))
        right = self.classify(packet(1.01, seq=900, plen=20, ack=110, reverse=True))
        left2 = self.classify(packet(1.02, seq=110, plen=10, ack=920))
        right2 = self.classify(packet(1.03, seq=920, plen=20, ack=120, reverse=True))
        self.assertEqual([r["seq_event"] for r in (left, right, left2, right2)],
                         ["BASELINE", "BASELINE", "IN_ORDER", "IN_ORDER"])
        self.assertEqual([r["ack_event"] for r in (left, right, left2, right2)],
                         ["BASELINE", "BASELINE", "ADVANCE", "ADVANCE"])
        self.assertEqual(left["session_id"], right["session_id"])

    def test_tuple_and_endpoint_views_have_isolated_state(self):
        first = self.classify(packet(1.0, seq=100, plen=10))
        other_port = self.classify(packet(1.01, seq=100, plen=10, sport=12346))
        other_view = self.classify(packet(1.02, seq=100, plen=10), endpoint=PEER)
        self.assertEqual(other_port["seq_event"], "BASELINE")
        self.assertEqual(other_view["seq_event"], "BASELINE")
        self.assertEqual(len({r["session_id"] for r in (first, other_port, other_view)}), 3)

    def test_invalid_header_does_not_move_payload_or_ack_state(self):
        self.classify(packet(1.0, seq=100, plen=100, ack=500))
        invalid = self.classify(packet(1.01, seq=5000, plen=-1, flags=-1,
                                       ack=9000, thl=-1, opts_trunc=1))
        after = self.classify(packet(1.02, seq=200, plen=10, ack=510))
        self.assertEqual(invalid["packet_type"], "INVALID")
        self.assertEqual(after["seq_event"], "IN_ORDER")
        self.assertEqual(after["ack_event"], "ADVANCE")

    def test_out_of_range_raw_fields_and_invalid_syn_controls_do_not_update_state(self):
        cases = [dict(win=65536), dict(flags=256), dict(flags=SYN | FIN),
                 dict(flags=SYN | RST), dict(seq=MOD32), dict(thl=22)]
        for values in cases:
            with self.subTest(values=values):
                engine = events.TCPClassifier()
                engine.classify(ENDPOINT, packet(1.0, seq=100, plen=100, ack=500))
                attributes = dict(seq=5000, plen=100, ack=9000)
                attributes.update(values)
                invalid = engine.classify(ENDPOINT, packet(1.01, **attributes))
                after = engine.classify(ENDPOINT, packet(1.02, seq=200,
                                                         plen=10, ack=510))
                self.assertEqual(invalid["packet_type"], "INVALID")
                self.assertEqual(after["seq_event"], "IN_ORDER")
                self.assertEqual(after["ack_event"], "ADVANCE")

    def test_options_truncation_does_not_invalidate_available_fixed_fields(self):
        self.classify(packet(1.0, seq=100, plen=100))
        truncated = self.classify(packet(1.01, seq=200, plen=100,
                                         opts_trunc=1, thl=40, caplen=54))
        after = self.classify(packet(1.02, seq=300, plen=10))
        self.assertEqual(truncated["packet_type"], "DATA")
        self.assertEqual(truncated["seq_event"], "IN_ORDER")
        self.assertIn("OPTIONS_TRUNCATED", reasons(truncated))
        self.assertEqual(after["seq_event"], "IN_ORDER")

    def test_short_timestamp_separation_and_long_idle_are_context_flags(self):
        self.classify(packet(1.0, seq=100, plen=10))
        close = self.classify(packet(1.0001, seq=100, plen=10))
        idle = self.classify(packet(62.0, seq=110, plen=10))
        self.assertIn("TIMESTAMP_ORDER_SENSITIVE", reasons(close))
        self.assertIn("LONG_IDLE_CONTEXT", reasons(idle))
        self.assertEqual(idle["seq_event"], "IN_ORDER")

    def test_equal_timestamps_keep_both_events_and_range_cause_unknown(self):
        first = self.classify(packet(1.0, seq=100, plen=10))
        duplicate = self.classify(packet(1.0, seq=100, plen=10))
        self.assertEqual(first["seq_event"], "BASELINE")
        self.assertEqual(duplicate["seq_event"], "DUP_FULL")
        self.assertIn("TIMESTAMP_ORDER_SENSITIVE", reasons(duplicate))
        self.assertIn("REPEATED_RANGE_CAUSE_UNKNOWN", reasons(duplicate))


if __name__ == "__main__":
    unittest.main()
