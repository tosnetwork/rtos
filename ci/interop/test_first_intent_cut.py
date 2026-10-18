#!/usr/bin/env python3
"""Scope checks for the actual first-intent process interruption fixture."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from first_intent_cut_fixture import FirstIntentCut, validate_first_intent_cut
from unittest.mock import Mock


class FirstIntentScopeTests(unittest.TestCase):
    def args(self, **changes):
        values = dict(first_intent_cut_library=Path('/owned/fault.so'),
                      rust_node=Path('/owned/rtos'), recovery_timeout=180)
        values.update(changes)
        return SimpleNamespace(**values)

    def test_explicit_standalone_case(self):
        validate_first_intent_cut(self.args())

    def test_other_recovery_authority_and_time_cases_cannot_be_silently_combined(self):
        for name, value in [('interrupt_rust_member', 2), ('source_ack_fault', 'sync-eio'),
                            ('source_ack_intent_stop', True), ('partition_restart', True),
                            ('source_retention_cut_library', Path('/other.so')),
                            ('network_fault', 'partition'), ('additional_network_faults', ['partition']),
                            ('signer_expiry_member', 5), ('expired_member_restart', True),
                            ('followup_intent_frontier', True), ('prepare_genesis_only', True),
                            ('rust_node', None), ('recovery_timeout', 181)]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_first_intent_cut(self.args(**{name: value}))

    def test_completion_file_does_not_replace_post_restart_consensus_evidence(self):
        for missing in ['normal_replay', 'mc_log', 'wc_log', 'vote']:
            with self.subTest(missing=missing):
                cut = FirstIntentCut.__new__(FirstIntentCut)
                cut.receipt = {'normal_replay_completed': missing != 'normal_replay'}
                cut.started = 0
                cut.check_budget = Mock()
                cut.save = Mock()
                mc = {'local_collation_log': 'node.log' if missing == 'mc_log' else 'node-restart.log',
                      'check': {'verified_final_certificates': [{'validator_ids': [] if missing == 'vote' else ['member2']}]}}
                wc = {'local_collation_log': 'node.log' if missing == 'wc_log' else 'node-restart.log'}
                epochs = {'after': {'mc_creators': {'member2': mc}, 'wc_creators': {'member2': wc}}}
                with self.assertRaises(RuntimeError):
                    cut.qualify_rotation(epochs, 'member2')
                cut.save.assert_not_called()

    def test_existing_cases_do_not_change(self):
        validate_first_intent_cut(self.args(first_intent_cut_library=None, source_ack_fault='sync-eio'))


if __name__ == '__main__':
    unittest.main()
