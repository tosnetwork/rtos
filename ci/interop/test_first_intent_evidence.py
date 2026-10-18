#!/usr/bin/env python3
"""Prevent relabelled first-intent receipts from reaching expensive native checks."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from verify_first_intent_evidence import verify, verify_references


class FirstIntentEvidenceTests(unittest.TestCase):
    def fixture(self, root):
        (root/'builds').mkdir()
        (root/'rotation/first-intent-cut').mkdir(parents=True)
        metadata = {'genesis': '111', 'compiled_product_commit': 'product', 'commit': 'fixture',
                    'first_intent_cut': {'point': 'before-write'}}
        (root/'builds/first-intent-empty-source.json').write_text(json.dumps(metadata))
        cut = {'phase': 'rotation_and_first_intent_recovery_verified', 'member': 2,
               'point': 'before-write', 'interruption_returncode': -9,
               'normal_replay_completed': True, 'stopped_state_verified': True,
               'prior_complete_intents': 0, 'pending_preserved_before_restart': True,
               'manual_database_repair': False, 'elapsed_seconds': 4,
               'total_acceptance_elapsed_seconds': 100, 'recovery_limit_seconds': 180}
        result = {'status': 'mixed_membership_rotation_observed',
                  'all_six_applied_mc_states_match': True,
                  'independent_post_rotation_finality_qualified': True,
                  'first_intent_cut': copy.deepcopy(cut)}
        self.write(root, cut, result)
        return cut, result

    def write(self, root, cut, result):
        (root/'rotation/first-intent-cut/receipt.json').write_text(json.dumps(cut))
        (root/'rotation/result.json').write_text(json.dumps(result))

    def check(self, root, **changes):
        args = dict(output=root/'validation', genesis=111, point='before-write',
                    product='product', fixture='fixture', native_checker=root/'absent-checker',
                    product_directory=root/'absent-programs')
        args.update(changes)
        return verify(root, **args)

    def test_expected_identity_and_cut_cannot_be_relabelled(self):
        for changes in [dict(genesis=110), dict(product='other'), dict(fixture='other'),
                        dict(point='after-partial-write')]:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); self.fixture(root)
                with self.assertRaisesRegex(ValueError, 'Declared|Metadata cut'):
                    self.check(root, **changes)

    def test_late_acceptance_or_prior_intents_are_not_a_first_intent_success(self):
        for key, value in [('total_acceptance_elapsed_seconds', 181),
                           ('recovery_limit_seconds', 181), ('prior_complete_intents', 1),
                           ('normal_replay_completed', False), ('manual_database_repair', True)]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); cut,result=self.fixture(root)
                cut[key]=value; result['first_intent_cut']=copy.deepcopy(cut)
                self.write(root,cut,result)
                with self.assertRaises(ValueError): self.check(root)

    def test_result_and_frozen_receipt_must_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cut,result=self.fixture(root);cut['elapsed_seconds']=5
            self.write(root,cut,result)
            with self.assertRaisesRegex(ValueError, r"result\['first_intent_cut'\]"):
                self.check(root)

    def test_all_six_nodes_must_have_matching_full_state_references(self):
        reference={'last': {'seqno': 7, 'root_hash': 'root', 'file_hash': 'file'},
                   'init': {'seqno': 0, 'root_hash': 'genesis'}, 'state_root_hash': 'state'}
        request={'reference': reference, 'all_references': {name: copy.deepcopy(reference)
                 for name in ['cpp-0','cpp-1','cpp-4','rust-2','rust-3','rust-5']}}
        verify_references(request)
        for mutation in ['missing', 'extra', 'last', 'init', 'state_root_hash']:
            with self.subTest(mutation=mutation):
                altered=copy.deepcopy(request)
                if mutation=='missing': del altered['all_references']['rust-2']
                elif mutation=='extra': altered['all_references']['fake-peer']=reference
                else: altered['all_references']['rust-2'][mutation]='different'
                with self.assertRaises(ValueError): verify_references(altered)

    def test_existing_output_is_never_rewritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root);out=root/'validation';out.mkdir()
            marker=out/'original';marker.write_bytes(b'keep')
            with self.assertRaisesRegex(ValueError, 'already exists'):self.check(root)
            self.assertEqual(marker.read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()
