"""Keep fixture reports and authenticated weights at the exact pinned C++ boundary."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from quorum_profile import MAX_TOTAL_WEIGHT, quorum_threshold, epoch_weights, check_committee_weights
from rotation_fixture import install_successor, INITIAL, SUCCESSOR


class QuorumProfileTests(unittest.TestCase):
    def test_cpp_boundary_is_inclusive_when_total_is_divisible_by_three(self):
        for total, expected in [(3, 2), (6, 4), (51, 34), (102, 68), (60, 40), (68, 46)]:
            self.assertEqual(quorum_threshold(total), expected)
        self.assertEqual(quorum_threshold(MAX_TOTAL_WEIGHT), (MAX_TOTAL_WEIGHT * 2 + 2) // 3)

    def test_rejects_bad_weight_domains_and_wrong_members(self):
        for total in [True, 0, -1, MAX_TOTAL_WEIGHT + 1, 1.5]:
            with self.assertRaises(ValueError): quorum_threshold(total)
        for values in [{'0': 1}, {'0': True, '1': 10, '2': 11, '3': 9},
                       {'0': 0, '1': 10, '2': 11, '3': 9},
                       {'0': MAX_TOTAL_WEIGHT, '1': 10, '2': 11, '3': 9}]:
            with self.assertRaises(ValueError): epoch_weights({'initial_weights': values}, 'initial_weights', INITIAL)
        self.assertEqual(epoch_weights({}, 'initial_weights', INITIAL), {i: 17 for i in INITIAL})

    def test_authenticated_config_must_match_each_frozen_weight(self):
        expected = {0: 30, 1: 10, 2: 11, 3: 9}
        state = {'configuration': {'current': {'members': [
            {'validator_id': str(i), 'weight': w} for i, w in expected.items()]}}}
        receipt = check_committee_weights(state, expected, str)
        self.assertEqual((receipt['total_weight'], receipt['quorum_weight']), (60, 40))
        state['configuration']['current']['members'][0]['weight'] = 29
        with self.assertRaises(RuntimeError): check_committee_weights(state, expected, str)

    def test_genesis_descriptor_and_fift_registration_share_explicit_weights(self):
        captured = []
        class Descriptor:
            def __init__(self, identity, weight): self.data = bytes([identity, weight])
            def to_boc(self): return self.data
        module = SimpleNamespace(run_fift=lambda install, code, directory, **kwargs: captured.append(code),
            _pq_validator_descriptor=lambda identity, weight: Descriptor(identity, weight))
        nodes = [SimpleNamespace(pq_initial_validator=i) for i in range(6)]
        profile = {'genesis_time': 1000, 'activation_delay': 90, 'successor_valid_for': 10000,
            'initial_weights': {'0': 30, '1': 10, '2': 11, '3': 9},
            'successor_weights': {'0': 9, '2': 11, '4': 10, '5': 30}}
        template = '\n'.join(f'17 "pq-validator-{i}.boc" file>B B>boc register-validator' for i in range(4))
        template += '\nconfig.new_consensus_params_all!\n'
        original = install_successor(module, nodes, profile)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp); module.run_fift(None, template, directory)
            for i, weight in epoch_weights(profile, 'initial_weights', INITIAL).items():
                self.assertEqual((directory / f'pq-validator-{i}.boc').read_bytes(), bytes([i, weight]))
                self.assertIn(f'{weight} "pq-validator-{i}.boc"', captured[0])
            for i, weight in epoch_weights(profile, 'successor_weights', SUCCESSOR).items():
                self.assertEqual((directory / f'rotation-validator-{i}.boc').read_bytes(), bytes([i, weight]))
                self.assertIn(f'{weight} "rotation-validator-{i}.boc"', captured[0])
        self.assertIn('4 16 u, 4 16 u, 60 64 u', captured[0])
        self.assertEqual(original.__name__, '<lambda>')

    def test_changed_pinned_template_fails_instead_of_silently_using_equal_weights(self):
        module = SimpleNamespace(run_fift=lambda *args: self.fail('wrong template must not run'))
        install_successor(module, [], {})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, 'template insertion point'):
                module.run_fift(None, 'unknown native template', Path(tmp))


if __name__ == '__main__': unittest.main()
