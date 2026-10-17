"""Keep fixture reports and authenticated weights at the exact pinned C++ boundary."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from quorum_profile import MAX_TOTAL_WEIGHT, quorum_threshold, epoch_weights, check_committee_weights, initial_probe_weights, initial_probe_deadline, matrix_committee_size, matrix_threshold_plan, matrix_weights, install_matrix_weights, observer_budget_plan
from rotation_fixture import install_successor, INITIAL, SUCCESSOR


class QuorumProfileTests(unittest.TestCase):
    def test_full_active_matrix_sizes_and_cpp_population_are_explicit(self):
        self.assertEqual(matrix_committee_size({'shard_validators': 4}, 2), 4)
        for count in (3, 4, 6):
            profile = {'validator_count': count, 'shard_validators': count}
            for cpp in range(count + 1):
                self.assertEqual(matrix_committee_size(profile, cpp), count)
            for cpp in (-1, count + 1, True, 1.5):
                with self.assertRaises(ValueError): matrix_committee_size(profile, cpp)
            with self.assertRaises(ValueError):
                matrix_committee_size({**profile, 'shard_validators': count - 1}, 0)
        for count in (True, 0, 2, 5, 7, 3.0, '6'):
            with self.assertRaises(ValueError):
                matrix_committee_size({'validator_count': count, 'shard_validators': count}, 0)

    def test_threshold_fault_plan_requires_the_complete_frozen_availability_case(self):
        self.assertIsNone(matrix_threshold_plan({'shard_validators': 4}, 2))
        for count, first, extra in [(3, [2], [1]), (6, [1, 5], [3])]:
            plan = {'pause_at_quorum': first, 'pause_below_quorum': extra,
                    'settle_seconds': 4, 'observe_seconds': 12}
            profile = {'validator_count': count, 'shard_validators': count, 'threshold_fault': plan}
            self.assertEqual(matrix_threshold_plan(profile, 1), plan)
            for key, value in [('pause_at_quorum', [True]), ('pause_below_quorum', first),
                               ('settle_seconds', True), ('settle_seconds', 3), ('observe_seconds', 1)]:
                with self.assertRaises(ValueError):
                    matrix_threshold_plan({**profile, 'threshold_fault': {**plan, key: value}}, 1)
            with self.assertRaises(ValueError): matrix_threshold_plan(profile, 0)
            with self.assertRaises(ValueError):
                matrix_threshold_plan({**profile, 'threshold_fault': {'pause_at_quorum': first}}, 1)

    def test_weighted_majority_budget_uses_the_full_frozen_committee(self):
        weights = {str(i): 30 if i == 5 else 6 for i in range(6)}
        plan = {'kind': 'low_weight_majority', 'pause_at_quorum': [],
            'pause_below_quorum': [5], 'settle_seconds': 4, 'observe_seconds': 12}
        profile = {'validator_count': 6, 'shard_validators': 6,
            'validator_weights': weights, 'threshold_fault': plan}
        self.assertEqual(matrix_weights(profile, 3), {int(i): w for i, w in weights.items()})
        self.assertEqual(matrix_threshold_plan(profile, 3), plan)
        self.assertEqual(quorum_threshold(sum(weights.values())), 40)
        self.assertEqual(sum(w for i, w in weights.items() if i != '5'), 30)
        for bad in [{**weights, '5': 29}, {**weights, '0': True}, {'5': 30}]:
            with self.assertRaises(ValueError):
                matrix_threshold_plan({**profile, 'validator_weights': bad}, 3)
        with self.assertRaises(ValueError):
            matrix_threshold_plan({**profile, 'threshold_fault': {**plan, 'pause_below_quorum': [4]}}, 3)
        with self.assertRaises(ValueError):
            matrix_threshold_plan({**profile, 'threshold_fault': {k:v for k,v in plan.items() if k!='kind'}}, 3)

    def test_matrix_descriptor_and_fift_weights_cannot_diverge(self):
        captured=[]
        class Descriptor:
            def __init__(self, identity, weight): self.data=bytes([identity,weight])
            def to_boc(self): return self.data
        module=SimpleNamespace(run_fift=lambda install,code,directory,**kwargs:captured.append(code),
            _pq_validator_descriptor=lambda identity,weight:Descriptor(identity,weight))
        nodes=[SimpleNamespace(pq_initial_validator=i) for i in range(6)]
        weights={i:30 if i==5 else 6 for i in range(6)}
        install_matrix_weights(module,nodes,weights)
        template='\n'.join(f'17 "pq-validator-{i}.boc" file>B B>boc register-validator' for i in range(6))
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);module.run_fift(None,template,directory)
            for i,w in weights.items():
                self.assertEqual((directory/f'pq-validator-{i}.boc').read_bytes(),bytes([i,w]))
                self.assertIn(f'{w} "pq-validator-{i}.boc"',captured[0])
            with self.assertRaisesRegex(RuntimeError,'template differs'):
                module.run_fift(None,'unknown native template',directory)

    def test_observer_budget_preserves_full_current_committee_and_original_window(self):
        plan={'pause_at_quorum':[], 'pause_below_quorum':[0,2], 'settle_seconds':4, 'observe_seconds':12}
        profile={'observer_budget':plan}
        self.assertEqual(observer_budget_plan(profile),plan)
        self.assertIsNone(observer_budget_plan({}))
        for key,value in [('pause_below_quorum',[True,2]),('pause_below_quorum',[1,3]),
                          ('settle_seconds',True),('settle_seconds',0),('observe_seconds',1)]:
            with self.assertRaises(ValueError):
                observer_budget_plan({'observer_budget':{**plan,key:value}})
        with self.assertRaises(ValueError):
            observer_budget_plan({**profile,'successor_weights':{'0':9,'2':11,'4':10,'5':30}})
        with self.assertRaises(ValueError):
            observer_budget_plan({**profile,'weighted_quorum_pause':[0,2]})

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

    def test_initial_probe_requires_every_remaining_member(self):
        profile = {'initial_probe_pause': [1], 'weighted_quorum_pause': [0, 2],
            'initial_weights': {'0': 29, '1': 11, '2': 10, '3': 10}}
        weights = initial_probe_weights(profile)
        self.assertEqual(sum(weights[i] for i in [0, 2, 3]), 49)
        self.assertEqual(quorum_threshold(sum(weights.values())), 40)
        for bad in [[True], [2], [], None]:
            with self.assertRaises(ValueError): initial_probe_weights({**profile, 'initial_probe_pause': bad})
        with self.assertRaises(ValueError):
            initial_probe_weights({**profile, 'initial_weights': {'0': 30, '1': 10, '2': 11, '3': 9}})
        with self.assertRaises(ValueError):
            initial_probe_weights({**profile, 'weighted_quorum_pause': [1]})

    def test_initial_probe_cannot_extend_epoch_or_rotation_deadline(self):
        self.assertEqual(initial_probe_deadline(1000, 180, 1100, 2060, 2000), 1060)
        self.assertEqual(initial_probe_deadline(1000, 180, 1010, 2200, 2000), 1010)
        self.assertEqual(initial_probe_deadline(1000, 5, 1100, 2200, 2000), 1005)
        for activation, rotation in [(2000, 1100), (1999, 1100), (2200, 1000)]:
            with self.assertRaises(TimeoutError):
                initial_probe_deadline(1000, 180, rotation, activation, 2000)

    def test_changed_pinned_template_fails_instead_of_silently_using_equal_weights(self):
        module = SimpleNamespace(run_fift=lambda *args: self.fail('wrong template must not run'))
        install_successor(module, [], {})
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, 'template insertion point'):
                module.run_fift(None, 'unknown native template', Path(tmp))


if __name__ == '__main__': unittest.main()
