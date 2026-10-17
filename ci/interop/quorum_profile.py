"""Explicit fixture weights and the pinned C++ non-strict two-thirds rule."""
MAX_TOTAL_WEIGHT = ((1 << 64) - 1) // 3


def quorum_threshold(total):
    if type(total) is not int or not 0 < total <= MAX_TOTAL_WEIGHT:
        raise ValueError('Validator total weight must be positive and within the C++ cap')
    return (total * 2 + 2) // 3


def epoch_weights(profile, key, indices):
    values = profile.get(key, {str(i): 17 for i in indices})
    if not isinstance(values, dict) or set(values) != {str(i) for i in indices}:
        raise ValueError(f'{key} must name exactly the declared physical members')
    if any(type(v) is not int or v <= 0 for v in values.values()):
        raise ValueError(f'{key} weights must be positive integers')
    quorum_threshold(sum(values.values()))
    return {i: values[str(i)] for i in indices}


def check_committee_weights(checked, expected, member_id):
    actual = {entry['validator_id']: entry['weight']
              for entry in checked['configuration']['current']['members']}
    desired = {member_id(i): weight for i, weight in expected.items()}
    if actual != desired:
        raise RuntimeError('Authenticated committee weights differ from the frozen profile')
    total = sum(desired.values())
    return {'members': desired, 'total_weight': total, 'quorum_weight': quorum_threshold(total)}


def initial_probe_weights(profile):
    paused = profile.get('initial_probe_pause')
    if type(paused) is not list or len(paused) != 1 or type(paused[0]) is not int or paused != [1]:
        raise ValueError('Initial probe requires the explicit owned member [1]')
    if profile.get('weighted_quorum_pause') != [0, 2]:
        raise ValueError('Initial probe must precede the declared successor weighted case')
    weights = epoch_weights(profile, 'initial_weights', [0, 1, 2, 3])
    threshold = quorum_threshold(sum(weights.values()))
    live = [0, 2, 3]
    surviving = sum(weights[i] for i in live)
    if surviving < threshold or any(surviving - weights[i] >= threshold for i in live):
        raise ValueError('Every surviving initial member must be necessary for quorum')
    return weights


def initial_probe_deadline(started, timeout, rotation_deadline, activation, wall_now):
    deadline = min(started + timeout, rotation_deadline, started + activation - wall_now)
    if deadline <= started:
        raise TimeoutError('Initial epoch has ended before the declared probe')
    return deadline


def matrix_committee_size(profile, cpp_count):
    """Require a full active 3/4/6-member committee, preserving legacy four."""
    count = profile.get('validator_count', 4)
    if type(count) is not int or count not in (3, 4, 6):
        raise ValueError('Matrix validator_count must be exactly 3, 4 or 6')
    if type(cpp_count) is not int or not 0 <= cpp_count <= count:
        raise ValueError('CPP count must be within the declared active committee')
    if profile.get('shard_validators') != count:
        raise ValueError('Full active matrix requires shard_validators == validator_count')
    return count


def matrix_weights(profile, cpp_count):
    count = matrix_committee_size(profile, cpp_count)
    return epoch_weights(profile, 'validator_weights', range(count))


def install_matrix_weights(module, nodes, weights):
    """Keep the native PQ descriptor and Fift registration weights identical."""
    original = module.run_fift
    def generate(install, code, directory, **kwargs):
        for index, weight in weights.items():
            filename = f'pq-validator-{index}.boc'
            old = f'17 "{filename}" file>B B>boc register-validator'
            if code.count(old) != 1:
                raise RuntimeError('Pinned matrix PQ validator template differs')
            (directory / filename).write_bytes(module._pq_validator_descriptor(
                nodes[index].pq_initial_validator, weight).to_boc())
            code = code.replace(old, f'{weight} "{filename}" file>B B>boc register-validator')
        return original(install, code, directory, **kwargs)
    module.run_fift = generate
    return original


def matrix_threshold_plan(profile, cpp_count):
    plan = profile.get('threshold_fault')
    if plan is None:
        return None
    count = matrix_committee_size(profile, cpp_count)
    if count not in (3, 6) or cpp_count == 0:
        raise ValueError('Threshold fault requires three/six active members and CPP anchor zero')
    weighted = type(plan) is dict and plan.get('kind') == 'low_weight_majority'
    if weighted and (count != 6 or matrix_weights(profile, cpp_count) != {0:6,1:6,2:6,3:6,4:6,5:30}):
        raise ValueError('Low-weight majority requires the explicit full six-member 6/6/6/6/6/30 profile')
    expected = {'pause_at_quorum': [2] if count == 3 else [1, 5],
        'pause_below_quorum': [1] if count == 3 else [3],
        'settle_seconds': 4, 'observe_seconds': 12}
    if weighted:
        expected.update(kind='low_weight_majority', pause_at_quorum=[], pause_below_quorum=[5])
    elif matrix_weights(profile, cpp_count) != {i:17 for i in range(count)}:
        raise ValueError('Equal-weight threshold plan requires uniform 17-unit weights')
    if type(plan) is not dict or set(plan) != set(expected):
        raise ValueError('Threshold fault requires the complete declared bounded plan')
    for key, value in expected.items():
        actual = plan[key]
        if isinstance(value, list):
            if type(actual) is not list or any(type(i) is not int for i in actual):
                raise ValueError('Threshold pause members must be explicit integer indices')
        elif key == 'kind':
            if type(actual) is not str:
                raise ValueError('Threshold kind must be explicit text')
        elif type(actual) is not int:
            raise ValueError('Threshold timing must be explicit integer seconds')
        if actual != value:
            raise ValueError('Threshold fault differs from the declared three/six-member case')
    return {key: value.copy() if isinstance(value, list) else value for key, value in expected.items()}


def observer_budget_plan(profile):
    plan = profile.get('observer_budget')
    if plan is None:
        return None
    expected = {'pause_at_quorum': [], 'pause_below_quorum': [0, 2],
                'settle_seconds': 4, 'observe_seconds': 12}
    if type(plan) is not dict or set(plan) != set(expected):
        raise ValueError('Observer budget requires the complete bounded plan')
    for key, value in expected.items():
        actual = plan[key]
        if isinstance(value, list):
            if type(actual) is not list or any(type(i) is not int for i in actual):
                raise ValueError('Observer pause indices must be explicit integers')
        elif type(actual) is not int:
            raise ValueError('Observer timing must be explicit integer seconds')
        if actual != value:
            raise ValueError('Observer budget differs from the declared successor case')
    for key, indices in [('initial_weights', [0,1,2,3]), ('successor_weights', [0,2,4,5])]:
        if epoch_weights(profile, key, indices) != {i:17 for i in indices}:
            raise ValueError('Observer availability case requires frozen equal-weight committees')
    if any(profile.get(key) is not None for key in ['weighted_quorum_pause','initial_probe_pause']):
        raise ValueError('Observer availability must be a separate declared case')
    return {key: value.copy() if isinstance(value, list) else value for key,value in expected.items()}
