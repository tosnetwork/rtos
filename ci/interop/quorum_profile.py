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
