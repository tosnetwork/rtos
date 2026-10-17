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
