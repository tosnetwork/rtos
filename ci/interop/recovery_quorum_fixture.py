"""Observe lack of finality when an owned restarted member is needed for quorum."""
import asyncio
import time

from mixed_matrix import identity, rpc, write
from partition_restart_fixture import hold
from quorum_profile import epoch_weights, quorum_threshold


def recovery_quorum_plan(profile, member, below_quorum):
    committee = [0, 2, 4, 5]
    if member not in committee:
        raise ValueError('Recovery member must belong to the successor committee')
    weights = epoch_weights(profile, 'successor_weights', committee)
    total = sum(weights.values()); threshold = quorum_threshold(total)
    survivors = [i for i in committee if i != member]
    surviving = sum(weights[i] for i in survivors)
    if not below_quorum:
        if surviving < threshold:
            raise ValueError('Recovery needs an explicit below-quorum observation for insufficient survivors')
        return None
    if surviving >= threshold:
        raise ValueError('Below-quorum observation requires insufficient surviving weight')
    return {'member': member, 'weights': weights, 'total_weight': total, 'quorum_weight': threshold,
        'surviving_weight': surviving, 'survivor_members': survivors,
        'live_endpoints': [i for i in range(6) if i != member],
        'settle_seconds': 4, 'observe_seconds': 12}


async def observe_below_quorum(root, endpoints, zero, plan, deadline, *,
                               settle_seconds=4, observe_seconds=12, interval=.2):
    directory = root / 'recovery-quorum'; directory.mkdir()
    receipt = {'phase': 'settling', 'plan': plan, 'started_at_unix': time.time(),
        'required_observe_seconds': observe_seconds, 'manual_database_repair': False}
    write(directory / 'receipt.json', receipt)
    def budget():
        if time.monotonic() >= deadline:
            raise TimeoutError('Below-quorum observation exceeded the original recovery deadline')
    await hold(settle_seconds, deadline, budget)

    async def read_all():
        budget()
        replies = await asyncio.wait_for(asyncio.gather(*(asyncio.to_thread(rpc, endpoints[i], 'getMasterchainInfo')
            for i in plan['live_endpoints'])), deadline-time.monotonic())
        infos = dict(zip(plan['live_endpoints'], replies))
        if any(identity(info['init']) != identity(zero) for info in replies):
            raise RuntimeError('Below-quorum endpoint changed Genesis')
        return infos

    # In-flight decisions may drain during settling. Require a common checkpoint
    # before observing, and then reject any movement on every surviving endpoint.
    while True:
        infos = await read_all()
        if len({identity(info['last']) for info in infos.values()}) == 1:break
        await asyncio.sleep(min(interval,max(0,deadline-time.monotonic())))
    first = next(iter(infos.values())); block = first['last']; state = first['state_root_hash']
    started = time.monotonic(); observations = []
    receipt.update(phase='observing', block=block, state_root_hash=state, observed_from_unix=time.time())
    try:
        while True:
            if any(identity(info['last']) != identity(block) for info in infos.values()):
                raise RuntimeError('Below-quorum finality advanced or forked after settling')
            if any(info['state_root_hash'] != state for info in infos.values()):
                raise RuntimeError('Below-quorum applied states disagree')
            elapsed = time.monotonic()-started
            observations.append({'elapsed_seconds':elapsed, 'references':infos})
            receipt.update(observation_count=len(observations), observation_elapsed_seconds=elapsed)
            if elapsed >= observe_seconds:break
            await asyncio.sleep(min(interval,observe_seconds-elapsed,max(0,deadline-time.monotonic())))
            infos = await read_all()
        budget()
        receipt.update(phase='observed_no_finality', completed_at_unix=time.time())
        return infos
    finally:
        write(directory / 'observations.json', observations)
        write(directory / 'receipt.json', receipt)


def validate_below_quorum_checkpoint(checked, observation, plan, member_id):
    members = checked['configuration']['current']['members']
    expected = {member_id(int(i)):weight for i,weight in plan['weights'].items()}
    actual = {entry['validator_id']:entry['weight'] for entry in members}
    if actual != expected or len(members) != len(expected):
        raise RuntimeError('Below-quorum checkpoint changed the original authenticated committee weights')
    # JSON serialization changes integer dictionary keys; compare normalized plans.
    import json
    normalize = lambda value:json.loads(json.dumps(value))
    if observation.get('phase') != 'observed_no_finality' or normalize(observation.get('plan')) != normalize(plan) \
            or observation['observation_count'] < 2 \
            or observation['observation_elapsed_seconds'] < observation['required_observe_seconds'] \
            or observation['required_observe_seconds'] != plan['observe_seconds'] \
            or identity(observation['block']) != identity(checked['block']) \
            or observation['state_root_hash'] != checked['state_root_hash']:
        raise RuntimeError('Below-quorum checkpoint lacks its completed original-budget observation')
    if not checked['verified_final_certificates']:
        raise RuntimeError('Below-quorum baseline lacks historical finality')
