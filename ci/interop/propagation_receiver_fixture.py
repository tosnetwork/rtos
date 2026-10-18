"""Nonvoting native receiver for original-sender-only propagation topologies."""
import hashlib
import json
import socket
import struct

# Pinned native overlay_memberCertificateId: node is a bare adnl.id.short.
CERTIFICATE_ID = 0x2c87dc32


def certificate_payload(node_id, slot, expire_at):
    if not isinstance(node_id, bytes) or len(node_id) != 32:
        raise ValueError('Receiver ADNL identity must contain 32 bytes')
    if type(slot) is not int or not 0 <= slot < 2**31:
        raise ValueError('Receiver certificate slot is outside the native limit')
    if type(expire_at) is not int or not 0 < expire_at < 2**31:
        raise ValueError('Receiver certificate expiry must fit a positive int32')
    return struct.pack('<I', CERTIFICATE_ID) + node_id + struct.pack('<iii', 0, slot, expire_at)


def issue_certificate(issuer, node_id, slot, expire_at):
    if type(slot) is not int or not 0 <= slot < 5:
        raise ValueError('Receiver slot exceeds pinned MAX_FAST_SYNC_OVERLAY_CLIENTS=5')
    payload = certificate_payload(node_id, slot, expire_at)
    return {'@type': 'overlay.memberCertificate',
        'issued_by': {'@type': 'pub.ed25519', 'key': issuer.key.verify_key.encode()},
        'flags': 0, 'slot': slot, 'expire_at': expire_at,
        'signature': issuer.key.sign(payload).signature}


def receiver_plan(profile):
    plan = profile.get('propagation_receiver')
    if plan is None:
        return None
    if plan != {'cpp_nonvoting': 1, 'issuer_member': 0, 'slot': 0, 'valid_for_seconds': 3600}:
        raise ValueError('Declare the single native nonvoting receiver explicitly')
    if profile['consensus']['protocol_version'] != 2 or not profile['consensus']['use_quic']:
        raise ValueError('The receiver exercises the native protocol-2 QUIC topology')
    return plan


def native_certificate(certificate, tos_api):
    return tos_api.Overlay_memberCertificate(
        issued_by=tos_api.Pub_ed25519(key=certificate['issued_by']['key']),
        flags=certificate['flags'], slot=certificate['slot'],
        expire_at=certificate['expire_at'], signature=certificate['signature'])


class PropagationReceiver:
    def __init__(self, root, node, endpoint, certificate, issuer):
        self.root, self.node, self.endpoint = root, node, endpoint
        self.zero = json.loads((root / 'genesis.json').read_text())['zerostate']
        self.receipt = {'role': 'cpp_nonvoting_propagation_receiver',
            'committee_member': False, 'consensus_keys_configured': False,
            'issuer_member': 0, 'issuer_adnl': issuer.id.hex(),
            'adnl_id': node._fullnode_key.id.hex(), 'endpoint': endpoint,
            'certificate_flags': certificate['flags'], 'certificate_slot': certificate['slot'],
            'certificate_expire_at': certificate['expire_at'],
            'certificate_signature_sha256': hashlib.sha256(certificate['signature']).hexdigest(),
            'pid': node.process_id, 'directory': str(node._directory)}
        self.save()

    def save(self):
        (self.root / 'propagation-receiver.json').write_text(json.dumps(self.receipt, indent=2) + '\n')

    async def verify_checkpoint(self, target, rpc, identity, timeout=20):
        import asyncio
        import time
        end = time.monotonic() + timeout
        last_error = None
        while time.monotonic() < end:
            try:
                info = await asyncio.to_thread(rpc, self.endpoint, 'getMasterchainInfo')
                if identity(info['init']) != identity(self.zero):
                    raise RuntimeError('Native receiver changed Genesis')
                if int(info['last']['seqno']) >= int(target['seqno']):
                    actual = await asyncio.to_thread(rpc, self.endpoint, 'lookupBlock', dict(
                        workchain=-1, shard=str(-(1 << 63)), seqno=int(target['seqno'])))
                    if identity(actual) != identity(target):
                        raise RuntimeError('Native receiver has a different full checkpoint identity')
                    self.receipt.update(checkpoint=actual, latest=info['last'],
                        checkpoint_full_identity_matches=True)
                    self.save()
                    return self.receipt
            except Exception as error:
                last_error = str(error)
            await asyncio.sleep(.1)
        raise RuntimeError('Native propagation receiver did not reach the declared checkpoint: ' + str(last_error))


async def start_receiver(args, profile, network, dht, members, root, used, reserve_port, StartOptions):
    from tosapi import tos_api
    plan = receiver_plan(profile)
    if plan is None:
        return None
    node = network.create_full_node()
    node._local_config.validators = []
    node.announce_to(dht)
    issuer = members[plan['issuer_member']].validator_key
    certificate = issue_certificate(issuer, node._fullnode_key.id, plan['slot'],
        profile['genesis_time'] + plan['valid_for_seconds'])
    node._local_config.extraconfig = tos_api.Engine_validator_extraConfig(
        state_serializer_enabled=True,
        fast_sync_member_certificates=[tos_api.Engine_validator_fastSyncMemberCertificate(
            adnl_id=node._fullnode_key.id,
            certificate=native_certificate(certificate, tos_api))])
    address = '127.0.0.1:' + str(reserve_port(socket.SOCK_STREAM, used))
    await node.run(StartOptions(threads=1, verbosity=3, args=['--json-rpc-address', address]))
    return PropagationReceiver(root, node, 'http://' + address + '/jsonRPC', certificate, issuer)
