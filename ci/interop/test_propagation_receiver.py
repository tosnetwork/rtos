import types
import unittest
from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError
from propagation_receiver_fixture import certificate_payload, issue_certificate, receiver_plan


class PropagationReceiverTests(unittest.TestCase):
    def test_signing_bytes_match_pinned_native_reference(self):
        self.assertEqual(certificate_payload(bytes([0x55])*32, 7, 2000000000).hex(),
            '32dc872c' + '55'*32 + '000000000700000000943577')

    def test_certificate_binds_receiver_slot_expiry_and_receives_without_voting(self):
        issuer = types.SimpleNamespace(key=SigningKey(bytes([7])*32))
        receiver = bytes([8])*32
        certificate = issue_certificate(issuer, receiver, 0, 2000000000)
        self.assertEqual(certificate['flags'], 0)
        self.assertNotIn('validator_id', certificate)
        with self.assertRaises(ValueError):
            issue_certificate(issuer, receiver, 5, 2000000000)
        verify = issuer.key.verify_key
        verify.verify(certificate_payload(receiver, 0, 2000000000), certificate['signature'])
        for node, slot, expiry in [(bytes([9])*32,0,2000000000),
                                  (receiver,1,2000000000),(receiver,0,1999999999)]:
            with self.assertRaises(BadSignatureError):
                verify.verify(certificate_payload(node,slot,expiry), certificate['signature'])

    def test_invalid_native_coordinates_are_refused(self):
        for node,slot,expiry in [(b'',0,1),(bytes(32),True,1),(bytes(32),2**31,1),
                                 (bytes(32),0,2**31),(bytes(32),0,False)]:
            with self.assertRaises(ValueError):
                certificate_payload(node,slot,expiry)

    def test_receiver_topology_is_explicit_and_does_not_modify_committee(self):
        profile={'consensus':{'protocol_version':2,'use_quic':True},
            'initial_members':[0,1,2,3],'successor_members':[0,2,4,5]}
        self.assertIsNone(receiver_plan(profile))
        plan={'cpp_nonvoting':1,'issuer_member':0,'slot':0,'valid_for_seconds':3600}
        profile['propagation_receiver']=plan
        self.assertEqual(receiver_plan(profile),plan)
        self.assertEqual(profile['initial_members'],[0,1,2,3])
        self.assertEqual(profile['successor_members'],[0,2,4,5])
        with self.assertRaises(ValueError):
            receiver_plan({**profile,'propagation_receiver':{**plan,'cpp_nonvoting':2}})
