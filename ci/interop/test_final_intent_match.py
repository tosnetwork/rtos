"""Keep first-intent scope while matching authenticated later Final candidates."""

import base64
import copy
import unittest

from first_intent_vote import matches_final_intent, matches_original_intent


def fixture(height=300):
    record = {"session_id": "01" * 32, "slot": 33, "candidate_hash": "ab" * 32}
    checked = {
        "status": "block_and_state_match",
        "block": {"workchain": -1, "seqno": height},
        "file_hash_checked": True,
        "cell_hash_checked": True,
        "header_identity_checked": True,
        "state_update_matches_both": True,
        "verified_final_certificates": [
            {
                "final_certificate_checked": True,
                "session_id": base64.b64encode(
                    bytes.fromhex(record["session_id"])
                ).decode(),
                "slot": record["slot"],
                "candidate_hash": record["candidate_hash"],
            }
        ],
    }
    return record, checked


class FinalIntentMatchTest(unittest.TestCase):
    def test_later_candidate_does_not_qualify_first_intent(self):
        record, checked = fixture()
        self.assertTrue(matches_final_intent(checked, record, workchain=-1))
        self.assertFalse(matches_original_intent(checked, record))
        checked["block"]["seqno"] = 1
        self.assertTrue(matches_original_intent(checked, record))

    def test_state_copy_or_unverified_certificate_is_insufficient(self):
        record, checked = fixture()
        mutations = [
            lambda c: c.update(status="state-copies"),
            lambda c: c.update(state_update_matches_both=False),
            lambda c: c.update(verified_final_certificates=[]),
            lambda c: c["verified_final_certificates"][0].update(
                final_certificate_checked=False
            ),
            lambda c: c["verified_final_certificates"][0].update(
                session_id="not base64"
            ),
            lambda c: c["verified_final_certificates"][0].update(slot=34),
            lambda c: c["verified_final_certificates"][0].update(
                candidate_hash="cd" * 32
            ),
            lambda c: c["block"].update(workchain=0),
            lambda c: c["block"].update(seqno=True),
            lambda c: c["block"].update(seqno=0),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                changed = copy.deepcopy(checked)
                mutate(changed)
                self.assertFalse(matches_final_intent(changed, record, workchain=-1))
        record["slot"] = True
        checked["verified_final_certificates"][0]["slot"] = 1
        self.assertFalse(matches_final_intent(checked, record, workchain=-1))


if __name__ == "__main__":
    unittest.main()
