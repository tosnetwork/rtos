"""Positive and adversarial controls for unsigned bootstrap evidence."""

import unittest
from copy import deepcopy

from sync_observation import SyncObservation

ZERO = {
    "workchain": -1,
    "shard": -9223372036854775808,
    "seqno": 0,
    "root_hash": "zero-root",
    "file_hash": "zero-file",
}


def info(height=4):
    return {
        "init": deepcopy(ZERO),
        "last": dict(
            ZERO, seqno=height, root_hash=f"root-{height}", file_hash=f"file-{height}"
        ),
        "state_root_hash": f"state-{height}",
    }


class SyncObservationTests(unittest.TestCase):
    def test_matching_native_state_without_logs(self):
        self.assertIsNotNone(SyncObservation(ZERO, 4).observe([info()] * 3, info()))

    def test_below_minimum(self):
        self.assertIsNone(SyncObservation(ZERO, 4).observe([info(3)] * 3, info(3)))

    def test_each_identity_field_is_required(self):
        for field in ["root_hash", "file_hash", "seqno"]:
            with self.subTest(field=field):
                rust = info()
                rust["last"][field] = 5 if field == "seqno" else "wrong"
                self.assertIsNone(SyncObservation(ZERO, 4).observe([info()] * 3, rust))

    def test_state_mismatch_is_failure(self):
        rust = info()
        rust["state_root_hash"] = "wrong"
        with self.assertRaisesRegex(ValueError, "state root differs"):
            SyncObservation(ZERO, 4).observe([info()] * 3, rust)

    def test_wrong_genesis_on_any_node(self):
        for index in range(4):
            observations = [info() for _ in range(4)]
            observations[index]["init"]["file_hash"] = "wrong"
            with self.assertRaisesRegex(ValueError, "Genesis"):
                SyncObservation(ZERO, 4).observe(observations[:3], observations[3])

    def test_disagreeing_references_cannot_certify(self):
        for field in ["state_root_hash", "last"]:
            references = [info() for _ in range(3)]
            references[2][field] = info(5)[field]
            self.assertIsNone(SyncObservation(ZERO, 4).observe(references, info()))

    def test_lagging_rust_matches_saved_checkpoint(self):
        observer = SyncObservation(ZERO, 4)
        self.assertIsNone(observer.observe([info()] * 3, info(3)))
        self.assertIsNotNone(observer.observe([info(5)] * 3, info()))

    def test_bounded_history(self):
        observer = SyncObservation(ZERO, 4, max_checkpoints=1)
        observer.observe([info()] * 3, info(3))
        self.assertIsNone(observer.observe([info(5)] * 3, info()))

    def test_no_references(self):
        with self.assertRaises(ValueError):
            SyncObservation(ZERO, 4).observe([], info())


if __name__ == "__main__":
    unittest.main()
