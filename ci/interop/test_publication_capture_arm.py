"""Never select a WC session by highest directory name or a different block."""

import json
import tempfile
import unittest
from pathlib import Path

from publication_capture_arm import CaptureSessionPending, arm_capture, select_session
from workchain_output_evidence import block_text


class CaptureArmTests(unittest.TestCase):
    def test_exact_observation_and_runtime_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            block = {
                "workchain": 0,
                "shard": str(-(1 << 63)),
                "seqno": 10,
                "root_hash": "AA==",
                "file_hash": "AQ==",
            }
            checked = {
                "verified_final_certificates": [{"final_certificate_checked": True}],
                "workchain_check": {
                    "block": block,
                    "masterchain_anchor_checked": True,
                    "all_four_states_match_block_update": True,
                    "gen_catchain_seqno": 1,
                },
            }
            session = "77" * 32
            runtime = (
                root / "node_db/catchains/consensus/v2/active/session-runtime.json"
            )
            runtime.parent.mkdir(parents=True)
            manifest = {
                "session": session,
                "role": "validator",
                "shard_workchain": 0,
                "shard_prefix": 1 << 63,
                "catchain_seqno": 1,
            }
            runtime.write_text(json.dumps(manifest))
            log = root / "node.log"
            log.write_text(
                f"SessionCallbacks::notify_candidate_observed session_id={session} block_id={block_text(block)} parent_ready=true\n"
            )
            self.assertEqual(select_session(root, checked), (session, runtime))
            self.assertEqual(arm_capture(root, checked, root / "capture", 42), session)
            self.assertEqual(
                (root / "capture/selector").read_text(), f"42\n{session}\n"
            )
            with self.assertRaises(ValueError):
                arm_capture(root, checked, root / "capture", 42)
            runtime.write_text(json.dumps(dict(manifest, role="observer")))
            with self.assertRaises(CaptureSessionPending):
                select_session(root, checked)
            runtime.write_text(json.dumps(dict(manifest, catchain_seqno=2)))
            with self.assertRaises(ValueError):
                select_session(root, checked)
            runtime.write_text(json.dumps(manifest))
            log.write_text(log.read_text().replace(", 10,", ", 11,"))
            with self.assertRaises(CaptureSessionPending):
                select_session(root, checked)
