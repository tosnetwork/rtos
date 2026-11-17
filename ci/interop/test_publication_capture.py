"""Raw capture integrity is required before any native finality validation."""

import hashlib
import struct
import unittest

from publication_capture import decode_body, read_capture


def encoded(role=True, carrier=b"actual carrier bytes"):
    body = b"actual block bytes"
    blob = lambda value: struct.pack("<I", len(value)) + value
    raw = b"RTOSPBXB" + struct.pack("<H", 5) + bytes(32)
    raw += struct.pack("<QB", 1, 0) + bytes(32) + bytes([7]) * 32
    raw += (
        struct.pack("<iQI", 0, 1 << 63, 10) + bytes(32) + hashlib.sha256(body).digest()
    )
    raw += bytes([0, int(role)]) + blob(carrier)
    raw += struct.pack("<BQQ", 1, 100, 200) + blob(body) + bytes([0])
    return raw + hashlib.sha256(raw).digest()


class PublicationCaptureTests(unittest.TestCase):
    def test_roles_remain_distinct_and_raw_carrier_preserved(self):
        import base64

        for role in (False, True):
            value = decode_body(encoded(role))
            self.assertEqual(value["is_final"], role)
            self.assertEqual(
                base64.b64decode(value["signature_set"]), b"actual carrier bytes"
            )
            self.assertEqual(value["block"]["id"]["seqno"], 10)

    def test_truncated_checksum_and_missing_carrier_are_rejected(self):
        raw = encoded()
        for changed in (raw[:-1], raw[:50] + b"x" + raw[51:], encoded(carrier=b"")):
            with self.assertRaises(ValueError):
                decode_body(changed)

    def test_resealed_wrong_file_hash_is_rejected(self):
        raw = bytearray(encoded()[:-32])
        raw[163] ^= 1
        with self.assertRaisesRegex(ValueError, "file hash"):
            decode_body(bytes(raw) + hashlib.sha256(raw).digest())


class CaptureSourceBindingTests(unittest.TestCase):
    def test_exact_receipt_binding_and_failure_marker(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = encoded()
            digest = hashlib.sha256(raw).hexdigest()
            (root / f"{digest}.bin").write_bytes(raw)
            receipt = {
                "pid": 42,
                "session": "07" * 32,
                "key": "PropagationOutboxV2/b/0000000000000001",
                "sha256": digest,
                "bytes": len(raw),
                "after_successful_sync": True,
            }
            path = root / f"{digest}.json"
            path.write_text(json.dumps(receipt))
            self.assertEqual(len(read_capture(root, 42, "07" * 32)), 1)
            for key, value in [
                ("pid", 43),
                ("session", "00" * 32),
                ("key", "different"),
                ("after_successful_sync", False),
                ("bytes", len(raw) + 1),
            ]:
                with self.subTest(key=key):
                    path.write_text(json.dumps(dict(receipt, **{key: value})))
                    with self.assertRaises(ValueError):
                        read_capture(root, 42, "07" * 32)
            path.write_text(json.dumps(receipt))
            (root / "failed").write_text("capture quota exhausted")
            with self.assertRaises(ValueError):
                read_capture(root, 42, "07" * 32)
