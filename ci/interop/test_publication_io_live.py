"""Bind live EIO evidence to original intents, never to observation copies."""

import asyncio
import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import test_publication_io_fixture as queued
from publication_io_live_fixture import (
    LivePublicationIoSource,
    bound_intents,
    selected_source,
    sha,
)


class LivePublicationTests(unittest.TestCase):
    def fixture(self, root):
        old, selector, _marker, target, failed = (
            queued.PublicationIoFixtureTests().context(root)
        )
        source = LivePublicationIoSource.__new__(LivePublicationIoSource)
        source.__dict__.update(old.__dict__)
        source.selector = selector
        record = json.loads(old.original)
        record.update(
            schema=1,
            carrier_version=1,
            local_adnl="d" * 64,
            local_validator_index=0,
            source_validator="e" * 64,
        )
        namespace = source.pending_directory.parent
        intent_dir = namespace / "finality-intents"
        output_dir = intent_dir / "outputs-v1"
        output_dir.mkdir(parents=True)
        cert = {"session_id": record["session_id"], "certificate": "deadbeef"}
        raw = json.dumps(cert, separators=(",", ":")).encode()
        intent = intent_dir / ("7-" + "f" * 64 + ".json")
        intent.write_bytes(raw)
        output = output_dir / (intent.stem + ".outputs")
        write_output = {
            "schema": 1,
            "digest": sha(raw),
            "metadata": {**cert, "certificate": ""},
            "outputs": [
                {
                    "block_id": record["block_id"],
                    "is_final": True,
                    "source_validator": record["source_validator"],
                }
            ],
            "released": False,
        }
        output.write_text(json.dumps(write_output))
        source.source_snapshot = bound_intents(namespace, record)
        publication = {
            "record_id": None,
            "node_receipt": None,
            "delivery_id": selector["delivery_id"],
            "stage": "LiveAcceptance",
        }
        target["publication"] = publication
        target_raw = json.dumps(target).encode()
        (source.io_directory / "target.json").write_bytes(target_raw)
        failed.update(
            publication=publication,
            target_sha256=sha(target_raw),
            retained_draft_verified=False,
        )
        (source.io_directory / "failed.json").write_text(json.dumps(failed))
        return source, record, namespace, intent, output, target, failed

    def test_exact_retained_intent_and_native_failure_are_required(self):
        for change in [None, "intent", "callback", "receipt", "wal", "delivery"]:
            with (
                self.subTest(change=change),
                tempfile.TemporaryDirectory() as temporary,
            ):
                source, _, _, intent, _, target, failed = self.fixture(Path(temporary))
                if change == "intent":
                    intent.write_bytes(b"changed")
                if change == "callback":
                    failed["accepted_callback_returned"] = True
                if change == "wal":
                    failed["retained_draft_verified"] = True
                if change in {"receipt", "delivery"}:
                    key = "node_receipt" if change == "receipt" else "delivery_id"
                    target["publication"][key] = "0" * 64
                    failed["publication"] = target["publication"]
                    raw = json.dumps(target).encode()
                    (source.io_directory / "target.json").write_bytes(raw)
                    failed["target_sha256"] = sha(raw)
                (source.io_directory / "failed.json").write_text(json.dumps(failed))
                with patch.object(source, "stopped", return_value=True):
                    if change is None:
                        source.capture_failure()
                        self.assertTrue(source.receipt["original_intents_preserved"])
                    else:
                        with self.assertRaises(RuntimeError):
                            source.capture_failure()

    def test_output_map_must_bind_actual_pending_certificate(self):
        for change in ["digest", "certificate", "released", "role", "creator"]:
            with (
                self.subTest(change=change),
                tempfile.TemporaryDirectory() as temporary,
            ):
                _, record, namespace, intent, output, _, _ = self.fixture(
                    Path(temporary)
                )
                value = json.loads(output.read_text())
                if change == "digest":
                    value["digest"] = "0" * 64
                if change == "certificate":
                    intent.write_text("{}")
                if change == "released":
                    value["released"] = True
                if change == "role":
                    value["outputs"][0]["is_final"] = False
                if change == "creator":
                    value["outputs"][0]["source_validator"] = "0" * 64
                output.write_text(json.dumps(value))
                with self.assertRaises(RuntimeError):
                    bound_intents(namespace, record)

    def test_observation_identity_and_non_custody_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, record, namespace, _, _, _, _ = self.fixture(Path(temporary))
            identity = [
                "rtos-source-finality-v1",
                record["global_id"],
                record["zerostate"],
                record["protocol"],
                record["carrier_version"],
                record["wire_profile"],
                record["profile"],
                record["session_id"],
                record["block_id"],
                True,
                [record["local_adnl"], 0, record["source_validator"]],
            ]
            observed = {
                "schema": 1,
                "pid": 10,
                "namespace": str(namespace),
                "record": record,
                "is_custody_receipt": False,
                "source_id": sha(json.dumps(identity, separators=(",", ":")).encode()),
            }
            self.assertEqual(
                selected_source(
                    observed, pid=10, session=record["session_id"], namespace=namespace
                )[0],
                record,
            )
            for key, value in [
                ("pid", 11),
                ("is_custody_receipt", True),
                ("source_id", "0" * 64),
                ("namespace", str(namespace.parent)),
            ]:
                changed = copy.deepcopy(observed)
                changed[key] = value
                with self.assertRaises(RuntimeError):
                    selected_source(
                        changed,
                        pid=10,
                        session=record["session_id"],
                        namespace=namespace,
                    )

    def test_recovery_requires_original_intent_removal_and_matching_native_state(self):
        for change in [None, "pending", "state", "body", "progress"]:
            with (
                self.subTest(change=change),
                tempfile.TemporaryDirectory() as temporary,
            ):
                source, record, _, _, _, _, _ = self.fixture(Path(temporary))
                if change != "pending":
                    for path in source.source_snapshot:
                        path.unlink()
                source.witness_context = (
                    SimpleNamespace(snapshot=Path(temporary)),
                    None,
                    None,
                    None,
                )
                body = base64.b64encode(bytes.fromhex(record["data"])).decode()
                block = {
                    "boc": body
                    if change != "body"
                    else base64.b64encode(b"wrong").decode()
                }
                states = [
                    {"boc": "same"},
                    {"boc": "different" if change == "state" else "same"},
                ]
                recovered = {
                    "last_checkpoint": {"seqno": 5 if change == "progress" else 6}
                }
                with (
                    patch(
                        "publication_io_live_fixture.cpp_block",
                        new=AsyncMock(return_value=block),
                    ),
                    patch(
                        "publication_io_live_fixture.native_state",
                        new=AsyncMock(side_effect=states),
                    ),
                    patch(
                        "publication_io_live_fixture.asyncio.sleep",
                        side_effect=RuntimeError("still pending"),
                    ),
                ):
                    if change is None:
                        asyncio.run(source.complete(recovered))
                        self.assertTrue(
                            source.receipt["original_block_native_state_match"]
                        )
                    else:
                        with self.assertRaises(RuntimeError):
                            asyncio.run(source.complete(recovered))
