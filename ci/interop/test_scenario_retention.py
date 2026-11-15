"""Retention proof binds interrupted prefixes and reconstructed source records."""

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scenario_retention import check_retention_evidence
from test_scenario_ack import fixture as base_ack_fixture


def ack_fixture(root):
    receipt, recovery = base_ack_fixture(root)
    directory = root / "source-ack-fault"
    record = json.loads((directory / "retained-before.json").read_bytes())
    record.update(
        schema=1,
        global_id=4,
        zerostate="zero",
        protocol=2,
        carrier_version=1,
        wire_profile="wire",
        profile="profile",
        is_final=True,
        local_adnl="local",
        local_validator_index=0,
        source_validator="source",
    )
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
        record["is_final"],
        [
            record["local_adnl"],
            record["local_validator_index"],
            record["source_validator"],
        ],
    ]
    receipt["source_id"] = hashlib.sha256(
        json.dumps(identity, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    raw = json.dumps(record).encode()
    (directory / "retained-before.json").write_bytes(raw)
    recovered = json.dumps(
        {"record": record, "node_receipt": receipt["recovered_node_receipt"]}
    ).encode()
    (directory / "recovered-ack.json").write_bytes(recovered)
    receipt.update(
        pending_bytes=len(raw),
        pending_sha256=hashlib.sha256(raw).hexdigest(),
        recovered_ack_sha256=hashlib.sha256(recovered).hexdigest(),
    )
    (directory / "stopped-process-status.txt").write_text("State:\tT (stopped)\n")
    return receipt, recovery


class RetentionTests(unittest.TestCase):
    def test_all_cut_points_and_substitution(self):
        for point in ("before-write", "after-partial-write", "after-fsync"):
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                receipt, _ = ack_fixture(root)
                directory = root / "source-retention-cut"
                (root / "source-ack-fault").rename(directory)
                original = (directory / "retained-before.json").read_bytes()
                temporary = (
                    b""
                    if point == "before-write"
                    else original[: len(original) // 2]
                    if point == "after-partial-write"
                    else original
                )
                receipt.update(
                    mode="retain-" + point,
                    interrupted_retention_recovered=True,
                    retention_uncommitted_after_interruption=True,
                    retention_uncommitted_before_restart=True,
                    source_pending_committed_before_interruption=False,
                    stopped_state_verified=True,
                    stopped_pid=10,
                    temporary_bytes=len(temporary),
                    temporary_sha256=hashlib.sha256(temporary).hexdigest(),
                )
                (directory / "temporary-before.bin").write_bytes(temporary)
                target = Path(receipt["pending_directory"]) / (
                    receipt["source_id"] + ".tmp"
                )
                (directory / "native-stop.marker").write_text(
                    f"source retain-{point} pid=10: {target}\n"
                )
                # The three replay hints are present in real retained records.
                if point != "after-fsync":
                    record = json.loads(original)
                    record.update(
                        created_at_unix_secs=1,
                        last_mc_finalized_seqno=2,
                        candidate_already_sent=False,
                    )
                    original = json.dumps(record).encode()
                    temporary = (
                        b""
                        if point == "before-write"
                        else original[: len(original) // 2]
                    )
                    (directory / "retained-before.json").write_bytes(original)
                    (directory / "temporary-before.bin").write_bytes(temporary)
                    completed = json.dumps(
                        {
                            "record": {**record, "created_at_unix_secs": 9},
                            "node_receipt": receipt["recovered_node_receipt"],
                        }
                    ).encode()
                    (directory / "recovered-ack.json").write_bytes(completed)
                    receipt.update(
                        pending_bytes=len(original),
                        pending_sha256=hashlib.sha256(original).hexdigest(),
                        temporary_bytes=len(temporary),
                        temporary_sha256=hashlib.sha256(temporary).hexdigest(),
                        recovered_ack_sha256=hashlib.sha256(completed).hexdigest(),
                    )
                check_retention_evidence(root, receipt, point)
                original_id = receipt["source_id"]
                receipt["source_id"] = "0" * 64
                marker = directory / "native-stop.marker"
                original_marker = marker.read_text()
                marker.write_text(
                    original_marker.replace(original_id, receipt["source_id"])
                )
                with self.assertRaisesRegex(ValueError, "identity"):
                    check_retention_evidence(root, receipt, point)
                receipt["source_id"] = original_id
                marker.write_text(original_marker)
                p = directory / "recovered-ack.json"
                good = p.read_bytes()
                bad = json.loads(good)
                bad["record"]["data"] = "changed"
                raw = json.dumps(bad).encode()
                p.write_bytes(raw)
                receipt["recovered_ack_sha256"] = hashlib.sha256(raw).hexdigest()
                with self.assertRaisesRegex(ValueError, "substituted"):
                    check_retention_evidence(root, receipt, point)


class RetentionAdapterTests(unittest.TestCase):
    def test_semantic_receipt_and_recovery_identity(self):
        import copy

        from scenario_execution import check_result
        from scenario_retention import RETENTIONS, retention_arguments
        from test_scenario_execution import rotation_result
        from test_scenario_restart import fixture as restart_fixture

        for name, point in RETENTIONS.items():
            _, recovery = restart_fixture()
            receipt = {
                "member": 2,
                "mode": "retain-" + point,
                "phase": "recovered",
                "interruption_returncode": -9,
                "manual_database_repair": False,
                "pending_preserved_after_interruption": True,
                "pending_preserved_before_restart": True,
                "original_source_ack_recovered": True,
                "interrupted_retention_recovered": True,
                "source_pending_committed_before_interruption": False,
                "retention_uncommitted_after_interruption": True,
                "retention_uncommitted_before_restart": True,
                "recovery_limit_seconds": 180.0,
                "elapsed_seconds": 22.0,
                "old_pid": 10,
                "new_pid": 20,
                "stopped_pid": 10,
                "new_start_ticks": "200",
                "final_checkpoint": recovery["last_checkpoint"],
                "survivor_checkpoint": recovery["survivor_checkpoint"],
            }
            result = rotation_result()
            result.update(source_retention_cut=receipt, recovery=recovery)
            check_result(name, result)
            args = retention_arguments(name, "/retention.so")
            self.assertEqual(args[-1], point)
            for key, value in [
                ("new_pid", 30),
                ("recovery_limit_seconds", 181),
                ("elapsed_seconds", float("nan")),
                ("pending_preserved_after_interruption", False),
            ]:
                changed = copy.deepcopy(result)
                changed["source_retention_cut"][key] = value
                with self.assertRaises(ValueError):
                    check_result(name, changed)
            with self.assertRaises(ValueError):
                check_result("rotation-mixed", result)

    def test_reference_and_delivered_preserve_original_body_digest(self):
        for point in ("before-write", "after-partial-write", "after-fsync"):
            for kind in ("reference", "delivered"):
                with TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    receipt, _ = ack_fixture(root)
                    directory = root / "source-retention-cut"
                    (root / "source-ack-fault").rename(directory)
                    record = json.loads(
                        (directory / "retained-before.json").read_bytes()
                    )
                    record.update(
                        created_at_unix_secs=1,
                        last_mc_finalized_seqno=2,
                        candidate_already_sent=False,
                    )
                    original = json.dumps(
                        record, separators=(",", ":"), ensure_ascii=False
                    ).encode()
                    after = (
                        {**record, "created_at_unix_secs": 9}
                        if point != "after-fsync"
                        else record
                    )
                    expected = json.dumps(
                        after, separators=(",", ":"), ensure_ascii=False
                    ).encode()
                    reference = {
                        "metadata": {**after, "data": "", "signature_set": ""},
                        "digest": hashlib.sha256(expected).hexdigest(),
                        "node_receipt": receipt["recovered_node_receipt"],
                    }
                    recovered = json.dumps(
                        {"reference": reference} if kind == "delivered" else reference
                    ).encode()
                    temporary = (
                        b""
                        if point == "before-write"
                        else original[: len(original) // 2]
                        if point == "after-partial-write"
                        else original
                    )
                    receipt.update(
                        mode="retain-" + point,
                        interrupted_retention_recovered=True,
                        retention_uncommitted_after_interruption=True,
                        retention_uncommitted_before_restart=True,
                        source_pending_committed_before_interruption=False,
                        stopped_state_verified=True,
                        stopped_pid=10,
                        recovered_ack_kind=kind,
                    )
                    for raw, name, size, digest in [
                        (
                            original,
                            "retained-before.json",
                            "pending_bytes",
                            "pending_sha256",
                        ),
                        (
                            temporary,
                            "temporary-before.bin",
                            "temporary_bytes",
                            "temporary_sha256",
                        ),
                    ]:
                        (directory / name).write_bytes(raw)
                        receipt[size] = len(raw)
                        receipt[digest] = hashlib.sha256(raw).hexdigest()
                    (directory / "recovered-ack.json").write_bytes(recovered)
                    receipt["recovered_ack_sha256"] = hashlib.sha256(
                        recovered
                    ).hexdigest()
                    target = Path(receipt["pending_directory"]) / (
                        receipt["source_id"] + ".tmp"
                    )
                    (directory / "native-stop.marker").write_text(
                        f"source retain-{point} pid=10: {target}\n"
                    )
                    check_retention_evidence(root, receipt, point)
                    reference["digest"] = "0" * 64
                    recovered = json.dumps(
                        {"reference": reference} if kind == "delivered" else reference
                    ).encode()
                    (directory / "recovered-ack.json").write_bytes(recovered)
                    receipt["recovered_ack_sha256"] = hashlib.sha256(
                        recovered
                    ).hexdigest()
                    with self.assertRaisesRegex(ValueError, "substituted"):
                        check_retention_evidence(root, receipt, point)


class RetentionInputTests(unittest.TestCase):
    def test_build_record_binds_native_source_and_library(self):
        from types import SimpleNamespace

        from scenario_retention import retention_artifacts

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "ci/interop"
            source.mkdir(parents=True)
            native = root / "rtos/src/tests/finality_retention_cut.c"
            native.parent.mkdir(parents=True)
            native.write_bytes(b"native-source")
            library = root / "retention.so"
            library.write_bytes(b"library")
            record = root / "build.json"

            def meta(path):
                return {
                    "bytes": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }

            build = {
                "source": str(native),
                "library": str(library),
                "source_meta": meta(native),
                "library_meta": meta(library),
            }
            record.write_text(json.dumps(build))
            args = SimpleNamespace(
                source_retention_cut_library=library,
                source_retention_cut_build_record=record,
            )
            self.assertEqual(
                retention_artifacts(args, source), [native, library, record]
            )
            for path in (native, library):
                original = path.read_bytes()
                path.write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    retention_artifacts(args, source)
                path.write_bytes(original)
            build["source"] = str(root / "other.c")
            record.write_text(json.dumps(build))
            with self.assertRaises(ValueError):
                retention_artifacts(args, source)
            with self.assertRaises(ValueError):
                retention_artifacts(SimpleNamespace(), source)
