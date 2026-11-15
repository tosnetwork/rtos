"""Do not accept fabricated native failures or substituted recovered ACK data."""

import copy
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scenario_ack import ack_arguments, check_ack_evidence, check_ack_result


def fixture(root, mode="sync-eio", kind="acked"):
    original = {
        "session_id": "a" * 64,
        "block_id": {"seqno": 10},
        "data": "body",
        "signature_set": "certificate",
    }
    before = json.dumps(original).encode()
    digest = hashlib.sha256(before).hexdigest()
    reference = {
        "digest": digest,
        "metadata": {**original, "data": "", "signature_set": ""},
        "node_receipt": "b" * 64,
    }
    ack = (
        {"record": original, "node_receipt": "b" * 64}
        if kind == "acked"
        else {"reference": reference}
        if kind == "delivered"
        else reference
    )
    after = json.dumps(ack).encode()
    block = {"seqno": 20}
    receipt = {
        "phase": "recovered",
        "mode": mode,
        "member": 2,
        "recovery_limit_seconds": 180,
        "interruption_returncode": -9,
        "source_acknowledged_before_interruption": False,
        "pending_preserved_after_interruption": True,
        "pending_preserved_before_restart": True,
        "original_source_ack_recovered": True,
        "manual_database_repair": False,
        "elapsed_seconds": 20,
        "temporary_bytes": 10 if mode == "sync-eio" else 0,
        "old_pid": 10,
        "new_pid": 20,
        "new_start_ticks": "200",
        "pending_sha256": digest,
        "pending_bytes": len(before),
        "recovered_ack_sha256": hashlib.sha256(after).hexdigest(),
        "recovered_node_receipt": "b" * 64,
        "source_id": "c" * 64,
        "session": "a" * 64,
        "native_error_line": "Node WAL durable but source ACK needs retry: "
        + ("Input/output error" if mode == "sync-eio" else "No space left on device"),
        "recovered_ack_kind": kind,
        "final_checkpoint": block,
        "survivor_checkpoint": {"seqno": 12},
        "source_block": original["block_id"],
        "pending_directory": str(root / "pending"),
    }
    recovery = {
        "phase": "recovered",
        "member": 2,
        "interruption_returncode": -9,
        "manual_database_repair": False,
        "all_six_applied_states_match": True,
        "workchain_states_match": True,
        "successor_finality_checked": True,
        "old_process": {"pid": 10},
        "new_process": {"pid": 20, "start_ticks": "200"},
        "last_checkpoint": block,
        "survivor_checkpoint": {"seqno": 12},
        "vote": {"block": block},
        "leaders": {"masterchain": {}, "workchain": {}},
    }
    directory = root / "source-ack-fault"
    directory.mkdir()
    (directory / "retained-before.json").write_bytes(before)
    (directory / "recovered-ack.json").write_bytes(after)
    (directory / "disarmed").touch()
    (directory / "native-error.marker").write_text(
        f"source {mode}: {root / 'pending' / (receipt['source_id'] + '.ack.tmp')}\n"
    )
    return receipt, recovery


class AckTests(unittest.TestCase):
    def test_real_driver_recovery_duration(self):
        with TemporaryDirectory() as directory:
            receipt, recovery = fixture(Path(directory))
            receipt["recovery_limit_seconds"] = 180.0
            check_ack_result("source-ack-sync-eio", receipt, recovery)
            for invalid in (True, "180", None, 180.5, float("nan"), float("inf")):
                receipt["recovery_limit_seconds"] = invalid
                with self.assertRaises(ValueError):
                    check_ack_result("source-ack-sync-eio", receipt, recovery)

    def test_native_inputs_match_record_before_use(self):
        from types import SimpleNamespace

        from scenario_ack import ack_artifacts

        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "ci/interop"
            source.mkdir(parents=True)
            native = root / "rtos/src/tests/finality_source_fault.c"
            native.parent.mkdir(parents=True)
            native.write_bytes(b"source")
            library = root / "library.so"
            library.write_bytes(b"native-library")
            record = root / "build.json"
            meta = lambda p: {
                "bytes": p.stat().st_size,
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            }
            record.write_text(
                json.dumps(
                    {
                        "source": str(native),
                        "library": str(library),
                        "source_meta": meta(native),
                        "library_meta": meta(library),
                    }
                )
            )
            args = SimpleNamespace(
                source_ack_fault_library=library, source_ack_fault_build_record=record
            )
            self.assertEqual(ack_artifacts(args, source), [native, library, record])
            library.write_bytes(b"changed-library")
            with self.assertRaises(ValueError):
                ack_artifacts(args, source)
            with self.assertRaises(ValueError):
                ack_artifacts(SimpleNamespace(), source)

    def test_both_syscalls_and_all_recovered_representations(self):
        for mode in ("sync-eio", "write-enospc"):
            for kind in ("acked", "reference", "delivered"):
                with TemporaryDirectory() as directory:
                    root = Path(directory)
                    receipt, recovery = fixture(root, mode, kind)
                    check_ack_result("source-ack-" + mode, receipt, recovery)
                    check_ack_evidence(root, receipt)
                    args = ack_arguments("source-ack-" + mode, "/native/ack.so")
                    self.assertEqual(args[args.index("--source-ack-fault") + 1], mode)

    def test_native_failure_and_process_recovery_cannot_be_omitted(self):
        with TemporaryDirectory() as directory:
            original, recovery = fixture(Path(directory))
            for mutate in (
                lambda r: r.update(temporary_bytes=0),
                lambda r: r.update(elapsed_seconds=181),
                lambda r: r.update(new_pid=10),
                lambda r: r.update(new_start_ticks="stale"),
                lambda r: r.update(native_error_line="unrelated EIO"),
                lambda r: r.update(pending_preserved_before_restart=False),
                lambda r: r.update(source_acknowledged_before_interruption=True),
                lambda r: r.update(final_checkpoint={"seqno": 21}),
                lambda r: r.update(recovered_node_receipt="missing"),
            ):
                receipt = copy.deepcopy(original)
                mutate(receipt)
                with self.assertRaises(ValueError):
                    check_ack_result("source-ack-sync-eio", receipt, recovery)

    def test_changed_source_cannot_be_hidden_by_rehashing_recovered_ack(self):
        for kind in ("acked", "reference", "delivered"):
            with TemporaryDirectory() as directory:
                root = Path(directory)
                receipt, _ = fixture(root, kind=kind)
                p = root / "source-ack-fault/recovered-ack.json"
                ack = json.loads(p.read_text())
                if kind == "acked":
                    ack["record"]["block_id"]["seqno"] = 99
                else:
                    ref = ack["reference"] if kind == "delivered" else ack
                    ref["metadata"]["block_id"]["seqno"] = 99
                p.write_text(json.dumps(ack))
                receipt["recovered_ack_sha256"] = hashlib.sha256(
                    p.read_bytes()
                ).hexdigest()
                with self.assertRaises(ValueError):
                    check_ack_evidence(root, receipt)

    def test_other_target_and_armed_fault_refused(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            receipt, _ = fixture(root)
            p = root / "source-ack-fault/native-error.marker"
            original = p.read_text()
            p.write_text(original.replace("c" * 64, "d" * 64))
            with self.assertRaises(ValueError):
                check_ack_evidence(root, receipt)
            p.write_text(original)
            (p.parent / "armed").touch()
            with self.assertRaises(ValueError):
                check_ack_evidence(root, receipt)


if __name__ == "__main__":
    unittest.main()
