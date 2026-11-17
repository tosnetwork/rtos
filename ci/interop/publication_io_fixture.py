"""Bind a body fsync EIO to one retained Final source, then recover its original DB."""

import asyncio
import hashlib
import json
import os
import re
import signal
import struct
import time
from pathlib import Path

from mixed_matrix import write
from network_faults import marked_environment
from partition_restart_fixture import PartitionRestart
from source_ack_fault_fixture import SourceAckFailure
from source_ack_partition_fixture import join_owned
from source_retention_cut_fixture import SourceRetentionCut, retention_cut_environment


def publication_io_environment(args, root):
    if any(key.startswith("RTOS_TEST_PUBLICATION_IO_") for key in os.environ):
        raise RuntimeError("Publication IO refuses inherited controls")
    environment = retention_cut_environment(args, root)
    directory = root / "publication-io"
    directory.mkdir(exist_ok=True)
    marked = marked_environment(args.socket_mark_library)
    environment["LD_PRELOAD"] = (
        str(args.publication_io_library)
        + ":"
        + environment["LD_PRELOAD"]
        + ":"
        + marked["LD_PRELOAD"]
    )
    environment["RTOS_FIXTURE_SOCKET_MARK"] = marked["RTOS_FIXTURE_SOCKET_MARK"]
    environment["RTOS_TEST_RETAIN_CUT_RESUME_SYNCED"] = "1"
    environment["RTOS_TEST_PUBLICATION_IO_CONTROL"] = str(directory)
    environment["RTOS_TEST_PUBLICATION_IO_RETURN_EIO"] = "1"
    return environment


def delivery_coordinate_id(record):
    # Match the existing delivery_coordinates encoder, not the source-file ID.
    def block(value):
        match = re.fullmatch(
            r"\((-?[0-9]+):([0-9a-f]{16}), ([0-9]+), rh ([0-9a-f]{64}), fh ([0-9a-f]{64})\)",
            value,
        )
        if match is None:
            raise RuntimeError("Invalid full publication block ID")
        wc, shard, seqno, root, file_hash = match.groups()
        return struct.pack("<iQI", int(wc), int(shard, 16), int(seqno)) + bytes.fromhex(
            root + file_hash
        )

    data = b"RTOS-finality-delivery-v1" + block(record["zerostate"])
    data += struct.pack(
        "<iBB", record["global_id"], record["wire_profile"], record["protocol"]
    )
    data += bytes.fromhex(record["profile"] + record["session_id"]) + block(
        record["block_id"]
    )
    data += bytes([int(record["is_final"])])
    return hashlib.sha256(data).hexdigest()


def selector_for(record, source_id, pid):
    body = bytes.fromhex(record["data"])
    if (
        not record["is_final"]
        or not body
        or not re.fullmatch("[0-9a-f]{64}", source_id)
    ):
        raise RuntimeError("Publication IO requires the original complete Final source")
    return {
        "schema": 1,
        "pid": pid,
        "session_id": record["session_id"],
        "block_id": record["block_id"],
        "block_sha256": hashlib.sha256(body).hexdigest(),
        "source_id": source_id,
        "delivery_id": delivery_coordinate_id(record),
    }


class PublicationIoSource(SourceRetentionCut):
    async def arm(self):
        await super().arm()  # Exact fully synced source, before its normal rename.
        self.io_directory = self.directory.parent / "publication-io"
        record = json.loads(self.original)
        selector = selector_for(record, self.source_id, self.node["process"].pid)
        temporary = self.io_directory / "selector.tmp"
        write(temporary, selector)
        temporary.rename(self.io_directory / "selector.json")
        self.disarm()  # Only this complete-retain fixture may resume after SIGCONT.
        self.node["process"].send_signal(signal.SIGCONT)
        self.receipt.update(
            phase="waiting_for_node_body_sync_failure",
            retain_resumed_at_unix=time.time(),
            fault_mechanism="test-only native EIO at exact authenticated Final acceptance body sync; stopped before callback; not physical media failure",
        )
        self.save()
        marker = self.io_directory / "native-error.marker"
        while True:
            self.check_budget()
            if self.node["process"].returncode is not None:
                raise RuntimeError("Node exited before selected acceptance body sync")
            if (
                marker.exists()
                and (self.io_directory / "failed.json").exists()
                and self.stopped()
            ):
                self.capture_io_failure(marker, selector)
                return
            await asyncio.sleep(0.02)

    def capture_io_failure(self, marker, selector):
        target = json.loads((self.io_directory / "target.json").read_text())
        selected_bytes = (self.io_directory / "selector.json").read_bytes()
        failed = json.loads((self.io_directory / "failed.json").read_text())
        if (
            failed["pid"] != self.node["process"].pid
            or not failed["typed_durability_failure"]
            or not failed["publication_owner_marked_fatal"]
            or failed["accepted_callback_returned"]
            or failed["selector_sha256"] != hashlib.sha256(selected_bytes).hexdigest()
            or failed["target_sha256"]
            != hashlib.sha256(
                (self.io_directory / "target.json").read_bytes()
            ).hexdigest()
            or failed["native_marker_sha256"]
            != hashlib.sha256(marker.read_bytes()).hexdigest()
            or "Input/output error (os error 5)" not in failed["error"]
        ):
            raise RuntimeError(
                "Node did not observe selected EIO and mark its publication owner fatal"
            )
        path = Path(target["path"])
        database = (self.node["directory"] / "node_db").resolve()
        info = path.stat()
        expected = (
            f"publication sync-eio pid={self.node['process'].pid} tid={target['tid']} "
            f"syscall=(fsync|fdatasync) errno=5: {re.escape(str(path))}\n"
        )
        if (
            not self.stopped()
            or not re.fullmatch(expected, marker.read_text())
            or target["schema"] != 1
            or target["selector"] != selector
            or target["selector_sha256"] != hashlib.sha256(selected_bytes).hexdigest()
            or target["pid"] != self.node["process"].pid
            or target["artifact"] != "loose_block_body"
            or not path.is_relative_to(database)
            or path.is_symlink()
            or target["device"] != info.st_dev
            or target["inode"] != info.st_ino
            or hashlib.sha256(path.read_bytes()).hexdigest() != selector["block_sha256"]
        ):
            raise RuntimeError(
                "Native acceptance cut does not match exact owned worker/body identity"
            )
        publication = target["publication"]
        if (
            publication != failed["publication"]
            or publication["node_receipt"] != selector["delivery_id"]
            or publication["stage"] != "DraftDurable"
            or not failed["retained_draft_verified"]
        ):
            raise RuntimeError("Failed acceptance lost its exact retained WAL draft")
        if self.pending.exists():
            raise RuntimeError(
                "Complete source retain did not resume its normal commit"
            )
        pending = self.pending.with_suffix(".json")
        ack = pending.with_suffix(".acked")
        self.source_snapshot = {}
        for path in [pending, ack]:
            if not path.exists():
                continue
            raw = path.read_bytes()
            if path == pending:
                if raw != self.original:
                    raise RuntimeError("Committed source bytes changed")
            else:
                value = json.loads(raw)
                if (
                    value["record"] != json.loads(self.original)
                    or value["node_receipt"] != selector["delivery_id"]
                ):
                    raise RuntimeError(
                        "WAL handoff ACK differs from exact original source/delivery"
                    )
                (self.io_directory / "wal-handoff-acked.json").write_bytes(raw)
            self.source_snapshot[path] = raw
        reference_path = (
            self.pending_directory / "references-v1" / (self.source_id + ".reference")
        )
        if reference_path.exists():
            raw = reference_path.read_bytes()
            value = json.loads(raw)
            valid, reference = SourceAckFailure.matches_recovered_source(
                self, "reference", value, json.loads(self.original)
            )
            if not valid or reference["node_receipt"] != selector["delivery_id"]:
                raise RuntimeError(
                    "Canonical WAL custody reference differs from exact full draft"
                )
            self.source_snapshot[reference_path] = raw
            (self.io_directory / "source-reference-before.json").write_bytes(raw)
        if not self.source_snapshot:
            raise RuntimeError("Failed acceptance lost its source and full WAL custody")
        self.pending = next(iter(self.source_snapshot))
        self.preserved_bytes = self.source_snapshot[self.pending]
        self.expected_node_receipt = selector["delivery_id"]
        for path in [
            pending.with_suffix(".ack.tmp"),
            self.pending_directory / "references-v1" / (self.source_id + ".delivered"),
        ]:
            if path.exists():
                raise RuntimeError(
                    "Failed acceptance already published canonical delivery"
                )
        (self.io_directory / "stopped-process-status.txt").write_text(
            self.process_status()
        )
        self.receipt.update(
            phase="native_node_body_sync_failure_observed",
            node_io_target=target,
            source_pending_committed_before_interruption=True,
            source_acknowledged_before_interruption=ack in self.source_snapshot,
            source_ack_scope="full node WAL handoff only, not block acceptance",
            source_custody_before=[
                {
                    "path": str(path),
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
                for path, raw in self.source_snapshot.items()
            ],
            source_canonical_delivery_before_interruption=False,
            node_io_failure_before_callback=True,
            node_observed_error=failed,
            native_error_observed_at_unix=time.time(),
        )
        self.save()

    # At the second cut the source is committed. Reuse the exact committed-source
    # recovery contract, not the uncommitted-retain reconstruction contract.
    def preserved_source_bytes(self):
        return self.preserved_bytes

    def check_source_snapshot(self):
        if any(path.read_bytes() != raw for path, raw in self.source_snapshot.items()):
            raise RuntimeError("Full source custody changed before original-DB restart")

    async def after_interruption(self):
        self.check_source_snapshot()
        await SourceAckFailure.after_interruption(self)

    def environment(self):
        self.check_source_snapshot()
        return SourceAckFailure.environment(self)

    def has_unacknowledged_source(self):
        return SourceAckFailure.has_unacknowledged_source(self)

    async def complete(self, recovered):
        # A source .acked only proves the earlier full-WAL handoff. Wait for
        # normal accepted/canonical delivery, never count that ACK as recovery.
        delivered = (
            self.pending_directory / "references-v1" / (self.source_id + ".delivered")
        )
        while True:
            self.check_budget()
            if self.node["process"].returncode is not None:
                raise RuntimeError("Recovered node exited before canonical delivery")
            if delivered.exists():
                raw = delivered.read_bytes()
                value = json.loads(raw)
                if (
                    value.get("schema") != 1
                    or type(value.get("generation")) is not int
                    or value["generation"] <= 0
                ):
                    raise RuntimeError("Malformed canonical delivered closing proof")
                if value.get("node_confirmed") is not True:
                    await asyncio.sleep(0.05)
                    continue
                valid, reference = SourceAckFailure.matches_recovered_source(
                    self, "delivered", value, json.loads(self.original)
                )
                if not valid or reference["node_receipt"] != self.expected_node_receipt:
                    raise RuntimeError(
                        "Recovered canonical delivery differs from exact original source"
                    )
                if not any(path.exists() for path in self.source_snapshot):
                    (self.io_directory / "recovered-canonical.json").write_bytes(raw)
                    self.receipt.update(
                        phase="recovered",
                        recovered_ack_kind="delivered",
                        recovered_ack_sha256=hashlib.sha256(raw).hexdigest(),
                        recovered_node_receipt=reference["node_receipt"],
                        final_checkpoint=recovered["last_checkpoint"],
                        original_source_canonical_delivery_recovered=True,
                        node_io_original_source_recovered=True,
                        canonical_node_confirmed=True,
                        canonical_close_generation=value["generation"],
                        manual_database_repair=False,
                    )
                    self.save()
                    return
            await asyncio.sleep(0.05)


class PublicationIoRestart:
    def __init__(self, args, root, node, endpoint, member_id, checkpoint):
        self.source = PublicationIoSource(args, root, node, checkpoint)
        self.partition = PartitionRestart(args, root, node, endpoint, member_id)
        self.started = self.source.started
        self.deadline = self.source.deadline
        self.partition.started = self.started
        self.partition.deadline = self.deadline
        self.partition.receipt["budget_started_at_unix"] = self.source.receipt[
            "budget_started_at_unix"
        ]
        self.directory = root / "publication-io"
        self.receipt = {
            "phase": "prepared",
            "mode": "node_body_sync_eio_and_partition_restart",
            "member": args.interrupt_rust_member,
            "recovery_limit_seconds": args.recovery_timeout,
            "budget_started_at_unix": self.source.receipt["budget_started_at_unix"],
        }
        self.save()

    def save(self):
        self.receipt.update(
            elapsed_seconds=time.monotonic() - self.started,
            source_phase=self.source.receipt["phase"],
            partition_phase=self.partition.receipt["phase"],
        )
        write(self.directory / "receipt.json", self.receipt)

    async def arm(self):
        await self.source.arm()
        await self.partition.arm()
        self.receipt["phase"] = "node_io_failed_and_partitioned"
        self.save()

    async def after_interruption(self):
        await join_owned(
            self.source.after_interruption(), self.partition.after_interruption()
        )
        self.receipt["phase"] = "waiting_for_survivors"
        self.save()

    def survivor(self, checked):
        self.source.survivor(checked)
        self.partition.survivor(checked)
        self.save()

    def environment(self):
        if self.source.environment() is not None:
            raise RuntimeError("Restart must remove node IO controls")
        environment = self.partition.environment()
        if any(
            key.startswith(("RTOS_TEST_PUBLICATION_IO_", "RTOS_TEST_RETAIN_CUT_"))
            for key in environment
        ):
            raise RuntimeError("Restart inherited node IO controls")
        self.save()
        return environment

    async def after_restart(self, node):
        await self.source.after_restart(node)
        await self.partition.after_restart(node)
        self.save()

    async def complete(self, recovered):
        await self.source.complete(recovered)
        await self.partition.complete(recovered)
        self.receipt["phase"] = "recovered"
        self.save()

    def close(self):
        try:
            self.partition.close()
        finally:
            self.source.close()
            self.save()
