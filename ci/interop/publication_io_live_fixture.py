"""Observe an authenticated live acceptance; recover only from the original DB."""

import asyncio
import base64
import hashlib
import json
import os
import re
import signal
import struct
import time
from pathlib import Path

from mixed_matrix import child_checked, cpp_block, native_state, write
from network_faults import marked_environment, require_namespace
from source_ack_fault_fixture import SourceAckFailure


def sha(data):
    return hashlib.sha256(data).hexdigest()


def live_environment(args, root):
    require_namespace()
    if os.environ.get("LD_PRELOAD") or any(
        key.startswith(
            (
                "RTOS_TEST_PUBLICATION_IO_",
                "RTOS_TEST_RETAIN_CUT_",
                "RTOS_TEST_SOURCE_FAULT_",
            )
        )
        for key in os.environ
    ):
        raise RuntimeError("Live publication IO refuses inherited fault controls")
    control = root / "publication-io"
    control.mkdir(exist_ok=True)
    marked = marked_environment(args.socket_mark_library)
    return {
        **marked,
        "LD_PRELOAD": f"{args.publication_io_library}:{marked['LD_PRELOAD']}",
        "RTOS_TEST_PUBLICATION_IO_CONTROL": str(control.resolve()),
        "RTOS_TEST_PUBLICATION_IO_RETURN_EIO": "1",
    }


def selected_source(observed, *, pid, session, namespace):
    record = observed["record"]
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
    source_id = sha(
        json.dumps(identity, separators=(",", ":"), ensure_ascii=False).encode()
    )
    if (
        observed.get("schema") != 1
        or observed.get("pid") != pid
        or observed.get("is_custody_receipt") is not False
        or Path(observed["namespace"]).resolve() != namespace.resolve()
        or observed["source_id"] != source_id
        or record["schema"] != 1
        or record["session_id"] != session
        or record["is_final"] is not True
        or not record["block_id"].startswith("(-1:")
        or not record["data"]
        or not record["signature_set"]
    ):
        raise RuntimeError("Live observation changed selected request identity")
    return record, source_id


def bound_intents(namespace, record, selected):
    """Bind the pending Final certificate; MC outputs do not exist before accept."""
    directory = namespace / "finality-intents"
    path = Path(selected["path"])
    candidate = selected["candidate_hash"]
    slot = selected["slot"]
    if (
        type(slot) is not int
        or not 0 <= slot < 1 << 32
        or not re.fullmatch("[0-9a-f]{64}", candidate)
        or directory.is_symlink()
        or path.is_symlink()
        or path != directory / f"{slot}-{candidate}.json"
        or path.stat().st_size > 16 << 20
    ):
        raise RuntimeError("Unsafe selected pending Final intent")
    raw = path.read_bytes()
    cert = json.loads(raw)
    if (
        sha(raw) != selected["sha256"]
        or cert["slot"] != slot
        or cert["candidate_hash"] != candidate
        or cert["session_id"] != record["session_id"]
        or not cert["certificate"]
    ):
        raise RuntimeError("Live request does not bind its original Final certificate")
    return {path: raw}


def verify_body_artifact(path, selector, artifact):
    """Verify actual selected body bytes even when the durability fd is a package."""
    if artifact == "loose_block_body":
        raw = path.read_bytes()
        if sha(raw) != selector["block_sha256"]:
            raise RuntimeError("Loose body differs from selected acceptance")
        return {"kind": artifact, "bytes": len(raw), "sha256": sha(raw)}
    if artifact != "archive_package":
        raise RuntimeError("Unknown publication durability artifact")
    match = re.fullmatch(
        r"\((-?[0-9]+):([0-9a-f]{16}), ([0-9]+), rh ([0-9a-f]{64}), fh ([0-9a-f]{64})\)",
        selector["block_id"],
    )
    if match is None:
        raise RuntimeError("Invalid selected archive block identity")
    wc, shard, seq, root, file_hash = match.groups()
    expected = f"block_({wc},{shard},{seq}):{root.upper()}:{file_hash.upper()}".encode()
    length = path.stat().st_size
    with path.open("rb") as stream:
        if stream.read(4) != struct.pack("<I", 0xAE8FDD01):
            raise RuntimeError("Invalid archive package magic")
        for _ in range(4096):
            header = stream.read(8)
            if len(header) != 8:
                break
            magic, name_size, data_size = struct.unpack("<HHI", header)
            if magic != 0x1E8B or name_size > 4096:
                raise RuntimeError("Invalid archive entry header")
            name = stream.read(name_size)
            offset = stream.tell()
            if offset + data_size > length:
                raise RuntimeError("Incomplete archive entry")
            if name == expected:
                if data_size > 16 << 20:
                    raise RuntimeError("Selected archive body exceeds bound")
                body = stream.read(data_size)
                if sha(body) != selector["block_sha256"]:
                    raise RuntimeError("Archive body differs from selected acceptance")
                return {
                    "kind": artifact,
                    "entry": name.decode(),
                    "offset": offset,
                    "bytes": data_size,
                    "sha256": sha(body),
                }
            stream.seek(data_size, 1)
    raise RuntimeError("Selected body absent from bounded archive scan")


class LivePublicationIoSource(SourceAckFailure):
    def __init__(self, args, root, node, checkpoint):
        directory = root / "publication-io-source"
        directory.mkdir()
        super().__init__(args, root, node, checkpoint, directory=directory)
        self.io_directory = root / "publication-io"
        self.receipt.update(
            mode="live-acceptance-body-sync-eio",
            fault_mechanism="isolated observed live request, native EIO, original intent recovery; no propagation ACK",
        )
        self.save()

    def process_status(self):
        return Path("/proc", str(self.node["process"].pid), "status").read_text()

    def stopped(self):
        return any(
            line.startswith("State:") and line.split()[1] == "T"
            for line in self.process_status().splitlines()
        )

    async def arm(self):
        from publication_io_fixture import selector_for

        temporary = self.io_directory / "live-source-arm.tmp"
        write(
            temporary,
            {"pid": self.node["process"].pid, "session_id": self.receipt["session"]},
        )
        temporary.rename(self.io_directory / "live-source-arm.json")
        self.receipt["phase"] = "waiting_for_live_request"
        self.save()
        while True:
            self.check_budget()
            if self.node["process"].returncode is not None:
                raise RuntimeError("Live IO target exited before observation")
            path = self.io_directory / "live-source.json"
            if path.exists() and self.stopped():
                break
            await asyncio.sleep(0.02)
        observed = json.loads(path.read_text())
        namespace = self.pending_directory.parent
        record, self.source_id = selected_source(
            observed,
            pid=self.node["process"].pid,
            session=self.receipt["session"],
            namespace=namespace,
        )
        self.original = json.dumps(record, separators=(",", ":")).encode()
        self.source_snapshot = bound_intents(
            namespace, record, observed["finality_intent"]
        )
        for i, (source, raw) in enumerate(self.source_snapshot.items()):
            (self.directory / f"original-{i}.json").write_bytes(raw)
        self.receipt["original_intents"] = [
            {"path": str(p), "sha256": sha(raw), "bytes": len(raw)}
            for p, raw in self.source_snapshot.items()
        ]
        self.pending = next(iter(self.source_snapshot))
        self.selector = selector_for(record, self.source_id, self.node["process"].pid)
        temporary = self.io_directory / "selector.tmp"
        write(temporary, self.selector)
        temporary.rename(self.io_directory / "selector.json")
        self.disarm()
        self.node["process"].send_signal(signal.SIGCONT)
        self.receipt["phase"] = "waiting_for_native_body_sync_eio"
        self.save()
        while True:
            self.check_budget()
            if self.node["process"].returncode is not None:
                raise RuntimeError("Live IO node exited before selected EIO")
            if (self.io_directory / "failed.json").exists() and self.stopped():
                self.capture_failure()
                return
            await asyncio.sleep(0.02)

    def capture_failure(self):
        target_raw = (self.io_directory / "target.json").read_bytes()
        target = json.loads(target_raw)
        failed = json.loads((self.io_directory / "failed.json").read_text())
        marker = (self.io_directory / "native-error.marker").read_bytes()
        selector_raw = (self.io_directory / "selector.json").read_bytes()
        path = Path(target["path"])
        info = path.stat()
        publication = {
            "record_id": None,
            "node_receipt": None,
            "delivery_id": self.selector["delivery_id"],
            "stage": "LiveAcceptance",
        }
        expected = (
            f"publication sync-eio pid={self.node['process'].pid} tid={target['tid']} "
            f"syscall=(fsync|fdatasync) errno=5: {re.escape(str(path))}\\n"
        )
        if (
            not self.stopped()
            or target["schema"] != 1
            or target["selector"] != self.selector
            or target["selector_sha256"] != sha(selector_raw)
            or target["pid"] != self.node["process"].pid
            or target["publication"] != publication
            or path.is_symlink()
            or not path.resolve().is_relative_to(
                (self.node["directory"] / "node_db").resolve()
            )
            or target["device"] != info.st_dev
            or target["inode"] != info.st_ino
            or not re.fullmatch(expected, marker.decode())
            or failed["pid"] != target["pid"]
            or failed["publication"] != publication
            or failed["selector_sha256"] != sha(selector_raw)
            or failed["target_sha256"] != sha(target_raw)
            or failed["native_marker_sha256"] != sha(marker)
            or failed["typed_durability_failure"] is not True
            or failed["publication_owner_marked_fatal"] is not True
            or failed["accepted_callback_returned"] is not False
            or failed["retained_draft_verified"] is not False
            or "Input/output error (os error 5)" not in failed["error"]
        ):
            raise RuntimeError(
                "Live EIO evidence does not match the selected real acceptance"
            )
        body_witness = verify_body_artifact(path, self.selector, target["artifact"])
        self.check_source_snapshot()
        self.receipt.update(
            phase="native_node_body_sync_failure_observed",
            body_artifact=body_witness,
            node_io_target=target,
            node_observed_error=failed,
            original_intents_preserved=True,
            source_canonical_delivery_before_interruption=False,
            node_io_failure_before_callback=True,
        )
        self.save()

    def preserved_source_bytes(self):
        return self.source_snapshot[self.pending]

    def check_source_snapshot(self):
        if any(p.read_bytes() != raw for p, raw in self.source_snapshot.items()):
            raise RuntimeError("Original live intent changed before database restart")

    def disarm(self):
        path = self.io_directory / "live-source-arm.json"
        if path.exists():
            path.rename(self.io_directory / "live-source-disarmed.json")

    async def after_interruption(self):
        self.check_source_snapshot()
        await super().after_interruption()

    def environment(self):
        self.check_source_snapshot()
        return super().environment()

    async def complete(self, recovered):
        while any(p.exists() for p in self.source_snapshot):
            self.check_budget()
            if self.node["process"].returncode is not None:
                raise RuntimeError(
                    "Restarted node exited before original intent acceptance"
                )
            await asyncio.sleep(0.05)
        args, cpp_node, cpp_config, rust_config = self.witness_context
        match = re.fullmatch(
            r"\((-?[0-9]+):([0-9a-f]{16}), ([0-9]+), rh ([0-9a-f]{64}), fh ([0-9a-f]{64})\)",
            self.selector["block_id"],
        )
        if match is None:
            raise RuntimeError("Invalid selected block identity")
        wc, shard, seqno, root_hash, file_hash = match.groups()
        block = {
            "@type": "tos.blockIdExt",
            "workchain": int(wc),
            "shard": str(
                int(shard, 16) - (1 << 64)
                if int(shard, 16) >= 1 << 63
                else int(shard, 16)
            ),
            "seqno": int(seqno),
            "root_hash": base64.b64encode(bytes.fromhex(root_hash)).decode(),
            "file_hash": base64.b64encode(bytes.fromhex(file_hash)).decode(),
        }
        target = self.directory / "recovered-original-block"
        target.mkdir()

        async def witness():
            body = await cpp_block(args.snapshot, cpp_node, block, target)
            states = await asyncio.gather(
                native_state(
                    args.snapshot,
                    cpp_config,
                    "cpp-reference",
                    block,
                    target / "cpp-state",
                ),
                native_state(
                    args.snapshot,
                    rust_config,
                    "restarted-rust",
                    block,
                    target / "rust-state",
                ),
            )
            return body, states

        body, states = await asyncio.wait_for(
            witness(), self.deadline - time.monotonic()
        )
        if sha(base64.b64decode(body["boc"], validate=True)) != self.selector[
            "block_sha256"
        ] or recovered["last_checkpoint"]["seqno"] <= int(seqno):
            raise RuntimeError(
                "Original block/state recovery differs from native reference"
            )
        write(
            target / "witness.json",
            {"mode": "state-copies", "block": body, "states": states},
        )
        await asyncio.wait_for(
            child_checked(
                [args.block_checker, target / "witness.json", target / "checked.json"],
                target / "checker.log",
            ),
            self.deadline - time.monotonic(),
        )
        checked = json.loads((target / "checked.json").read_text())
        if (
            checked.get("mode") != "state-copies"
            or checked.get("block") != block
            or set(checked.get("sources", [])) != {"cpp-reference", "restarted-rust"}
            or checked.get("finality_checked") is not False
        ):
            raise RuntimeError("Original state-copy checker scope differs")
        self.check_budget()
        self.receipt.update(
            phase="recovered",
            original_intents_resolved=True,
            original_block_native_state_match=True,
            node_io_original_source_recovered=True,
            original_block=block,
            final_checkpoint=recovered["last_checkpoint"],
            manual_database_repair=False,
        )
        self.save()
