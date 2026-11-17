"""Cut the first MC intent of an owned node, then reopen its original directory."""

import asyncio
import hashlib
import json
import os
import re
import time
from pathlib import Path

from network_faults import require_namespace
from runtime_manifest_observer import read_starting_manifest


def validate_first_intent_cut(args):
    if not getattr(args, "first_intent_cut_library", None):
        return
    conflicts = [
        "interrupt_rust_member",
        "source_ack_fault",
        "source_ack_intent_stop",
        "source_retention_cut_library",
        "partition_restart",
        "network_fault",
        "additional_network_faults",
        "signer_expiry_member",
        "expired_member_restart",
        "followup_intent_frontier",
        "prepare_genesis_only",
    ]
    if not args.rust_node or any(getattr(args, name, None) for name in conflicts):
        raise ValueError(
            "First-intent cut requires an owned Rust node and a separate recovery case"
        )
    if args.recovery_timeout != 180:
        raise ValueError("First-intent cut retains the original 180-second deadline")


class FirstIntentCut:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.directory = root / "first-intent-cut"
        self.directory.mkdir()
        self.receipt = {
            "member": 2,
            "phase": "prepared",
            "point": args.first_intent_cut_point,
            "recovery_limit_seconds": 180,
            "manual_database_repair": False,
            "prior_complete_intents": 0,
            "normal_replay_completed": False,
        }
        self.save()

    def save(self):
        (self.directory / "receipt.json").write_text(
            json.dumps(self.receipt, indent=2) + "\n"
        )

    def environment(self):
        require_namespace()
        if os.environ.get("LD_PRELOAD") or any(
            k.startswith("RTOS_TEST_SOURCE_") for k in os.environ
        ):
            raise RuntimeError("First-intent cut refuses inherited fault controls")
        return {
            **os.environ,
            "LD_PRELOAD": str(self.args.first_intent_cut_library),
            "RTOS_TEST_SOURCE_FAULT_DIRECTORY_FILE": str(
                self.directory / "selected-directory"
            ),
            "RTOS_TEST_SOURCE_INTENT_ARM": str(self.directory / "armed"),
            "RTOS_TEST_SOURCE_INTENT_MARKER": str(
                self.directory / "native-stop.marker"
            ),
            "RTOS_TEST_SOURCE_INTENT_POINT": self.args.first_intent_cut_point,
            "RTOS_TEST_SOURCE_INTENT_INTENDED": str(self.directory / "intended.json"),
        }

    def check_budget(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError(
                "First-intent recovery exceeded its original 180-second deadline"
            )

    async def supervise(self, node, start_node):
        self.started = time.monotonic()
        self.deadline = self.started + 180
        self.receipt.update(
            budget_started_at_unix=time.time(), phase="waiting_for_initial_mc_source"
        )
        self.save()
        base = node["directory"] / "node_db/catchains/consensus/v2"
        selected = None
        while selected is None:
            self.check_budget()
            for manifest in base.glob("*/session-runtime.json"):
                value = read_starting_manifest(manifest)
                if value is None:
                    continue
                if (
                    value["shard_workchain"],
                    value["catchain_seqno"],
                    value["role"],
                ) == (-1, 0, "validator"):
                    selected = manifest.parent
                    break
            if selected is None:
                if node["process"].returncode is not None:
                    raise RuntimeError(
                        "First-intent target exited before source selection"
                    )
                await asyncio.sleep(0.01)
        intent_directory = selected / "finality-intents"
        if list(intent_directory.glob("*-*.json")) or list(
            intent_directory.glob("completed-v1/*.complete")
        ):
            raise RuntimeError(
                "Initial MC source already retained an intent; first-cut coverage missed"
            )
        (self.directory / "selected-directory").write_text(
            str(selected / "finality-pending") + "\n"
        )
        (self.directory / "armed").write_text(
            "first exact initial MC intent of owned member2\n"
        )
        marker = self.directory / "native-stop.marker"
        old = node["process"]
        while not marker.exists():
            self.check_budget()
            if old.returncode is not None:
                raise RuntimeError("First-intent target exited before native stop")
            await asyncio.sleep(0.01)
        while True:
            self.check_budget()
            status = Path(f"/proc/{old.pid}/status").read_text()
            if any(
                l.startswith("State:") and l.split()[1] == "T"
                for l in status.splitlines()
            ):
                break
            await asyncio.sleep(0.01)
        match = re.fullmatch(
            r"intent (before-write|after-partial-write) pid=(\d+): (.+)\n",
            marker.read_text(),
        )
        if (
            not match
            or match[1] != self.args.first_intent_cut_point
            or int(match[2]) != old.pid
        ):
            raise RuntimeError(
                "First-intent native marker differs from owned process/cut"
            )
        target = Path(match[3])
        if target.parent != intent_directory:
            raise RuntimeError("First-intent cut reached a different namespace")
        raw, intended = (
            target.read_bytes(),
            (self.directory / "intended.json").read_bytes(),
        )
        from verify_intent_cut_evidence import verify_written_prefix

        verify_written_prefix(raw, intended, self.args.first_intent_cut_point)
        record = json.loads(intended)
        if target.name != f"{record['slot']}-{record['candidate_hash']}.tmp":
            raise RuntimeError("First-intent filename differs from intended identity")
        paths = (
            list(intent_directory.glob("*-*.json"))
            + list(intent_directory.glob("*-*.tmp"))
            + list(intent_directory.glob("*-*.resolved"))
            + list(intent_directory.glob("completed-v1/*.complete"))
        )
        if paths != [target]:
            raise RuntimeError(
                "First-intent source contains other retained/completed intents"
            )
        inventory = []
        for path in sorted(intent_directory.rglob("*")):
            if path.is_symlink():
                raise RuntimeError(
                    "First-intent directory contains an unexpected symlink"
                )
            if path.is_file():
                data = path.read_bytes()
                inventory.append(
                    {
                        "path": str(path.relative_to(intent_directory)),
                        "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
        if [entry["path"] for entry in inventory] != [target.name]:
            raise RuntimeError(
                "First-intent directory has additional physical evidence"
            )
        inventory_bytes = (json.dumps(inventory, indent=2) + "\n").encode()
        (self.directory / "intent-directory-at-stop.json").write_bytes(inventory_bytes)
        context = selected / "finality-session-start.json"
        start = json.loads(context.read_text())
        if start != {
            k: v
            for k, v in record.items()
            if k not in ["slot", "candidate_hash", "certificate"]
        }:
            raise RuntimeError(
                "Durable start locator differs from first intended record"
            )
        for name, data in [
            ("intent-before.json", raw),
            ("session-start.json", context.read_bytes()),
            ("session-runtime.json", (selected / "session-runtime.json").read_bytes()),
            ("stopped-process.txt", status.encode()),
        ]:
            (self.directory / name).write_bytes(data)
        sha = lambda data: hashlib.sha256(data).hexdigest()
        prepared = node["directory"] / "validator-prepared.json"
        prepared_bytes = prepared.read_bytes()
        self.receipt.update(
            phase="stopped_first_intent",
            path=str(target),
            namespace=str(selected),
            old_process={"pid": old.pid, "start_ticks": node["start_ticks"]},
            bytes=len(raw),
            intended_bytes=len(intended),
            sha256=sha(raw),
            intended_sha256=sha(intended),
            session_start_sha256=sha(context.read_bytes()),
            session=record["session_id"],
            slot=record["slot"],
            candidate_hash=record["candidate_hash"],
            prepared_sha256=sha(prepared_bytes),
            stopped_state_verified=True,
            stopped_directory_inventory_sha256=sha(inventory_bytes),
            stopped_at_unix=time.time(),
        )
        self.save()
        node["first_intent_restarting"] = True
        try:
            old.kill()
            code = await asyncio.wait_for(old.wait(), 10)
            if (
                code != -9
                or target.read_bytes() != raw
                or prepared.read_bytes() != prepared_bytes
            ):
                raise RuntimeError(
                    "First-intent interruption changed original bytes/config"
                )
            (self.directory / "armed").rename(self.directory / "disarmed")
            node.update(
                await start_node(
                    self.args.rust_node, node["directory"], "node-restart.log"
                )
            )
            self.receipt.update(
                phase="waiting_for_normal_completion",
                interruption_returncode=code,
                restarted_at_unix=time.time(),
                new_process={
                    "pid": node["process"].pid,
                    "start_ticks": node["start_ticks"],
                },
                pending_preserved_before_restart=True,
            )
            self.save()
        finally:
            node["first_intent_restarting"] = False
        proof = intent_directory / "completed-v1" / target.with_suffix(".complete").name
        while not proof.exists():
            self.check_budget()
            if node["process"].returncode is not None:
                raise RuntimeError(
                    "Restarted first-intent target exited before normal completion"
                )
            await asyncio.sleep(0.05)
        completed = proof.read_bytes()
        if (
            json.loads(completed) != {"schema": 1, "record": record}
            or target.exists()
            or target.with_suffix(".json").exists()
        ):
            raise RuntimeError(
                "First-intent normal completion differs from original intended record"
            )
        if (
            prepared.read_bytes() != prepared_bytes
            or context.read_bytes()
            != (self.directory / "session-start.json").read_bytes()
        ):
            raise RuntimeError(
                "First-intent restart changed authority or session start"
            )
        self.check_budget()
        (self.directory / "intent-completed.json").write_bytes(completed)
        self.receipt.update(
            phase="normal_replay_completed",
            normal_replay_completed=True,
            elapsed_seconds=time.monotonic() - self.started,
            completed_sha256=sha(completed),
        )
        self.save()

    def observe_vote(self, checked, directory, member):
        from first_intent_vote import post_restart_successor_vote

        if "post_restart_vote" in self.receipt:
            return
        restarted = self.receipt.get("restarted_at_unix")
        if not post_restart_successor_vote(checked, member, restarted):
            return
        self.check_budget()
        witness = directory / "epoch-checked.json"
        raw = witness.read_bytes()
        if json.loads(raw) != checked:
            raise RuntimeError("First-intent vote differs from raw checked evidence")
        self.receipt["post_restart_vote"] = {
            "validator_id": member,
            "block": checked["block"],
            "sample_directory": str(directory),
            "checked_sha256": hashlib.sha256(raw).hexdigest(),
            "check": checked,
        }
        self.save()

    def qualify_rotation(self, epochs, member):
        self.check_budget()
        if not self.receipt["normal_replay_completed"]:
            raise RuntimeError("First-intent normal replay has not completed")
        for kind in ["mc_creators", "wc_creators"]:
            entry = epochs["after"][kind][member]
            if entry["local_collation_log"] != "node-restart.log":
                raise RuntimeError(
                    "First-intent acceptance lacks post-restart successor collation"
                )
        if "post_restart_vote" not in self.receipt:
            return False
        self.receipt.update(
            phase="rotation_and_first_intent_recovery_verified",
            successor_mc_wc_post_restart_creators=True,
            verified_post_restart_vote=True,
            all_six_mc_four_wc_states_match=True,
            total_acceptance_elapsed_seconds=time.monotonic() - self.started,
        )
        self.save()
        return True
