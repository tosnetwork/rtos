#!/usr/bin/env python3
"""Owned-node restart while its packet partition remains in place."""

import asyncio
import json
import time
import urllib.error
from pathlib import Path

from mixed_matrix import rpc, write
from network_faults import PacketFault, marked_environment


async def hold(seconds, deadline, check):
    end = time.monotonic() + seconds
    while True:
        check()
        now = time.monotonic()
        if now >= deadline:
            raise TimeoutError(
                "Partition restart exceeded the original recovery deadline"
            )
        if now >= end:
            return
        await asyncio.sleep(min(0.2, end - now, deadline - now))


class PartitionRestart:
    def __init__(self, args, root, node, endpoint, member_id):
        self.root = root
        self.below_quorum = getattr(args, "recovery_below_quorum", False)
        self.quorum_plan = getattr(args, "recovery_quorum_plan", None)
        self.member_identity = member_id
        self.directory = root / "recovery-partition"
        self.directory.mkdir()
        self.seconds = args.network_fault_seconds
        self.library = args.socket_mark_library
        self.endpoint = endpoint
        self.member_id = member_id(args.interrupt_rust_member)
        self.old_process = node["process"]
        self.started = time.monotonic()
        self.deadline = self.started + args.recovery_timeout
        config = json.loads((node["directory"] / "default_config.json").read_text())
        ports = [
            int(config[key].rsplit(":", 1)[1])
            for key in ["ip_address", "ip_address_quic"]
        ]
        ports += [
            int(config["json_rpc_server"]["address"].rsplit(":", 1)[1]),
            int(config["lite_server_port"]),
        ]
        self.fault = PacketFault(self.directory / "injection", "partition", ports)
        self.receipt = {
            "phase": "prepared",
            "member": args.interrupt_rust_member,
            "mode": "partition_during_original_database_restart",
            "settle_after_interruption_seconds": self.seconds,
            "hold_after_restart_seconds": self.seconds,
            "recovery_limit_seconds": args.recovery_timeout,
            "budget_started_at_unix": time.time(),
            "old_pid": self.old_process.pid,
        }
        self.save()

    def save(self):
        self.receipt["elapsed_seconds"] = time.monotonic() - self.started
        write(self.directory / "receipt.json", self.receipt)

    async def arm(self):
        if self.old_process.returncode is not None:
            raise RuntimeError(
                "Partition target exited before the intended interruption"
            )
        self.fault.arm()
        self.receipt.update(
            phase="partitioned_before_interruption", armed_at_unix=self.fault.armed_at
        )
        self.save()

    async def after_interruption(self):
        def reaped():
            if self.old_process.returncode != -9:
                raise RuntimeError(
                    "Partition restart requires the original SIGKILL to be reaped"
                )

        await hold(self.seconds, self.deadline, reaped)
        self.receipt.update(
            phase="waiting_for_survivor_proof", interruption_returncode=-9
        )
        self.save()

    def survivor(self, checked):
        if self.below_quorum:
            from recovery_quorum_fixture import validate_below_quorum_checkpoint

            observation = json.loads(
                (self.root / "recovery-quorum/receipt.json").read_text()
            )
            validate_below_quorum_checkpoint(
                checked, observation, self.quorum_plan, self.member_identity
            )
            self.receipt.update(
                survivor_checkpoint=checked["block"],
                survivor_kind="historical_checkpoint_after_below_quorum_stall",
                below_quorum_observation=observation,
                surviving_weight=self.quorum_plan["surviving_weight"],
                total_weight=self.quorum_plan["total_weight"],
                quorum_weight=self.quorum_plan["quorum_weight"],
            )
            self.save()
            return
        members = {
            m["validator_id"]: m["weight"]
            for m in checked["configuration"]["current"]["members"]
        }
        survivors = set(members) - {self.member_id}
        if self.member_id not in members or not checked["verified_final_certificates"]:
            raise RuntimeError("Partition survivor proof lost the complete committee")
        weight = sum(members[key] for key in survivors)
        if weight < (2 * sum(members.values()) + 2) // 3:
            raise RuntimeError(
                "Partition survivors have insufficient original committee weight"
            )
        for certificate in checked["verified_final_certificates"]:
            if (
                set(certificate["validator_ids"]) != survivors
                or certificate["verified_weight"] != weight
            ):
                raise RuntimeError(
                    "Partition proof did not certify exactly the surviving quorum"
                )
        self.receipt.update(
            survivor_checkpoint=checked["block"],
            survivor_certificates=checked["verified_final_certificates"],
            surviving_weight=weight,
            total_weight=sum(members.values()),
        )
        self.save()

    def environment(self):
        return marked_environment(self.library)

    async def after_restart(self, node):
        process = node["process"]
        ticks = node["start_ticks"]
        if process.pid == self.old_process.pid:
            raise RuntimeError("Partition restart did not create a new process")

        def alive():
            if (
                process.returncode is not None
                or Path(f"/proc/{process.pid}/stat").read_text().split()[21] != ticks
            ):
                raise RuntimeError(
                    "Restarted process exited while the partition was still active"
                )

        self.receipt.update(
            phase="restarted_while_partitioned",
            new_pid=process.pid,
            new_start_ticks=ticks,
            restarted_at_unix=time.time(),
        )
        self.receipt["kernel_before_restart_hold"] = self.fault.statistics()
        write(
            self.directory / "kernel_before_restart_hold.json",
            self.receipt["kernel_before_restart_hold"],
        )
        self.save()
        await hold(self.seconds, self.deadline, alive)
        remaining = self.deadline - time.monotonic()
        try:
            await asyncio.wait_for(
                asyncio.to_thread(rpc, self.endpoint, "getMasterchainInfo"), remaining
            )
        except (TimeoutError, urllib.error.URLError) as error:
            if time.monotonic() >= self.deadline:
                raise TimeoutError(
                    "Partition restart exceeded the original recovery deadline"
                ) from error
            if isinstance(error, urllib.error.URLError) and not isinstance(
                error.reason, TimeoutError
            ):
                raise
        else:
            raise RuntimeError(
                "Restarted control endpoint bypassed the packet partition"
            )
        alive()
        after = self.fault.statistics()
        write(self.directory / "kernel_after_restart_hold.json", after)
        before = self.receipt["kernel_before_restart_hold"]
        if after["drops"] <= before["drops"]:
            raise RuntimeError(
                "Kernel did not observe partition drops after process restart"
            )
        self.receipt.update(
            kernel_after_restart_hold=after, isolated_rpc_timeout_observed=True
        )
        self.fault.restore()
        self.receipt.update(phase="network_restored", restored_at_unix=time.time())
        self.save()

    async def complete(self, recovered):
        if time.monotonic() >= self.deadline:
            raise TimeoutError(
                "Partition restart exceeded the original recovery deadline"
            )
        self.receipt.update(
            phase="recovered",
            final_checkpoint=recovered["last_checkpoint"],
            manual_database_repair=recovered["manual_database_repair"],
        )
        self.save()

    def close(self):
        if self.fault.owned:
            self.fault.restore()
            self.receipt["cleanup_restored_at_unix"] = time.time()
        self.save()
