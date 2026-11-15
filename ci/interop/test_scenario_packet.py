"""Packet effects, native tool provenance and cleanup must be evidenced."""

import copy
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from scenario_matrix import member_id
from scenario_packet import (
    PACKETS,
    check_packet_cleanup,
    check_packet_result,
    file_hash,
    packet_arguments,
    packet_artifacts,
)


def receipt(mode, member):
    signers = [i for i in (0, 2, 4, 5) if mode != "partition" or i != member]
    return {
        "mode": mode,
        "member": member,
        "phase": "recovered",
        "same_process": True,
        "manual_database_repair": False,
        "all_six_applied_states_match": True,
        "workchain_states_match": True,
        "successor_finality_checked": True,
        "deadline_seconds": 180,
        "elapsed_seconds": 30.0,
        "armed_at_unix": 100.0,
        "restored_at_unix": 113.0,
        "kernel_statistics": {
            "kind": "netem",
            "handle": "30:",
            "packets": 100,
            "drops": 10 if mode in ("partition", "loss") else 0,
        },
        "survivor_certificates": [
            {
                "validator_ids": [member_id(i) for i in signers],
                "verified_weight": len(signers) * 17,
                "final_certificate_checked": True,
            }
        ],
        "isolated_rpc_timeout_observed": True,
        "surviving_weight": 51,
        "total_weight": 68,
        "vote": {"block": "verified"},
        "leaders": {"masterchain": {}, "workchain": {}},
    }


class PacketScenarioTest(unittest.TestCase):
    def test_all_fixed_packet_modes_and_members(self):
        for name, (mode, member) in PACKETS.items():
            check_packet_result(name, receipt(mode, member))
            args = packet_arguments(name, Path("mark.so"))
            self.assertEqual(args[args.index("--network-fault") + 1], mode)
            self.assertEqual(
                args[args.index("--network-fault-member") + 1], str(member)
            )
            self.assertEqual(args[args.index("--network-fault-seconds") + 1], "12")

    def test_no_traffic_or_wrong_impairment_refused(self):
        for mode, key, value in [
            ("partition", "drops", 0),
            ("loss", "drops", 0),
            ("reorder", "drops", 1),
            ("reorder", "packets", 0),
            ("duplicate", "packets", 0),
        ]:
            result = receipt(mode, 2)
            result["kernel_statistics"][key] = value
            with self.assertRaises(ValueError):
                check_packet_result(f"packet-{mode}-member2", result)

    def test_partitioned_signer_and_missing_recovery_refused(self):
        changes = [
            lambda r: r.update(isolated_rpc_timeout_observed=False),
            lambda r: r.update(restored_at_unix=111.9),
            lambda r: r.update(elapsed_seconds=181),
            lambda r: r.update(same_process=False),
            lambda r: r.pop("vote"),
            lambda r: r["leaders"].pop("workchain"),
            lambda r: r["survivor_certificates"][0]["validator_ids"].__setitem__(
                0, member_id(2)
            ),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                result = receipt("partition", 2)
                change(result)
                with self.assertRaises(ValueError):
                    check_packet_result("packet-partition-member2", result)

    def test_native_library_and_source_must_match_build_record(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "network_fault/socket_mark.c"
            source.parent.mkdir()
            source.write_bytes(b"source")
            library = root / "mark.so"
            library.write_bytes(b"fixture library")
            record = root / "build.json"
            meta = lambda path: {
                "bytes": path.stat().st_size,
                "sha256": file_hash(path),
            }
            record.write_text(
                json.dumps(
                    {
                        "source": str(source),
                        "library": str(library),
                        "source_meta": meta(source),
                        "library_meta": meta(library),
                    }
                )
            )
            args = SimpleNamespace(
                socket_mark_library=library, socket_mark_build_record=record
            )
            self.assertEqual(packet_artifacts(args, root), [source, library, record])
            library.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                packet_artifacts(args, root)
        with self.assertRaises(ValueError):
            packet_artifacts(SimpleNamespace(), Path("unused"))

    def test_cleanup_and_retained_kernel_output(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "network-fault/injection"
            output.mkdir(parents=True)
            result = receipt("reorder", 5)
            injection = {
                "owned_qdisc": False,
                "mode": "reorder",
                "namespace": {
                    "network": "new-net",
                    "parent_network": "host-net",
                    "user": "new-user",
                    "parent_user": "host-user",
                },
            }
            path = output / "injection.json"
            path.write_text(json.dumps(injection))
            stats = output / "statistics.json"
            stats.write_text(json.dumps([result["kernel_statistics"]]))
            check_packet_cleanup(root, result)
            for mutate in [
                lambda d: d.update(owned_qdisc=True),
                lambda d: d["namespace"].update(network="host-net"),
            ]:
                changed = copy.deepcopy(injection)
                mutate(changed)
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    check_packet_cleanup(root, result)
            path.write_text(json.dumps(injection))
            stats.write_text("[]")
            with self.assertRaises(ValueError):
                check_packet_cleanup(root, result)


if __name__ == "__main__":
    unittest.main()
