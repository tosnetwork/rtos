"""Reject renewed authority, expired signatures and unrelated refusals."""

import copy
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scenario_expiry import check_expiry_evidence
from scenario_matrix import member_id


class ExpiryTests(unittest.TestCase):
    def test_authority_and_quorum_binding(self):
        for passive in (False, True):
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                directory = root / "signer-expiry"
                directory.mkdir()
                profile = {
                    "expire_at": 100,
                    "session": "a" * 64,
                    "validator": hashlib.sha256(b"n6-validator-id-5").hexdigest(),
                }
                schedule = {"expire_at": 100}
                (directory / "original-profile.json").write_text(json.dumps(profile))
                (directory / "original-schedule.json").write_text(json.dumps(schedule))
                prepared = directory / "prepared.json"
                prepared.write_text("{}")
                paths = [
                    directory / "original-profile.json",
                    directory / "original-schedule.json",
                    prepared,
                ]
                receipt = {
                    "phase": "expired_member_restarted_without_signing"
                    if passive
                    else "recovered_with_peer_still_expired",
                    "manual_database_repair": False,
                    "clock_adjusted": False,
                    "authority_unchanged": True,
                    "post_expiry_all_six_states_match": True,
                    "plan": {
                        "member": 5,
                        "interrupted_member": 5 if passive else 2,
                        "quorum_weight": 46,
                        "total_weight": 68,
                        "surviving_weight_during_interruption": 51 if passive else 34,
                        "surviving_weight_after_restart": 51,
                        "expire_at": 100,
                    },
                    "observed_at_unix": 101,
                    "elapsed_seconds": 50,
                    "recovery_limit_seconds": 180.0,
                    "session": "a" * 64,
                    "authority_file_hashes": {
                        str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in paths
                    },
                    "post_expiry_certificates": [
                        {
                            "final_certificate_checked": True,
                            "validator_ids": [member_id(i) for i in (0, 2, 4)],
                            "verified_weight": 51,
                        }
                    ],
                    "last_checkpoint": {"seqno": 20},
                    "refusal_line": "Session "
                    + "a" * 64
                    + " broadcast_vote: failed to sign vote: signing journal stopped/retired",
                    "expiry_line": "signing generation expired and retired",
                    "same_expired_process": True,
                    "old_process_replaced": True,
                    "pid": 10,
                    "new_pid": 20,
                    "new_start_ticks": "200",
                }
                recovery = {
                    "last_checkpoint": {"seqno": 20},
                    "new_process": {"pid": 20, "start_ticks": "200"},
                }
                check_expiry_evidence(root, receipt, recovery, passive=passive)
                for change in [
                    lambda d: d.update(observed_at_unix=99),
                    lambda d: d.update(recovery_limit_seconds=181),
                    lambda d: d.update(refusal_line="wrong session"),
                    lambda d: d["post_expiry_certificates"][0].update(
                        validator_ids=[member_id(i) for i in (0, 2, 5)]
                    ),
                ]:
                    bad = copy.deepcopy(receipt)
                    change(bad)
                    with self.assertRaises(ValueError):
                        check_expiry_evidence(root, bad, recovery, passive=passive)
                profile["expire_at"] = 200
                (directory / "original-profile.json").write_text(json.dumps(profile))
                with self.assertRaisesRegex(ValueError, "finite expiry"):
                    check_expiry_evidence(root, receipt, recovery, passive=passive)


class ExpiryRawTests(unittest.TestCase):
    def test_checked_witness_and_original_log_cannot_be_substituted(self):
        from scenario_expiry import check_expiry_raw_witness

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "signer-expiry/expired-20"
            sample.mkdir(parents=True)
            checked = {
                "block": {"seqno": 20},
                "verified_final_certificates": [{"proof": "original"}],
                "gen_utime": 105,
                "key_block": False,
                "verified_governing_key_blocks": [{}],
            }
            (sample / "checked.json").write_text(json.dumps(checked))
            node = root / "rust-5"
            node.mkdir()
            log = node / "node.log"
            log.write_text("earlier\nexpired\nrefusal\n")
            receipt = {
                "post_expiry_sample": str(sample),
                "post_expiry_block": checked["block"],
                "post_expiry_certificates": checked["verified_final_certificates"],
                "plan": {"expire_at": 100},
                "log_offset": len(b"earlier\n"),
                "expiry_line": "expired",
                "refusal_line": "refusal",
            }
            check_expiry_raw_witness(root, receipt)
            checked["verified_final_certificates"] = [{"proof": "substituted"}]
            (sample / "checked.json").write_text(json.dumps(checked))
            with self.assertRaises(ValueError):
                check_expiry_raw_witness(root, receipt)
            checked["verified_final_certificates"] = receipt["post_expiry_certificates"]
            (sample / "checked.json").write_text(json.dumps(checked))
            log.write_text("expired\nrefusal\n")
            with self.assertRaises(ValueError):
                check_expiry_raw_witness(root, receipt)
            log.write_text("earlier\nexpired\nrefusal\n")
            receipt["post_expiry_sample"] = str(root / "outside")
            with self.assertRaises(ValueError):
                check_expiry_raw_witness(root, receipt)


class ExpiryAuthorityCopyTests(unittest.TestCase):
    def test_copies_and_owned_paths_must_match_bound_authority(self):
        from scenario_expiry import check_expiry_authority_copies

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "signer-expiry"
            directory.mkdir()
            node = root / "rust-5"
            node.mkdir()
            namespace = node / "node_db/session"
            namespace.mkdir(parents=True)
            bindings = {}
            for path, saved, raw in [
                (
                    namespace / "isolated-signing.json",
                    "original-profile.json",
                    b"profile",
                ),
                (
                    namespace.parent / "isolated-signing-schedule.json",
                    "original-schedule.json",
                    b"schedule",
                ),
                (node / "validator-prepared.json", None, b"prepared"),
            ]:
                path.write_bytes(raw)
                bindings[str(path)] = hashlib.sha256(raw).hexdigest()
                if saved:
                    (directory / saved).write_bytes(raw)
            selected = {"session": "a" * 64, "shard_workchain": -1, "role": "validator"}
            (directory / "selected-runtime.json").write_text(json.dumps(selected))
            receipt = {"authority_file_hashes": bindings, "session": "a" * 64}
            check_expiry_authority_copies(root, receipt)
            (directory / "original-profile.json").write_bytes(b"substituted")
            with self.assertRaisesRegex(ValueError, "Saved expiry authority"):
                check_expiry_authority_copies(root, receipt)
            (directory / "original-profile.json").write_bytes(b"profile")
            other = root / "isolated-signing.json"
            other.write_bytes(b"profile")
            old = next(p for p in bindings if Path(p).name == "isolated-signing.json")
            bindings[str(other)] = bindings.pop(old)
            with self.assertRaisesRegex(ValueError, "outside"):
                check_expiry_authority_copies(root, receipt)


class ExpiryArgumentTests(unittest.TestCase):
    def test_composed_modes_match_production_quorum_and_expiry_plan(self):
        from types import SimpleNamespace

        from recovery_quorum_fixture import recovery_quorum_plan
        from scenario_execution import make_profile
        from scenario_expiry import expiry_arguments
        from signer_expiry_fixture import expiry_plan

        template = {
            "schema": 1,
            "cpp_revision": "ref",
            "global_version": 16,
            "consensus": {},
            "auth_network_tag": "tag",
        }
        profile = make_profile("rotation-mixed", template, 1000)
        for name, member, weight in [
            ("signer-expiry", 2, 34),
            ("expired-member-restart", 5, 51),
        ]:
            args = expiry_arguments(name, "/ack.so", "/packet.so")
            self.assertEqual(
                args[args.index("--interrupt-rust-member") + 1], str(member)
            )
            namespace = SimpleNamespace(
                signer_expiry_member=5,
                expired_member_restart="--expired-member-restart" in args,
                interrupt_rust_member=member,
                source_ack_partition_restart=True,
                source_ack_fault="sync-eio",
                recovery_below_quorum="--recovery-below-quorum" in args,
            )
            plan = expiry_plan(profile, namespace)
            self.assertEqual(plan["surviving_weight_during_interruption"], weight)
            self.assertEqual(plan["expire_at"], 1170)
            quorum = recovery_quorum_plan(
                profile,
                member,
                namespace.recovery_below_quorum,
                unavailable=() if namespace.expired_member_restart else (5,),
            )
            if member == 2:
                self.assertEqual(quorum["surviving_weight"], 34)
                self.assertEqual(quorum["quorum_weight"], 46)
            else:
                self.assertIsNone(quorum)
            self.assertNotIn("successor_weights", profile)
        with self.assertRaises(ValueError):
            expiry_arguments("typo", "ack", "packet")


class ExpiredFullNodeTests(unittest.TestCase):
    def test_full_node_progress_never_restores_signer(self):
        from scenario_expiry import check_expired_full_node_witness

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            node = root / "rust-5"
            node.mkdir()
            session = "a" * 64
            refusal = f"session_id={session} Isolated custody key differs from authenticated descriptor or has expired"
            (node / "node-restart.log").write_text(refusal + "\n")
            survivors = [member_id(i) for i in (0, 2, 4)]
            samples = []
            for i, elapsed in enumerate((0, 6, 12)):
                directory = root / "recovery" / str(20 + i)
                directory.mkdir(parents=True)
                block = {"seqno": 20 + i}
                wcblock = {"seqno": 30 + i}
                checked = {
                    "block": block,
                    "created_by": survivors[0],
                    "gen_utime": 200 + i,
                    "verified_final_certificates": [
                        {
                            "final_certificate_checked": True,
                            "validator_ids": survivors,
                            "verified_weight": 51,
                        }
                    ],
                    "workchain_check": {
                        "block": wcblock,
                        "created_by": survivors[1],
                        "gen_utime": 200 + i,
                        "all_four_states_match_block_update": True,
                        "masterchain_anchor_checked": True,
                    },
                }
                (directory / "checked-with-workchain.json").write_text(
                    json.dumps(checked)
                )
                samples.append(
                    {
                        "block": block,
                        "workchain": wcblock,
                        "sample_directory": str(directory),
                        "elapsed_seconds": elapsed,
                    }
                )
            observation = {
                "member": 5,
                "required_observation_seconds": 12,
                "signing_authority_restored": False,
                "expire_at": 100,
                "samples": samples,
                "refusal_line": refusal,
            }
            recovery = {
                "expired_full_node": observation,
                "all_original_pending_intents_completed": True,
                "restarted_at_unix": 150,
            }
            receipt = {
                "full_node_observation": observation,
                "plan": {"expire_at": 100},
                "session": session,
            }
            check_expired_full_node_witness(root, receipt, recovery)
            observation["signing_authority_restored"] = True
            with self.assertRaises(ValueError):
                check_expired_full_node_witness(root, receipt, recovery)
            observation["signing_authority_restored"] = False
            samples[-1]["elapsed_seconds"] = 11
            with self.assertRaises(ValueError):
                check_expired_full_node_witness(root, receipt, recovery)
            samples[-1]["elapsed_seconds"] = 12
            path = Path(samples[-1]["sample_directory"]) / "checked-with-workchain.json"
            value = json.loads(path.read_text())
            value["verified_final_certificates"][0]["validator_ids"][-1] = member_id(5)
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "certificate vote"):
                check_expired_full_node_witness(root, receipt, recovery)


class PassiveComponentTests(unittest.TestCase):
    def test_passive_member5_rejects_votes_and_ordinary_member2_mode(self):
        import copy

        from scenario_ack import check_ack_result
        from scenario_expiry import check_passive_recovery_components
        from scenario_matrix import member_id
        from test_scenario_ack_partition import fixture

        with TemporaryDirectory() as tmp:
            combined, source, partition, recovery = fixture(Path(tmp), "sync-eio")
            for value in [combined, source, partition, recovery]:
                value["member"] = 5
            recovery.update(
                vote=None,
                leaders={},
                expired_full_node={"signing_authority_restored": False},
            )
            partition["survivor_certificates"] = [
                {
                    "final_certificate_checked": True,
                    "validator_ids": [member_id(i) for i in (0, 2, 4)],
                    "verified_weight": 51,
                }
            ]
            check_passive_recovery_components(combined, source, partition, recovery)
            from scenario_execution import check_result, make_profile
            from test_scenario_execution import rotation_result

            result = rotation_result()
            result.update(
                source_ack_partition_restart=combined,
                source_ack_fault=source,
                partition_restart=partition,
                recovery=recovery,
            )
            check_result("expired-member-restart", result)
            with self.assertRaises(ValueError):
                check_result("source-ack-partition-sync-eio", result)
            profile = make_profile(
                "expired-member-restart",
                {
                    "schema": 1,
                    "cpp_revision": "ref",
                    "global_version": 16,
                    "consensus": {},
                    "auth_network_tag": "tag",
                },
                1000,
            )
            self.assertEqual(profile["successor_members"], [0, 2, 4, 5])
            self.assertNotIn("successor_weights", profile)
            with self.assertRaises(ValueError):
                check_ack_result("source-ack-sync-eio", source, recovery)
            for mutate in [
                lambda r: r.update(vote={"validator_id": member_id(5)}),
                lambda r: r.update(leaders={"masterchain": {}}),
                lambda r: r["expired_full_node"].update(
                    signing_authority_restored=True
                ),
            ]:
                changed = copy.deepcopy(recovery)
                mutate(changed)
                with self.assertRaises(ValueError):
                    check_passive_recovery_components(
                        combined, source, partition, changed
                    )
