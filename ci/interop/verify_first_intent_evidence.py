"""Independently bind a declared first-intent cut to native consensus and teardown evidence.

Creates a new validation directory. Never rewrites or supplies node database input.
"""

import argparse
import base64
import gzip
import hashlib
import json
import subprocess
from pathlib import Path

from verify_intent_cut_evidence import require, verify_written_prefix


def verify_references(request):
    references = request.get("all_references", {})
    require(
        set(references) == {"cpp-0", "cpp-1", "cpp-4", "rust-2", "rust-3", "rust-5"},
        "Missing or extra node in six-peer state references",
    )
    for reference in references.values():
        require(
            all(
                reference[key] == request["reference"][key]
                for key in ["last", "init", "state_root_hash"]
            ),
            "Six-peer block, genesis or applied state differs",
        )


def verify_post_restart_vote(archive, runtime, cut, by_sample, member):
    from first_intent_vote import post_restart_successor_vote

    vote = cut["post_restart_vote"]
    path = Path(vote["sample_directory"])
    require(
        path.resolve().is_relative_to((runtime / "checks").resolve()),
        "Independent vote is outside owned checks",
    )
    relative = path.relative_to(runtime / "checks")
    raw = (archive / "checks" / relative / "epoch-checked.json").read_bytes()
    require(
        hashlib.sha256(raw).hexdigest() == vote["checked_sha256"]
        and json.loads(raw) == vote["check"],
        "Independent vote raw evidence differs",
    )
    checked = by_sample[str(relative)]
    require(
        checked == vote["check"]
        and vote["validator_id"] == member
        and vote["block"] == checked["block"]
        and post_restart_successor_vote(checked, member, cut["restarted_at_unix"]),
        "Independent post-restart vote failed native validation",
    )


def verify(
    evidence,
    *,
    output,
    genesis,
    point,
    product,
    fixture,
    native_checker,
    product_directory,
):
    require(
        point in ("before-write", "after-partial-write"),
        "Unsupported first-intent point",
    )
    d, v = Path(evidence), Path(output)
    require(not v.exists(), "Validation output already exists")
    v.mkdir(parents=True)
    (v / "native").mkdir()
    a = d / "rotation"
    read = lambda path: json.loads(path.read_text())
    sha = lambda data: hashlib.sha256(data).hexdigest()
    product_directory, native_checker = Path(product_directory), Path(native_checker)
    metas = [
        p
        for p in (d / "builds").glob("first-intent-*-source.json")
        if "first_intent_cut" in read(p)
    ]
    require(len(metas) == 1, "Ambiguous first-intent fixture metadata")
    m = read(metas[0])
    require(int(m["genesis"]) == genesis, "Declared genesis differs")
    require(m["compiled_product_commit"] == product, "Declared product differs")
    require(m["commit"] == fixture, "Declared fixture differs")
    require(m["first_intent_cut"]["point"] == point, "Metadata cut differs")
    result = read(a / "result.json")
    require(
        result["status"] == "mixed_membership_rotation_observed"
        and result["all_six_applied_mc_states_match"]
        and result["independent_post_rotation_finality_qualified"],
        "Evidence check failed: result['status'] == 'mixed_membership_rotation_observed' and result['all_six_applied_mc_states_match'] and result['independent_post_rotation_finality_qualified'",
    )
    cut = read(a / "first-intent-cut/receipt.json")
    require(
        result["first_intent_cut"] == cut,
        "Evidence check failed: result['first_intent_cut'] == cut",
    )
    require(
        cut["phase"] == "rotation_and_first_intent_recovery_verified"
        and cut["member"] == 2
        and (cut["point"] == point),
        "Evidence check failed: cut['phase'] == 'rotation_and_first_intent_recovery_verified' and cut['member'] == 2 and (cut['point'] == point)",
    )
    require(
        cut["interruption_returncode"] == -9
        and cut["normal_replay_completed"]
        and cut["stopped_state_verified"],
        "Evidence check failed: cut['interruption_returncode'] == -9 and cut['normal_replay_completed'] and cut['stopped_state_verified']",
    )
    require(
        cut["prior_complete_intents"] == 0
        and cut["pending_preserved_before_restart"]
        and (not cut["manual_database_repair"]),
        "Evidence check failed: cut['prior_complete_intents'] == 0 and cut['pending_preserved_before_restart'] and (not cut['manual_database_repair'])",
    )
    require(
        0
        < cut["elapsed_seconds"]
        <= cut["total_acceptance_elapsed_seconds"]
        <= cut["recovery_limit_seconds"]
        == 180,
        "Evidence check failed: 0 < cut['elapsed_seconds'] <= cut['total_acceptance_elapsed_seconds'] <= cut['recovery_limit_seconds'] == 180",
    )
    old, new = (cut["old_process"], cut["new_process"])
    require(
        old["pid"] != new["pid"] and old["start_ticks"] != new["start_ticks"],
        "Evidence check failed: old['pid'] != new['pid'] and old['start_ticks'] != new['start_ticks']",
    )
    require(
        cut["budget_started_at_unix"]
        <= cut["stopped_at_unix"]
        < cut["restarted_at_unix"],
        "Evidence check failed: cut['budget_started_at_unix'] <= cut['stopped_at_unix'] < cut['restarted_at_unix']",
    )
    command = read(a / "source.json")["command"]
    require(
        command[command.index("--first-intent-cut-point") + 1] == point,
        "Evidence check failed: command[command.index('--first-intent-cut-point') + 1] == point",
    )
    for flag in [
        "--source-ack-fault",
        "--partition-restart",
        "--signer-expiry-member",
        "--followup-intent-frontier",
    ]:
        require(flag not in command, "Evidence check failed: flag not in command")
    runtime = Path(command[command.index("--output") + 1])
    target = Path(cut["path"])
    ns = Path(cut["namespace"])
    require(
        target.parent == ns / "finality-intents",
        "Evidence check failed: target.parent == ns / 'finality-intents'",
    )
    require(
        ns.is_relative_to(runtime / "rust-2/node_db/catchains/consensus/v2")
        and ".." not in ns.parts,
        "Evidence check failed: ns.is_relative_to(runtime / 'rust-2/node_db/catchains/consensus/v2') and '..' not in ns.parts",
    )
    source = a / "first-intent-cut"
    raw = (source / "intent-before.json").read_bytes()
    intended = (source / "intended.json").read_bytes()
    record = json.loads(intended)
    require(
        len(raw) == cut["bytes"] and len(intended) == cut["intended_bytes"],
        "Cut byte counts differ",
    )
    verify_written_prefix(raw, intended, point)
    require(
        sha(raw) == cut["sha256"] and sha(intended) == cut["intended_sha256"],
        "Evidence check failed: sha(raw) == cut['sha256'] and sha(intended) == cut['intended_sha256']",
    )
    require(
        record["schema"] == 1
        and record["session_id"] == cut["session"]
        and (record["slot"] == cut["slot"])
        and (record["candidate_hash"] == cut["candidate_hash"]),
        "Evidence check failed: record['schema'] == 1 and record['session_id'] == cut['session'] and (record['slot'] == cut['slot']) and (record['candidate_hash'] == cut['candidate_hash'])",
    )
    require(
        target.name == f"{record['slot']}-{record['candidate_hash']}.tmp",
        "Evidence check failed: target.name == f\"{record['slot']}-{record['candidate_hash']}.tmp\"",
    )
    inv_bytes = (source / "intent-directory-at-stop.json").read_bytes()
    require(
        sha(inv_bytes) == cut["stopped_directory_inventory_sha256"],
        "Evidence check failed: sha(inv_bytes) == cut['stopped_directory_inventory_sha256']",
    )
    require(
        json.loads(inv_bytes)
        == [{"path": target.name, "bytes": len(raw), "sha256": sha(raw)}],
        "Evidence check failed: json.loads(inv_bytes) == [{'path': target.name, 'bytes': len(raw), 'sha256': sha(raw)}]",
    )
    start = (source / "session-start.json").read_bytes()
    require(
        sha(start) == cut["session_start_sha256"],
        "Evidence check failed: sha(start) == cut['session_start_sha256']",
    )
    require(
        json.loads(start)
        == {
            k: value
            for k, value in record.items()
            if k not in ["slot", "candidate_hash", "certificate"]
        },
        "Evidence check failed: json.loads(start) == {k: value for k, value in record.items() if k not in ['slot', 'candidate_hash', 'certificate']}",
    )
    manifest = read(source / "session-runtime.json")
    require(
        (manifest["shard_workchain"], manifest["catchain_seqno"], manifest["role"])
        == (-1, 0, "validator"),
        "Evidence check failed: (manifest['shard_workchain'], manifest['catchain_seqno'], manifest['role']) == (-1, 0, 'validator')",
    )
    require(
        manifest["session"] == record["session_id"]
        and manifest["profile"] == record["profile"]
        and (manifest["global_id"] == record["global_id"]),
        "Evidence check failed: manifest['session'] == record['session_id'] and manifest['profile'] == record['profile'] and (manifest['global_id'] == record['global_id'])",
    )
    require(
        (source / "native-stop.marker").read_text()
        == f"intent {point} pid={old['pid']}: {target}\n",
        "Evidence check failed: (source / 'native-stop.marker').read_text() == f\"intent {point} pid={old['pid']}: {target}\\n\"",
    )
    status = (source / "stopped-process.txt").read_text().splitlines()
    require(
        any(l.startswith("State:") and l.split()[1] == "T" for l in status),
        "Evidence check failed: any((l.startswith('State:') and l.split()[1] == 'T' for l in status))",
    )
    require(
        any(l.startswith("Pid:") and int(l.split()[1]) == old["pid"] for l in status),
        "Evidence check failed: any((l.startswith('Pid:') and int(l.split()[1]) == old['pid'] for l in status))",
    )
    from first_intent_vote import verify_original_acceptance

    verify_original_acceptance(source, cut, record)
    outputs = target.parent / "outputs-v1" / target.with_suffix(".outputs").name
    require(
        not any(p.exists() for p in [target, target.with_suffix(".json"), outputs]),
        "Original intent/output cleanup is incomplete",
    )
    # Re-execute both native checks; saved checked JSON alone is not qualification.
    for name in ["accepted", "accepted-states"]:
        input_name = (
            "accepted-sample.json" if name == "accepted" else "accepted-states.json"
        )
        checked_path = v / "native" / (name + ".json")
        subprocess.run(
            [str(native_checker), str(source / input_name), str(checked_path)],
            check=True,
        )
        require(
            read(checked_path) == read(source / (name + "-checked.json")),
            "Original acceptance native replay differs",
        )
    require(
        (ns / "finality-session-start.json").read_bytes() == start,
        "Evidence check failed: (ns / 'finality-session-start.json').read_bytes() == start",
    )
    require(
        sha((a / "rust-2/validator-prepared.json").read_bytes())
        == cut["prepared_sha256"],
        "Evidence check failed: sha((a / 'rust-2/validator-prepared.json').read_bytes()) == cut['prepared_sha256']",
    )
    require(
        sha((runtime / "rust-2/validator-prepared.json").read_bytes())
        == cut["prepared_sha256"],
        "Evidence check failed: sha((runtime / 'rust-2/validator-prepared.json').read_bytes()) == cut['prepared_sha256']",
    )
    for name, h in m["binaries"].items():
        require(
            sha((product_directory / name).read_bytes()) == h,
            "Evidence check failed: sha((product_directory / name).read_bytes()) == h",
        )
    for f, h in {**m["rust_product_files"], **m["fixture_files"]}.items():
        require(
            sha((d / "source" / f).read_bytes()) == h,
            "Evidence check failed: sha((d / 'source' / f).read_bytes()) == h",
        )
    checker = native_checker
    require(
        sha(checker.read_bytes()) == m["checker_sha256"],
        "Evidence check failed: sha(checker.read_bytes()) == m['checker_sha256']",
    )
    required_samples = {
        str(Path(entry["sample_directory"]).relative_to(runtime / "checks"))
        for groups in result["epochs"].values()
        for entries in groups.values()
        for entry in entries.values()
    }
    vote_path = Path(cut["post_restart_vote"]["sample_directory"])
    require(
        vote_path.resolve().is_relative_to((runtime / "checks").resolve()),
        "Independent vote is outside owned checks",
    )
    required_samples.add(str(vote_path.relative_to(runtime / "checks")))
    index = []
    by_sample = {}
    excluded = []
    for sample in sorted((a / "checks").rglob("sample.json")):
        if str(sample.parent.relative_to(a / "checks")) not in required_samples and (
            not (sample.parent / "epoch-checked.json").exists()
        ):
            excluded.append(
                {
                    "sample": str(sample.relative_to(d)),
                    "sample_sha256": sha(sample.read_bytes()),
                    "reason": "Intermediate raw snapshot has no terminal epoch check and is not referenced by final epoch acceptance; retained without finality qualification.",
                }
            )
            continue
        out = v / "native" / f"{len(index):05}.json"
        log = out.with_suffix(".log")
        require(not out.exists(), "Evidence check failed: not out.exists()")
        with log.open("x") as stream:
            ret = subprocess.run(
                [str(checker), str(sample), str(out)],
                check=False,
                stdout=stream,
                stderr=subprocess.STDOUT,
            )
        require(ret.returncode == 0, (sample, log))
        checked = read(out)
        request = read(sample)
        require(
            all(
                checked[k]
                for k in [
                    "cell_hash_checked",
                    "file_hash_checked",
                    "header_identity_checked",
                    "state_update_matches_both",
                ]
            ),
            "Evidence check failed: all((checked[k] for k in ['cell_hash_checked', 'file_hash_checked', 'header_identity_checked', 'state_update_matches_both']))",
        )
        require(
            checked["verified_final_certificates"]
            and all(
                cert["final_certificate_checked"]
                for cert in checked["verified_final_certificates"]
            ),
            "Evidence check failed: checked['verified_final_certificates'] and all((cert['final_certificate_checked'] for cert in checked['verified_final_certificates']))",
        )
        verify_references(request)
        if request.get("workchain"):
            wc = checked["workchain_check"]
            require(
                wc["all_four_states_match_block_update"]
                and wc["masterchain_anchor_checked"]
                and (len(wc["states"]) == 4),
                "Evidence check failed: wc['all_four_states_match_block_update'] and wc['masterchain_anchor_checked'] and (len(wc['states']) == 4)",
            )
        by_sample[str(sample.parent.relative_to(a / "checks"))] = checked
        index.append(
            {
                "sample": str(sample.relative_to(d)),
                "sample_sha256": sha(sample.read_bytes()),
                "output": str(out.relative_to(v)),
                "output_sha256": sha(out.read_bytes()),
            }
        )
    member = lambda i: base64.b64encode(
        hashlib.sha256(f"n6-validator-id-{i}".encode()).digest()
    ).decode()
    for phase, indices in [("before", [0, 1, 2, 3]), ("after", [0, 2, 4, 5])]:
        for kind in ["mc_creators", "wc_creators"]:
            entries = result["epochs"][phase][kind]
            require(
                set(entries) == {member(i) for i in indices},
                "Evidence check failed: set(entries) == {member(i) for i in indices}",
            )
            for identity, entry in entries.items():
                relative = Path(entry["sample_directory"]).relative_to(
                    runtime / "checks"
                )
                checked = by_sample[str(relative)]
                require(
                    (
                        checked["created_by"]
                        if kind == "mc_creators"
                        else checked["workchain_check"]["created_by"]
                    )
                    == identity,
                    "Evidence check failed: (checked['created_by'] if kind == 'mc_creators' else checked['workchain_check']['created_by']) == identity",
                )
    for kind in ["mc_creators", "wc_creators"]:
        entry = result["epochs"]["after"][kind][member(2)]
        require(
            entry["local_collation_log"] == "node-restart.log",
            "Evidence check failed: entry['local_collation_log'] == 'node-restart.log'",
        )
        log = gzip.decompress((a / "rust-2/node-restart.log.gz").read_bytes()).decode(
            errors="replace"
        )
        require(
            entry["local_collation"] in log,
            "Evidence check failed: entry['local_collation'] in log",
        )
        require(
            entry["check"]["gen_utime"] > cut["restarted_at_unix"],
            "Evidence check failed: entry['check']['gen_utime'] > cut['restarted_at_unix']",
        )
    verify_post_restart_vote(a, runtime, cut, by_sample, member(2))
    processes = read(a / "processes.json")
    pids = (
        set(processes["cpp"].values())
        | {x["pid"] for x in processes["rust"].values()}
        | {old["pid"], new["pid"]}
    )
    require(
        len(pids) == 7 and all(not Path("/proc", str(pid)).exists() for pid in pids),
        "Evidence check failed: len(pids) == 7 and all((not Path('/proc', str(pid)).exists() for pid in pids))",
    )
    require(
        read(a / "rust-shutdown.json") == {"2": 0, "3": 0, "5": 0},
        "Evidence check failed: read(a / 'rust-shutdown.json') == {'2': 0, '3': 0, '5': 0}",
    )
    timing = read(a / "rust-shutdown-timing.json")
    require(
        all(
            x["elapsed_seconds"] <= x["normal_exit_limit_seconds"] == 20
            for x in timing.values()
        ),
        "Evidence check failed: all((x['elapsed_seconds'] <= x['normal_exit_limit_seconds'] == 20 for x in timing.values()))",
    )
    cpp = read(a / "cpp-shutdown.json")
    require(
        set(cpp) == {"0", "1", "4"},
        "Evidence check failed: set(cpp) == {'0', '1', '4'}",
    )
    require(
        all(
            x["returncode"] == -15
            and x["requested_signal"] == "SIGTERM"
            and x["alive_before_stop"]
            and x["matches_pinned_tester_teardown"]
            and (x["elapsed_seconds"] <= x["teardown_limit_seconds"] == 20)
            for x in cpp.values()
        ),
        "Evidence check failed: all((x['returncode'] == -15 and x['requested_signal'] == 'SIGTERM' and x['alive_before_stop'] and x['matches_pinned_tester_teardown'] and (x['elapsed_seconds'] ",
    )
    (v / "native-index.json").write_text(
        json.dumps(
            {
                "checker_sha256": m["checker_sha256"],
                "samples": index,
                "excluded_unqualified_snapshots": excluded,
            },
            indent=2,
        )
        + "\n"
    )
    obs = {
        "genesis": genesis,
        "point": point,
        "product": m["compiled_product_commit"],
        "fixture": m["commit"],
        "status": "first_intent_recovery_independently_verified",
        "written_bytes": len(raw),
        "intended_bytes": len(intended),
        "prior_complete_intents": 0,
        "normal_completion_elapsed_seconds": cut["elapsed_seconds"],
        "all_acceptance_elapsed_seconds": cut["total_acceptance_elapsed_seconds"],
        "original_budget_seconds": 180,
        "independent_native_samples": len(index),
        "all_six_mc_four_wc_states_match": True,
        "verified_post_restart_vote": True,
        "successor_mc_wc_post_restart_creators": True,
        "normal_original_record_completed": True,
        "process_count": len(pids),
        "all_processes_absent": True,
        "scope": f"Genesis{genesis} first initial-MC intent {point} only: no earlier complete intent in selected namespace, durable certificate-free start locator, real SIGSTOP/SIGKILL and original-DB/config restart, normal full completion and subsequent mixed committee consensus/state checks under original180. Not ACK IO/expiry/partition combination, all pending intents clearance, power loss, full fault matrix or local fallback qualification.",
        "broad_task_complete": False,
    }
    (v / "observations.json").write_text(json.dumps(obs, indent=2) + "\n")
    return obs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--genesis", type=int, required=True)
    parser.add_argument(
        "--point", choices=["before-write", "after-partial-write"], required=True
    )
    parser.add_argument("--product", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--native-checker", type=Path, required=True)
    parser.add_argument("--product-directory", type=Path, required=True)
    args = parser.parse_args()
    result = verify(
        args.evidence,
        output=args.output,
        genesis=args.genesis,
        point=args.point,
        product=args.product,
        fixture=args.fixture,
        native_checker=args.native_checker,
        product_directory=args.product_directory,
    )
    print(
        f"Verified Genesis{args.genesis} {args.point}: {result['independent_native_samples']} native samples."
    )


if __name__ == "__main__":
    main()
