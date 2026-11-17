"""Collect the nonvoting receiver's own body/state against an existing finality witness."""

import json

from mixed_matrix import child_checked, cpp_block, digest, identity, native_state


def require_receiver_check(checked, target, expected_state):
    if identity(checked["block"]) != identity(target):
        raise ValueError("Receiver checker verified a different block")
    for field in (
        "cell_hash_checked",
        "file_hash_checked",
        "header_identity_checked",
        "state_update_matches_both",
    ):
        if checked.get(field) is not True:
            raise ValueError("Receiver checker omitted " + field)
    if checked.get("state_root_hash") != expected_state:
        raise ValueError("Receiver full state differs from the common checkpoint")
    certificates = checked.get("verified_final_certificates", [])
    if not certificates or any(
        c.get("final_certificate_checked") is not True for c in certificates
    ):
        raise ValueError("Receiver evidence lacks checked finality")


async def collect_receiver_evidence(args, receiver, target, reference_directory):
    """Keep peer finality witnesses, replacing body and full state with receiver responses."""
    sample = json.loads((reference_directory / "sample.json").read_text())
    reference = json.loads((reference_directory / "epoch-checked.json").read_text())
    if identity(sample["block"]["id"]) != identity(target):
        raise ValueError("Receiver reference sample differs from its checkpoint")
    require_receiver_check(reference, target, reference["state_root_hash"])
    directory = receiver.root / "propagation-receiver-evidence"
    directory.mkdir()
    sample["block"] = await cpp_block(args.snapshot, receiver.node, target, directory)
    sample["masterchain_state"] = await native_state(
        args.snapshot,
        receiver.node.liteserver_config,
        "cpp-receiver",
        target,
        directory / "state",
    )
    sample_path, checked_path = directory / "sample.json", directory / "checked.json"
    sample_path.write_text(json.dumps(sample, indent=2) + "\n")
    await child_checked(
        [args.block_checker, sample_path, checked_path], directory / "checker.log"
    )
    checked = json.loads(checked_path.read_text())
    require_receiver_check(checked, target, reference["state_root_hash"])
    receiver.receipt["body_state_evidence"] = {
        "source": "cpp_nonvoting_receiver",
        "sample_directory": str(directory),
        "sample_sha256": digest(sample_path),
        "checked_sha256": digest(checked_path),
        "block": checked["block"],
        "state_root_hash": checked["state_root_hash"],
        "receiver_body_and_full_state_checked": True,
    }
    receiver.save()
    return receiver.receipt["body_state_evidence"]
