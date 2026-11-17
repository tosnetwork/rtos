"""Full-state evidence for bootstrap diagnostics, using the native checker."""

import asyncio
import base64
import json

from mixed_matrix import child_checked, cpp_certificate, digest, identity, native_state
from receiver_evidence import require_receiver_check


def require_bootstrap_vote(checked, required):
    """Bind a checked certificate to the actual insufficient-C++ topology."""
    committee = required["committee"]
    voter = required["validator_id"]
    cpp = required["cpp_ids"]
    if len(committee) != 4 or any(
        type(w) is not int or w <= 0 for w in committee.values()
    ):
        raise ValueError("Invalid bootstrap committee weights")
    if len(cpp) != 2 or len(set(cpp)) != 2 or voter in cpp:
        raise ValueError("Expected two C++ members and a distinct Rust member")
    if any(member not in committee for member in [*cpp, voter]):
        raise ValueError("Bootstrap topology is outside the committee")
    config = checked["configuration"]
    members = config["current"]["members"]
    if (
        config.get("state_root_checked") is not True
        or len(members) != len(committee)
        or {member["validator_id"]: member["weight"] for member in members} != committee
    ):
        raise ValueError("Checked state committee differs from prepared custody")
    threshold = sum(committee.values()) * 2 // 3 + 1
    cpp_weight = sum(committee[member] for member in cpp)
    if cpp_weight >= threshold or cpp_weight + committee[voter] < threshold:
        raise ValueError("Rust is not necessary and sufficient for this quorum")
    for certificate in checked["verified_final_certificates"]:
        signers = certificate["validator_ids"]
        if certificate.get("final_certificate_checked") is not True:
            raise ValueError("Unchecked bootstrap finality certificate")
        if len(set(signers)) != len(signers) or not set(signers) <= {*cpp, voter}:
            raise ValueError("Certificate signer set differs from active topology")
        weight = sum(committee[member] for member in signers)
        if (
            type(certificate["verified_weight"]) is not int
            or weight != certificate["verified_weight"]
        ):
            raise ValueError("Certificate weight differs from checked signers")
        if voter in signers and weight >= threshold:
            return {
                "validator_id": voter,
                "cpp_weight": cpp_weight,
                "quorum_weight": threshold,
                "verified_weight": weight,
                "session_id": certificate["session_id"],
                "slot": certificate["slot"],
            }
    raise ValueError("No checked certificate contains the required Rust vote")


async def collect_bootstrap_evidence(
    args,
    observation,
    rust_rpc,
    rpc,
    lite_config,
    cpp_node,
    zerostate,
    directory,
    required_vote=None,
):
    """Fetch the Rust node's own body/state, retaining native finality evidence."""
    directory.mkdir()
    target = observation["rust"]["last"]
    sample = dict(observation)
    sample["reference"] = observation["references"][0]
    sample["block"] = await asyncio.to_thread(rpc, rust_rpc, "getBlock", target)
    if identity(sample["block"]["id"]) != identity(target):
        raise ValueError("Bootstrap body differs from the observed checkpoint")
    sample["masterchain_state"] = await native_state(
        args.snapshot, lite_config, "rust-bootstrap", target, directory / "state"
    )
    sample["governing_zerostate_boc"] = base64.b64encode(zerostate).decode()
    sample["certificates"] = [
        await cpp_certificate(
            args.snapshot, cpp_node, observation["zerostate"], target, directory
        )
    ]
    sample_path, checked_path = directory / "sample.json", directory / "checked.json"
    sample_path.write_text(json.dumps(sample, indent=2) + "\n")
    await child_checked(
        [args.block_checker, sample_path, checked_path], directory / "checker.log"
    )
    checked = json.loads(checked_path.read_text())
    require_receiver_check(checked, target, observation["rust"]["state_root_hash"])
    return {
        "source": "rust_bootstrap",
        "sample_directory": str(directory),
        "sample_sha256": digest(sample_path),
        "checked_sha256": digest(checked_path),
        "block": checked["block"],
        "state_root_hash": checked["state_root_hash"],
        "body_and_full_state_checked": True,
        "required_rust_vote": require_bootstrap_vote(checked, required_vote)
        if required_vote is not None
        else None,
    }
