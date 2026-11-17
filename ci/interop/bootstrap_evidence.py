"""Full-state evidence for bootstrap diagnostics, using the native checker."""

import asyncio
import base64
import json

from mixed_matrix import child_checked, cpp_certificate, digest, identity, native_state
from receiver_evidence import require_receiver_check


async def collect_bootstrap_evidence(
    args, observation, rust_rpc, rpc, lite_config, cpp_node, zerostate, directory
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
    }
