"""Authenticate every captured MC output after an original-database restart."""

import asyncio
import base64
import hashlib
import json
import re
import time
from pathlib import Path

from first_intent_vote import matches_final_intent
from mixed_matrix import child_checked, cpp_block, cpp_certificate, native_state, write


def masterchain_outputs(record, sealed):
    """Reject missing/unsealed or unsupported obligations rather than omit them."""
    canonical = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode()
    if (
        not isinstance(sealed, dict)
        or sealed.get("schema") != 1
        or sealed.get("digest") != hashlib.sha256(canonical).hexdigest()
        or sealed.get("metadata") != dict(record, certificate="")
        or type(sealed.get("released")) is not bool
        or not isinstance(sealed.get("outputs"), list)
        or not 1 <= len(sealed["outputs"]) <= 1024
    ):
        raise ValueError("Original intent lacks its complete bound sealed output set")
    blocks, seen = [], set()
    for output in sealed["outputs"]:
        if (
            set(output) != {"block_id", "is_final", "source_validator"}
            or output["is_final"] is not True
            or not re.fullmatch(r"[0-9a-f]{64}", output["source_validator"])
        ):
            raise ValueError("Expected MC Final output; unsupported obligations remain")
        match = re.fullmatch(
            r"\((-1):8000000000000000, ([1-9][0-9]*), rh ([0-9a-f]{64}), fh ([0-9a-f]{64})\)",
            output["block_id"],
        )
        if match is None or output["block_id"] in seen:
            raise ValueError("Invalid or duplicate original MC block identity")
        seen.add(output["block_id"])
        _, seqno, root, file = match.groups()
        blocks.append(
            {
                "@type": "tos.blockIdExt",
                "workchain": -1,
                "shard": str(-(1 << 63)),
                "seqno": int(seqno),
                "root_hash": base64.b64encode(bytes.fromhex(root)).decode(),
                "file_hash": base64.b64encode(bytes.fromhex(file)).decode(),
            }
        )
    return blocks


def check_original_output(output, block, checked, states):
    """Match already executed checker outputs; never authenticate JSON alone."""
    if (
        checked.get("block") != block
        or checked.get("mode") != "finality-witness"
        or checked.get("status") != "block_and_state_match"
        or checked.get("rpc_heads_checked") is not False
        or checked.get("state_update_matches_full_state") is not True
        or any(
            checked.get(flag) is not True
            for flag in (
                "file_hash_checked",
                "cell_hash_checked",
                "header_identity_checked",
            )
        )
        or base64.b64decode(checked.get("created_by", ""), validate=True).hex()
        != output["source_validator"]
        or not checked.get("verified_final_certificates")
        or any(
            c.get("final_certificate_checked") is not True
            for c in checked["verified_final_certificates"]
        )
        or states.get("mode") != "state-copies"
        or states.get("block") != block
        or not isinstance(checked.get("state_root_hash"), str)
        or not checked["state_root_hash"]
        or states.get("state_root_hash") != checked.get("state_root_hash")
        or set(states.get("sources", [])) != {"cpp-reference", "restarted-rust"}
        or len(states.get("sources", [])) != 2
        or states.get("finality_checked") is not False
    ):
        raise ValueError("Original MC output lacks matching authenticated state copies")


async def verify_masterchain_intent(
    record,
    sealed,
    *,
    snapshot,
    checker,
    cpp_node,
    cpp_config,
    rust_config,
    zero,
    governing,
    directory,
    deadline,
):
    """Collect and execute original proofs under the caller's unchanged deadline.

    This does not prove original-DB identity, absence of signing or cleanup. The
    caller must establish those separately. WC/Approval sets fail closed.
    """
    blocks = masterchain_outputs(record, sealed)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Original recovery deadline expired before proof collection")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)

    async def collect():
        trigger = False
        results = []
        for index, (output, block) in enumerate(
            zip(sealed["outputs"], blocks, strict=True)
        ):
            target = directory / str(index)
            target.mkdir()
            body = await cpp_block(snapshot, cpp_node, block, target)
            proof = await cpp_certificate(snapshot, cpp_node, zero, block, target)
            states = []
            for name, config in [
                ("cpp-reference", cpp_config),
                ("restarted-rust", rust_config),
            ]:
                states.append(
                    await native_state(snapshot, config, name, block, target / name)
                )
            request = {
                "mode": "finality-witness",
                "zerostate": zero,
                "block": body,
                "masterchain_state": states[0],
                "certificates": [proof],
                "governing_key_block": {**governing, "certificates": [proof]},
            }
            write(target / "finality.json", request)
            write(
                target / "states.json",
                {"mode": "state-copies", "block": body, "states": states},
            )
            for name in ("finality", "states"):
                await child_checked(
                    [checker, target / f"{name}.json", target / f"{name}-checked.json"],
                    target / f"{name}.log",
                )
            checked = json.loads((target / "finality-checked.json").read_text())
            state_checked = json.loads((target / "states-checked.json").read_text())
            check_original_output(output, block, checked, state_checked)
            trigger |= matches_final_intent(checked, record, workchain=-1)
            results.append({"block": block, "directory": str(target)})
        if not trigger:
            raise ValueError(
                "Original output set does not authenticate the exact Final trigger"
            )
        if time.monotonic() >= deadline:
            raise TimeoutError(
                "Original recovery deadline expired during proof collection"
            )
        write(
            directory / "receipt.json",
            {
                "original_trigger_checked": True,
                "outputs_checked": len(results),
                "outputs": results,
                "scope": "Complete captured MC Final set; caller owns cleanup/authority/DB checks",
            },
        )
        return results

    return await asyncio.wait_for(collect(), timeout=remaining)
