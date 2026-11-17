"""Match complete WC obligations to independently executed native checker outputs."""

import base64
import hashlib
import json
import re


def block_text(block):
    return (
        f"({block['workchain']}:{int(block['shard']) % (1 << 64):016x}, "
        f"{block['seqno']}, rh {base64.b64decode(block['root_hash'], validate=True).hex()}, "
        f"fh {base64.b64decode(block['file_hash'], validate=True).hex()})"
    )


def sealed_workchain_outputs(intent, sealed):
    """Decode the complete captured WC set, never filter unsupported outputs.

    The caller must bind the original sealed file bytes to the stopped node's
    capture. Its digest binds intent metadata, not the output list itself.
    This validates structure and binding; native checks authenticate each output.
    """
    canonical = json.dumps(intent, separators=(",", ":"), ensure_ascii=False).encode()
    if (
        type(intent.get("workchain")) is not int
        or intent["workchain"] != 0
        or type(intent.get("shard_prefix")) is not int
        or intent["shard_prefix"] != 1 << 63
        or not isinstance(sealed, dict)
        or sealed.get("schema") != 1
        or sealed.get("digest") != hashlib.sha256(canonical).hexdigest()
        or sealed.get("metadata") != dict(intent, certificate="")
        or type(sealed.get("released")) is not bool
        or not isinstance(sealed.get("outputs"), list)
        or not 1 <= len(sealed["outputs"]) <= 1024
    ):
        raise ValueError("Original WC intent lacks its complete bound output set")
    blocks, seen, final = [], set(), False
    for output in sealed["outputs"]:
        if (
            not isinstance(output, dict)
            or set(output) != {"block_id", "is_final", "source_validator"}
            or type(output.get("is_final")) is not bool
            or not isinstance(output.get("source_validator"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", output["source_validator"])
            or not isinstance(output.get("block_id"), str)
        ):
            raise ValueError("Malformed original WC output")
        match = re.fullmatch(
            r"\(0:8000000000000000, ([1-9][0-9]*), rh ([0-9a-f]{64}), fh ([0-9a-f]{64})\)",
            output["block_id"],
        )
        identity = (output["block_id"], output["is_final"], output["source_validator"])
        if match is None or identity in seen:
            raise ValueError("Unsupported or duplicate original WC output")
        seen.add(identity)
        seqno, root, file = match.groups()
        if int(seqno) > (1 << 32) - 1:
            raise ValueError("Original WC height exceeds protocol bound")
        final |= output["is_final"]
        blocks.append(
            {
                "@type": "tos.blockIdExt",
                "workchain": 0,
                "shard": str(-(1 << 63)),
                "seqno": int(seqno),
                "root_hash": base64.b64encode(bytes.fromhex(root)).decode(),
                "file_hash": base64.b64encode(bytes.fromhex(file)).decode(),
            }
        )
    if not final:
        raise ValueError("Original WC set lacks its Final trigger")
    return blocks


def verify_sealed_workchain_requests(
    intent, sealed, requests, checker, evidence, deadline
):
    """Verify every captured obligation; caller proves provenance and recovery."""
    sealed_workchain_outputs(intent, sealed)
    return verify_workchain_output_requests(
        intent, sealed["outputs"], requests, checker, evidence, deadline
    )


def matches_workchain_outputs(intent, outputs, witnesses):
    """Require every original output plus its exact Final trigger.

    This function matches already authenticated native output; it does not
    authenticate arbitrary JSON, prove original-DB cleanup or establish that
    a sealed set includes every output of an unfinished candidate walk.
    """
    if not outputs or len(outputs) > 1024:
        return False
    expected = set()
    for output in outputs:
        if type(output.get("is_final")) is not bool:
            return False
        key = (output["block_id"], output["is_final"], output["source_validator"])
        if key in expected:
            return False
        expected.add(key)
    covered, trigger = set(), False
    for checked in witnesses:
        wc = checked.get("workchain_check") or {}
        certificate = wc.get("verified_carrier") or {}
        role = certificate.get("is_final")
        if (
            checked.get("mode") != "workchain-carrier"
            or checked.get("status") != "block_and_state_match"
            or not any(
                c.get("final_certificate_checked") is True
                for c in checked.get("verified_final_certificates", [])
            )
            or type(wc.get("block", {}).get("workchain")) is not int
            or wc["block"]["workchain"] != 0
            or any(
                wc.get(flag) is not True
                for flag in (
                    "masterchain_anchor_checked",
                    "block_file_cell_and_header_checked",
                    "all_declared_states_match_block_update",
                )
            )
            or type(role) is not bool
            or certificate.get("final_certificate_checked") is not role
            or certificate.get("approval_checked") is not (not role)
        ):
            continue
        key = (
            block_text(wc["block"]),
            role,
            base64.b64decode(wc["created_by"], validate=True).hex(),
        )
        if key not in expected:
            continue
        covered.add(key)
        if (
            role
            and base64.b64decode(certificate["session_id"], validate=True).hex()
            == intent["session_id"]
            and type(certificate.get("slot")) is int
            and type(intent.get("slot")) is int
            and certificate["slot"] == intent["slot"]
            and certificate["candidate_hash"] == intent["candidate_hash"]
        ):
            trigger = True
    return covered == expected and trigger


def verify_workchain_output_requests(
    intent, outputs, requests, checker, evidence, deadline
):
    """Re-run original native requests within the caller's existing deadline.

    The caller must separately verify original-DB cleanup and the provenance and
    completeness of the captured obligations. No new recovery budget is created.
    """
    import json
    import subprocess
    import time
    from pathlib import Path

    if not outputs or not 1 <= len(requests) <= len(outputs) <= 1024:
        raise ValueError("Expected bounded native requests for original outputs")
    if time.monotonic() >= deadline:
        raise TimeoutError("Original output verification deadline expired")
    evidence = Path(evidence)
    evidence.mkdir(parents=True, exist_ok=False)
    checked = []
    for index, source in enumerate(requests):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Original output verification deadline expired")
        raw = Path(source).read_bytes()
        if json.loads(raw).get("mode") != "workchain-carrier":
            raise ValueError(
                "Original output requires a native workchain carrier request"
            )
        request, result = evidence / f"{index}.json", evidence / f"{index}-checked.json"
        with request.open("xb") as stream:
            stream.write(raw)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Original output verification deadline expired")
        run = subprocess.run(
            [str(checker), str(request), str(result)],
            check=False,
            capture_output=True,
            timeout=remaining,
        )
        (evidence / f"{index}.log").write_bytes(run.stdout + run.stderr)
        if run.returncode:
            raise RuntimeError("Native original output verification failed")
        checked.append(json.loads(result.read_text()))
    if time.monotonic() >= deadline:
        raise TimeoutError("Original output verification deadline expired")
    if not matches_workchain_outputs(intent, outputs, checked):
        raise ValueError(
            "Native witnesses do not cover the complete original output set"
        )
    return checked
