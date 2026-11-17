"""Independent successor vote evidence after a first-intent process restart."""

import base64
import hashlib


def post_restart_successor_vote(checked, member, restarted_at):
    successor = {
        base64.b64encode(
            hashlib.sha256(f"n6-validator-id-{i}".encode()).digest()
        ).decode()
        for i in (0, 2, 4, 5)
    }
    return (
        type(restarted_at) in (int, float)
        and type(checked.get("gen_utime")) is int
        and checked["gen_utime"] > restarted_at
        and checked.get("block", {}).get("workchain") == -1
        and checked.get("key_block") is False
        and bool(checked.get("verified_governing_key_blocks"))
        and {
            m["validator_id"]
            for m in checked.get("configuration", {})
            .get("current", {})
            .get("members", [])
        }
        == successor
        and any(
            certificate.get("final_certificate_checked") is True
            and member in certificate.get("validator_ids", [])
            for certificate in checked.get("verified_final_certificates", [])
        )
    )


def matches_original_intent(checked, record):
    """Match an intended Final to the native checker's authenticated candidate."""
    return (
        checked.get("mode") is None
        and checked.get("block", {}).get("seqno") == 1
        and matches_final_intent(checked, record, workchain=-1)
    )


def matches_final_intent(checked, record, *, workchain):
    """Bind a Final intent at any produced height to an already verified candidate.

    This matches native checker output; it does not authenticate JSON by itself or
    replace the separate original-block full-state witnesses and cleanup checks.
    """
    block = checked.get("block", {})
    if (
        checked.get("status") != "block_and_state_match"
        or type(workchain) is not int
        or type(block.get("workchain")) is not int
        or block["workchain"] != workchain
        or type(block.get("seqno")) is not int
        or block["seqno"] <= 0
        or type(record.get("slot")) is not int
    ):
        return False
    if any(
        checked.get(k) is not True
        for k in (
            "file_hash_checked",
            "cell_hash_checked",
            "header_identity_checked",
        )
    ):
        return False
    if checked.get("mode") == "finality-witness":
        if (
            checked.get("rpc_heads_checked") is not False
            or checked.get("state_update_matches_full_state") is not True
        ):
            return False
    elif (
        checked.get("mode") is not None
        or checked.get("state_update_matches_both") is not True
    ):
        return False
    for cert in checked.get("verified_final_certificates", []):
        try:
            session = base64.b64decode(cert.get("session_id", ""), validate=True).hex()
        except (ValueError, TypeError):
            continue
        if (
            cert.get("final_certificate_checked") is True
            and session == record["session_id"]
            and type(cert.get("slot")) is int
            and cert["slot"] == record["slot"]
            and cert.get("candidate_hash") == record["candidate_hash"]
        ):
            return True
    return False


def verify_original_acceptance(directory, receipt, record):
    """Check immutable native evidence, independently of retired completion files."""
    import json

    def read(name, key):
        raw = (directory / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != receipt.get(key):
            raise ValueError("First-intent acceptance evidence hash differs")
        return json.loads(raw)

    sample = read("accepted-sample.json", "acceptance_sample_sha256")
    checked = read("accepted-checked.json", "acceptance_checked_sha256")
    states = read("accepted-states.json", "acceptance_states_sha256")
    state_check = read(
        "accepted-states-checked.json", "acceptance_states_checked_sha256"
    )
    if (
        receipt.get("original_candidate_accepted") is not True
        or not matches_original_intent(checked, record)
        or sample.get("block", {}).get("id") != checked["block"]
        or states.get("block", {}).get("id") != checked["block"]
        or states.get("mode") != "state-copies"
        or state_check.get("mode") != "state-copies"
        or state_check.get("block") != checked["block"]
        or state_check.get("state_root_hash") != checked.get("state_root_hash")
        or set(state_check.get("sources", [])) != {"cpp-reference", "restarted-rust"}
        or state_check.get("finality_checked") is not False
    ):
        raise ValueError("First-intent original candidate/state acceptance differs")
    return checked


def historical_finality_request(record, block, state, context):
    """Bind a historical checker request to the captured live node carrier.

    The context only supplies governing-chain inputs; the native checker must
    authenticate that chain, the original certificate, block and full state.
    Live endpoint heads from a later sample are deliberately not copied.
    """

    def block_text(identity):
        return (
            f"({identity['workchain']}:{int(identity['shard']) % (1 << 64):016x}, "
            f"{identity['seqno']}, rh "
            f"{base64.b64decode(identity['root_hash'], validate=True).hex()}, fh "
            f"{base64.b64decode(identity['file_hash'], validate=True).hex()})"
        )

    if (
        record.get("is_final") is not True
        or block["id"]["workchain"] != -1
        or block_text(block["id"]) != record["block_id"]
        or state["id"] != block["id"]
        or block_text(context["zerostate"]) != record["zerostate"]
        or base64.b64decode(block["boc"], validate=True)
        != bytes.fromhex(record["data"])
    ):
        raise ValueError("Historical Final request differs from original live source")
    carrier = bytes.fromhex(record["signature_set"])
    if not carrier or len(carrier) > 16 * 1024 * 1024:
        raise ValueError("Historical Final carrier is empty or oversized")
    governing = {
        key: context[key]
        for key in ("governing_key_block", "governing_zerostate_boc")
        if key in context
    }
    if len(governing) != 1:
        raise ValueError("Historical Final request needs one governing context")
    return {
        "mode": "finality-witness",
        "zerostate": context["zerostate"],
        **governing,
        "block": block,
        "masterchain_state": state,
        "certificates": [
            {
                "kind": "node",
                "name": "original-live-acceptance",
                "signature_set": base64.b64encode(carrier).decode(),
            }
        ],
    }
