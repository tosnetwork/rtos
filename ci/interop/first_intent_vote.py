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
    if (
        checked.get("status") != "block_and_state_match"
        or checked.get("block", {}).get("workchain") != -1
        or checked.get("block", {}).get("seqno") != 1
    ):
        return False
    if any(
        checked.get(k) is not True
        for k in (
            "file_hash_checked",
            "cell_hash_checked",
            "header_identity_checked",
            "state_update_matches_both",
        )
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
