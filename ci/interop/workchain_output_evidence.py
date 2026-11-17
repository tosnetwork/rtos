"""Match complete WC obligations to independently executed native checker outputs."""

import base64


def block_text(block):
    return (
        f"({block['workchain']}:{int(block['shard']) % (1 << 64):016x}, "
        f"{block['seqno']}, rh {base64.b64decode(block['root_hash'], validate=True).hex()}, "
        f"fh {base64.b64decode(block['file_hash'], validate=True).hex()})"
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
