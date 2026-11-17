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
