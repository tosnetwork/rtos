"""Bind finite expiry to the node's configured and actually loaded custody key."""

import base64
import hashlib
import json
import re
from pathlib import Path

from mixed_matrix import digest


def capture_custody_authority(node, expire_at):
    """Read authority only; never renew it, copy key bytes, or claim runtime expiry."""
    node = Path(node).resolve()
    if type(expire_at) is not int or not 0 < expire_at <= 0x7FFFFFFF:
        raise ValueError("Custody expiry must be a finite supported timestamp")
    config_path, prepared_path = node / "config.json", node / "validator-prepared.json"
    config = json.loads(config_path.read_text())["pq_consensus"]
    prepared = json.loads(prepared_path.read_text())
    validator = hashlib.sha256(b"n6-validator-id-5").hexdigest()
    keys = config.get("keys")
    if (
        config.get("@type") != "engine.validator.pqConsensus"
        or config.get("validator_id")
        != base64.b64encode(bytes.fromhex(validator)).decode()
        or config.get("consensus_key_file") != ""
        or not isinstance(keys, list)
        or len(keys) != 1
        or not isinstance(keys[0], dict)
        or type(prepared.get("public_test_member")) is not int
        or prepared["public_test_member"] != 5
        or prepared.get("validator_id") != validator
        or type(prepared.get("signer_expire_at")) is not int
        or prepared["signer_expire_at"] != expire_at
    ):
        raise ValueError("Custody identity or declared authority differs")
    entry = keys[0]
    if (
        entry.get("@type") != "engine.validator.pqConsensusKey"
        or type(entry.get("valid_from")) is not int
        or entry["valid_from"] != 0
        or type(entry.get("expire_at")) is not int
        or entry["expire_at"] != expire_at
    ):
        raise ValueError("Custody window differs from original finite authority")
    filename = entry.get("consensus_key_file")
    if type(filename) is not str or filename != prepared.get("consensus_key_file"):
        raise ValueError("Prepared custody key path differs")
    key = Path(filename)
    owned = node / "consensus-keys"
    if (
        not key.is_absolute()
        or key.is_symlink()
        or not key.resolve().is_relative_to(owned)
        or not key.is_file()
    ):
        raise ValueError("Custody key is outside the original owned directory")
    key_id = prepared.get("consensus_key_id")
    if type(key_id) is not str or not re.fullmatch("[0-9a-f]{64}", key_id):
        raise ValueError("Prepared custody key identity is malformed")
    loaded = (
        f"post-quantum consensus custody: validator_id {validator} "
        f"key_id {key_id} valid_from 0 expire_at {expire_at}"
    )
    if loaded not in (node / "node.log").read_text(errors="replace").splitlines():
        raise ValueError(
            "Original process did not record loading the declared custody key"
        )
    return {
        "kind": "configured_pq_custody",
        "validator": validator,
        "key_id": key_id,
        "valid_from": 0,
        "expire_at": expire_at,
        "loaded_line": loaded,
        "authority_file_hashes": {
            str(path): digest(path) for path in (config_path, prepared_path, key)
        },
    }
