"""Prepare never-started, genesis-declared C++ successor fixture identities."""

import base64
import hashlib
import json
import subprocess

from cpp_baseline import ACTIVE_CPP_REVISION, PREVIOUS_ACTIVE_CPP_REVISION


def prepare_successor_ledgers(args, profile, nodes, zerostate, output):
    if profile["cpp_revision"] not in {
        ACTIVE_CPP_REVISION,
        PREVIOUS_ACTIVE_CPP_REVISION,
    }:
        return
    successors = set(profile["successor_members"]) - set(profile["initial_members"])
    if args.rust_node:
        successors -= {2, 3, 5}
    # Called after generation and comparison with the frozen genesis, before
    # starting any validator. Never repair an existing node's signing history.
    if profile.get("expected_zerostate") != zerostate:
        raise ValueError("successor ceremony requires the exact frozen genesis")
    hashes = [
        base64.b64decode(zerostate[key], validate=True)
        for key in ("root_hash", "file_hash")
    ]
    if any(len(value) != 32 for value in hashes):
        raise ValueError("invalid genesis hash length")
    planned = []
    for index in sorted(successors):
        node = nodes[index]
        expected = hashlib.sha256(f"n6-validator-id-{index}".encode()).digest()
        if node.pq_initial_validator.validator_id != expected:
            raise ValueError("successor fixture identity mismatch")
        if node.process_id is not None or node.directory.is_symlink():
            raise ValueError("successor ceremony requires a fresh stopped directory")
        entries = {path.name for path in node.directory.iterdir()}
        if entries != {"keyring", "pq-consensus.seed"}:
            raise ValueError("successor directory has existing or unexpected state")
        if any(path.is_symlink() for path in node.directory.iterdir()):
            raise ValueError("successor fixture paths must not be symlinks")
        command = [
            str(args.snapshot / "build/crypto/pq/tos-pq-consensus-key"),
            "init-signing-ledger",
            "--genesis-ceremony",
            str(node.directory),
            expected.hex(),
            *(value.hex() for value in hashes),
        ]
        planned.append((index, node.directory, command))
    receipts = []
    for index, directory, command in planned:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=30, check=False
        )
        receipts.append(
            {"member": index, "command": command, "exit_code": result.returncode}
        )
        (output / "successor-ledger-ceremony.json").write_text(
            json.dumps(receipts, indent=2) + "\n"
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"successor ledger ceremony failed: {result.stderr.strip()}"
            )
        if not (directory / "consensus/signing-ledger/ledger").is_file():
            raise RuntimeError("successor ceremony produced no ledger")
