"""Explicit unsigned conversion and authenticated original-obligation completion.

The caller must stop the original process, prove natural expiry, start the same
node directory, and provide fresh full-node progress observations. These helpers
never synthesize a completed-v1 record or write to the original database.
"""

import hashlib
import json
import time
from pathlib import Path

from accepted_intent_evidence import verify_masterchain_intent
from mixed_matrix import write


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class UnsignedConfiguration:
    def __init__(self, node_directory, evidence, *, expected_before_sha256):
        self.node = Path(node_directory)
        self.directory = Path(evidence)
        self.config = self.node / "config.json"
        self.database = self.node / "node_db"
        if self.config.is_symlink() or self.database.is_symlink():
            raise ValueError("Unsigned conversion needs the original owned node files")
        stat = self.database.stat()
        if not self.database.is_dir():
            raise ValueError("Original database directory is absent")
        self.database_identity = (stat.st_dev, stat.st_ino)
        before_raw = self.config.read_bytes()
        if sha(before_raw) != expected_before_sha256:
            raise ValueError(
                "Configuration changed since original natural expiry binding"
            )
        before = json.loads(before_raw)
        if not before.get("pq_consensus"):
            raise ValueError("Expected an explicitly provisioned signing configuration")
        self.after = {
            key: value
            for key, value in before.items()
            if key not in {"pq_consensus", "validator_keys"}
        }
        self.directory.mkdir(parents=True, exist_ok=False)
        (self.directory / "config-before.json").write_bytes(before_raw)
        after_raw = (json.dumps(self.after, indent=2) + "\n").encode()
        # Exclusive temporary creation avoids overwriting another operation.
        temporary = self.config.with_suffix(".unsigned.tmp")
        with temporary.open("xb") as stream:
            stream.write(after_raw)
        temporary.chmod(self.config.stat().st_mode & 0o777)
        temporary.replace(self.config)
        (self.directory / "config-after.json").write_bytes(after_raw)
        self.after_hash = sha(after_raw)
        self.receipt = {
            "mode": "explicit_unsigned_original_database",
            "before_sha256": sha(before_raw),
            "after_sha256": self.after_hash,
            "hash_encoding": "original_file_bytes",
            "removed_fields": ["pq_consensus", "validator_keys"],
            "all_other_fields_unchanged": True,
            "database": str(self.database),
            "database_device": stat.st_dev,
            "database_inode": stat.st_ino,
            "signing_configuration_removed": True,
            "original_config_unchanged": False,
        }
        write(self.directory / "receipt.json", self.receipt)

    def check(self):
        if self.config.is_symlink() or self.database.is_symlink():
            raise ValueError("Original unsigned node paths were replaced")
        stat = self.database.stat()
        if (stat.st_dev, stat.st_ino) != self.database_identity or sha(
            self.config.read_bytes()
        ) != self.after_hash:
            raise ValueError("Original database or unsigned configuration changed")


def check_cleanup_capture(pending, control, expiry_receipt, pid):
    """Bind the preload's pre-expiry capture to the stopped node's obligations."""
    control = Path(control)
    if expiry_receipt.get("cleanup_capture_before_expiry") is not True:
        raise ValueError("No observed cleanup capture before natural expiry")
    fields = (control / "captured").read_text().splitlines()
    if len(fields) != 5 or int(fields[0]) != pid:
        raise ValueError("Cleanup capture belongs to another process")
    output_path, intent_path = map(Path, fields[3:5])
    if output_path != intent_path.parent / "outputs-v1" / (
        intent_path.stem + ".outputs"
    ):
        raise ValueError("Cleanup output does not belong to the original intent")
    stat = output_path.stat()
    if (stat.st_dev, stat.st_ino) != (int(fields[1]), int(fields[2])):
        raise ValueError("Captured output inode changed before restart")
    matching = [
        item
        for item in pending.records
        if pending.namespaces / item["path"] == intent_path
    ]
    if len(matching) != 1:
        raise ValueError("Captured intent is not in the complete original frontier")
    item = matching[0]
    if (
        sha((control / "original.json").read_bytes()) != item["sha256"]
        or not item["sealed_outputs"]
        or sha((control / "original.outputs").read_bytes())
        != item["sealed_outputs"]["sha256"]
    ):
        raise ValueError("Captured original intent or sealed outputs changed")


def original_paths_removed(pending):
    """Absence alone is not acceptance; call only alongside original proofs."""
    if pending.namespaces.is_symlink():
        raise ValueError("Original namespace was replaced with a symlink")
    if not pending.records:
        raise ValueError("No original obligations captured")
    for item in pending.records:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Original obligation path escapes its namespace")
        path = pending.namespaces / relative
        output = path.parent / "outputs-v1" / (path.stem + ".outputs")
        for candidate in (path, output):
            if candidate.is_symlink() or any(
                parent.is_symlink()
                for parent in candidate.parents
                if parent != pending.namespaces and pending.namespaces in parent.parents
            ):
                raise ValueError("Original obligation path was replaced with a symlink")
            if candidate.exists():
                return False
    return True


async def complete_unsigned_originals(pending, configuration, *, deadline, **proof):
    """Authenticate all captured MC outputs, then recheck cleanup/config/DB.

    Returns False while original paths remain. Unsupported WC/Approval sets and
    any changed binding fail closed. The caller owns progress and runtime role
    evidence; this function does not issue an overall scenario verdict.
    """
    if time.monotonic() >= deadline:
        raise TimeoutError("Original recovery deadline expired")
    configuration.check()
    if not original_paths_removed(pending):
        return False
    results = []
    directory = Path(proof.pop("directory"))
    for ordinal, item in enumerate(pending.records):
        sealed = item.get("sealed_outputs")
        if not sealed:
            raise ValueError("Original obligation lacks its complete sealed output set")
        results.append(
            await verify_masterchain_intent(
                item["record"],
                sealed["record"],
                directory=directory / str(ordinal),
                deadline=deadline,
                **proof,
            )
        )
    configuration.check()
    if not original_paths_removed(pending):
        raise ValueError("Original obligations reappeared during proof verification")
    if time.monotonic() >= deadline:
        raise TimeoutError("Original recovery deadline expired during verification")
    write(
        directory / "original-obligations-checked.json",
        {
            "original_sets_checked": len(results),
            "outputs": results,
            "original_pending_and_output_paths_absent": True,
            "unsigned_configuration_unchanged": True,
            "original_database_directory_unchanged": True,
            "scope": "MC Final original obligations; caller must verify runtime role and progress",
        },
    )
    return True
