"""Decode captured schema-5 rows; checksums are integrity, never finality proof."""

import base64
import hashlib
import json
import struct
from pathlib import Path

MAX_ROW = 16 << 20


def decode_body(raw):
    if len(raw) > MAX_ROW or len(raw) < 151:
        raise ValueError("Captured body size is outside its bound")
    if hashlib.sha256(raw[:-32]).digest() != raw[-32:]:
        raise ValueError("Captured publication checksum differs")
    position = 0
    end = len(raw) - 32

    def take(size):
        nonlocal position
        if size > end - position:
            raise ValueError("Truncated captured publication")
        value = raw[position : position + size]
        position += size
        return value

    def integer(fmt):
        return struct.unpack(fmt, take(struct.calcsize(fmt)))[0]

    def blob():
        return take(integer("<I"))

    def boolean():
        value = integer("<B")
        if value not in (0, 1):
            raise ValueError("Invalid captured boolean")
        return bool(value)

    def block():
        wc, shard, seqno = integer("<i"), integer("<Q"), integer("<I")
        return {
            "@type": "tos.blockIdExt",
            "workchain": wc,
            "shard": str(shard if shard < 1 << 63 else shard - (1 << 64)),
            "seqno": seqno,
            "root_hash": base64.b64encode(take(32)).decode(),
            "file_hash": base64.b64encode(take(32)).decode(),
        }

    if take(8) != b"RTOSPBXB" or integer("<H") != 5:
        raise ValueError("Unsupported captured publication schema")
    domain = take(32).hex()
    record_id, protocol = integer("<Q"), integer("<B")
    if protocol not in (0, 1, 2):
        raise ValueError("Unsupported captured protocol")
    profile, session = take(32).hex(), take(32).hex()
    identity = block()
    count = integer("<B")
    if count > 2:
        raise ValueError("Too many captured parent blocks")
    previous = [block() for _ in range(count)]
    is_final, carrier = boolean(), blob()
    local, created, expires = boolean(), integer("<Q"), integer("<Q")
    body = blob()
    proof = blob() if boolean() else None
    if position != end or not carrier or not body:
        raise ValueError("Captured body is incomplete or has trailing bytes")
    if identity["workchain"] != 0 or identity["seqno"] <= 0:
        raise ValueError("Expected a produced workchain-0 block")
    if hashlib.sha256(body).digest() != base64.b64decode(identity["file_hash"]):
        raise ValueError("Captured body file hash differs")
    return {
        "record_id": record_id,
        "domain": domain,
        "protocol": protocol,
        "profile": profile,
        "session": session,
        "block": {"id": identity, "boc": base64.b64encode(body).decode()},
        "previous": previous,
        "is_final": is_final,
        "signature_set": base64.b64encode(carrier).decode(),
        "locally_generated": local,
        "created": created,
        "expires": expires,
        "proof": base64.b64encode(proof).decode() if proof is not None else None,
    }


def read_capture(directory, pid, session):
    directory = Path(directory)
    if (directory / "failed").exists():
        raise ValueError("Publication capture reported failure")
    paths = sorted(directory.glob("*.bin"))
    if not 1 <= len(paths) <= 128:
        raise ValueError("Missing or excessive captured publications")
    total, result = 0, []
    for path in paths:
        receipt_path = path.with_suffix(".json")
        if path.is_symlink() or receipt_path.is_symlink():
            raise ValueError("Captured publication requires owned regular files")
        with path.open("rb") as stream:
            raw = stream.read(MAX_ROW + 1)
        total += len(raw)
        if total > 64 << 20:
            raise ValueError("Captured publication total exceeds bound")
        receipt = json.loads(receipt_path.read_text())
        digest = hashlib.sha256(raw).hexdigest()
        if (
            path.stem != digest
            or receipt.get("sha256") != digest
            or receipt.get("pid") != pid
            or receipt.get("session") != session
            or receipt.get("bytes") != len(raw)
            or receipt.get("after_live_acceptance") is not True
        ):
            raise ValueError("Captured publication source binding differs")
        value = decode_body(raw)
        if value["session"] != session or receipt.get("key") != (
            f"LiveAcceptance/b/{value['record_id']:016x}"
        ):
            raise ValueError("Captured publication record identity differs")
        result.append(value)
    return result
