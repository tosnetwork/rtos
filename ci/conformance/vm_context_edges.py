#!/usr/bin/env python3
"""Emit regression inputs for varint, random-state, slice-window and version boundaries."""

import base64
import json


def integer(value):
    return {"type": "int", "value": str(value)}


def emit(name, code, stack, version=16, **extra):
    raw = bytes.fromhex(code)
    boc = (
        bytes.fromhex("b5ee9c720101010100")
        + bytes([len(raw) + 2, 0, 0, len(raw) * 2])
        + raw
    )
    context = {
        "code": base64.b64encode(boc).decode(),
        "stack": stack,
        "global_version": version,
        "gas": {"limit": 1000000, "max": 1000000},
        **extra,
    }
    print(json.dumps({"fixture_id": name, "context": context}))


def main():
    null = {"type": "null"}
    for op in ("fa02", "fa03", "fa06", "fa07"):
        for label, value in (
            ("nan", {"type": "nan"}),
            ("null", null),
            ("negative", integer(-1)),
            ("zero", integer(0)),
            ("large", integer(1 << 248)),
        ):
            emit(f"varint-{op}-{label}-invalid-builder", op, [null, value])
            emit(f"varint-{op}-{label}-builder", "c801" + op, [value])
    for op in ("f814", "f815"):
        for size in (0, 1, 6, 7, 8, 255):
            inner = [null] * size
            if size >= 7:
                inner[6] = integer(0)
            c7 = {"type": "tuple", "items": [{"type": "tuple", "items": inner}]}
            for gas in (26, 32, 33, 34, 1000000):
                emit(
                    f"random-{op}-{size}-{gas}",
                    op,
                    [integer(0)],
                    c7=c7,
                    gas={"limit": gas, "max": gas},
                )
    for opcode in ("60", "61", "62", "63", "64", "65", "67", "69", "6a", "6b"):
        for version in (3, 4):
            for index in (0, 255, 256):
                args = [integer(index)] + (
                    [integer(1)] if opcode in ("63", "64") else []
                )
                emit(
                    f"index-{opcode}-{version}-{index}", opcode, [null] + args, version
                )
    source = {"type": "slice", "boc": "te6ccgEBAgEADAABDv0sB/XpZSIBAAA="}
    for prefix in ("", "d4"):
        for op in ("d600", "d637", "70d718", "70d719", "70d71a", "70d71b"):
            emit(f"slice-{prefix or 'fresh'}-{op}", prefix + op, [source])


if __name__ == "__main__":
    main()
