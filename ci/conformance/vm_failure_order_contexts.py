#!/usr/bin/env python3
"""Emit VM failure-order boundary contexts; fill effects with the pinned TOS runner."""

import base64
import json


def integer(value):
    return {"type": "int", "value": str(value)}


def emit(name, code, stack):
    code = bytes.fromhex(code)
    # One ordinary, byte-aligned cell, no references or CRC.
    boc = (
        bytes.fromhex("b5ee9c720101010100")
        + bytes([len(code) + 2, 0, 0, len(code) * 2])
        + code
    )
    context = {
        "code": base64.b64encode(boc).decode(),
        "global_version": 16,
        "stack": stack,
        "gas": {"limit": 1000000, "max": 1000000},
    }
    print(json.dumps({"fixture_id": name, "context": context}))


def main():
    null = {"type": "null"}
    for opcode in ("61", "62", "63", "64"):
        for depth in (0, 1, 253):
            for index in (0, 1, 255, 256, 1023):
                args = [integer(index)]
                if opcode in ("63", "64"):
                    args.append(integer(1))
                emit(f"stack-{opcode}-{depth}-{index}", opcode, [null] * depth + args)
    for opcode in ("b600", "b601", "b7b600", "b7b601"):
        for depth in (0, 1, 2):
            for label, value in (
                ("null", null),
                ("negative", integer(-1)),
                ("large", integer(1024)),
                ("valid", integer(8)),
            ):
                stack = [] if depth == 0 else [integer(1)] * (depth - 1) + [value]
                emit(f"fits-{opcode}-{depth}-{label}", opcode, stack)
    for opcode in range(8):
        for length in (-1, 0, 256, 257, 258, 1 << 63):
            emit(
                f"store-{opcode}-{length}",
                f"cf0{opcode}",
                [null, null, integer(length)],
            )


if __name__ == "__main__":
    main()
