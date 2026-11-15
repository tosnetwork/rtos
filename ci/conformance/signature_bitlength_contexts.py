"""Emit CHKSIGN signature bit-length contexts; fill with the pinned C++ reference."""

import base64
import json


def cell(raw, bits=None):
    bits = len(raw) * 8 if bits is None else bits
    data = bytearray(raw[: (bits + 7) // 8])
    if bits % 8:
        data[-1] &= 0xFF << (8 - bits % 8)
        data[-1] |= 1 << (7 - bits % 8)
    payload = bytes([0, bits // 8 + (bits + 7) // 8]) + bytes(data)
    return base64.b64encode(
        bytes.fromhex("b5ee9c720101010100") + bytes([len(payload), 0]) + payload
    ).decode()


def integer(x):
    return {"type": "int", "value": str(x)}


rows = []
for version in [13, 14, 16]:
    for opcode in ["f910", "f911"]:
        for bits in range(504, 514):
            for key in [0, -1]:
                for valid_data in [True, False]:
                    data = (
                        integer(0 if valid_data else -1)
                        if opcode == "f910"
                        else {
                            "type": "slice",
                            "boc": cell(b"\0", 8 if valid_data else 7),
                        }
                    )
                    context = {
                        "code": cell(bytes.fromhex(opcode)),
                        "global_version": version,
                        "gas": {"limit": 1000000, "max": 1000000},
                        "stack": [
                            data,
                            {"type": "slice", "boc": cell(bytes(65), bits)},
                            integer(key),
                        ],
                    }
                    rows.append(
                        {
                            "fixture_id": f"{opcode}-v{version}-bits{bits}-key{key != 0}-data{valid_data}",
                            "context": context,
                        }
                    )
for row in rows:
    print(json.dumps(row))
