#!/usr/bin/env python3
# Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
"""Regenerate the public publication fixture with pinned native keys/signatures.

No operational key file is read. Native signing intentionally uses its normal
randomizer: retain the resulting bytes and receipt rather than promising the
signature bytes are identical across regenerations.
"""

import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cpp-build", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--input", type=Path)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
r = args.out.resolve()
if r.exists() and any(r.iterdir()):
    raise SystemExit("output directory must be empty to preserve earlier receipts")
r.mkdir(parents=True, exist_ok=True)
input_path = (
    args.input
    or repo / "rtos/src/full_node/finality/testdata/v2-publication-spool.json"
)
original = r / "original.json"
original.write_bytes(input_path.read_bytes())
helper = r / "native-helper/probe"
ref = str(args.cpp_build.resolve() / "test/conformance/conformance-ref-cli")
with (r / "native-build.log").open("w") as log:
    subprocess.run(
        [
            "python3",
            str(Path(__file__).with_name("publication_fixture_reference.py")),
            "--cpp-build",
            str(args.cpp_build.resolve()),
            "--out",
            str(r / "native-helper"),
        ],
        cwd=repo,
        stdout=log,
        stderr=subprocess.STDOUT,
        check=True,
    )
keys = [
    line.split()[2]
    for line in (r / "native-helper/native.log").read_text().splitlines()
    if line.startswith("KEY ")
]
assert len(keys) == 3 and all(len(bytes.fromhex(k)) == 1312 for k in keys)
(r / "native-public-keys.json").write_text(json.dumps(keys) + "\n")
cargo = [
    "cargo",
    "run",
    "--locked",
    "-j32",
    "--release",
    "-p",
    "rtos_api",
    "--example",
    "refresh_publication_fixture",
    "--",
]
with (r / "prepare.log").open("w") as log:
    subprocess.run(
        cargo
        + [
            "prepare",
            str(original),
            str(r / "native-public-keys.json"),
            str(r / "prepared.json"),
        ],
        cwd=repo,
        stdout=log,
        stderr=subprocess.STDOUT,
        check=True,
    )
old = json.loads(original.read_text())
data = json.loads((r / "prepared.json").read_text())
assert (
    data["reference_commit"] == (repo / "ci/conformance/REFERENCE").read_text().strip()
)
for name, fixture in [("old", old), ("prepared", data)]:
    inputs = "".join(
        fixture["state_boc"]
        + " "
        + row["block_boc"]
        + " "
        + row["candidate"]
        + " "
        + str(row["slot"])
        + "\n"
        for row in fixture["rows"]
    )
    done = subprocess.run(
        [str(helper), "--check"],
        input=inputs,
        text=True,
        capture_output=True,
        timeout=30,
        check=True,
    )
    (r / (name + "-full-native-context.log")).write_text(done.stdout + done.stderr)
    lines = done.stdout.splitlines()
    assert len(lines) == len(fixture["rows"]) == 2
    for row, line in zip(fixture["rows"], lines, strict=True):
        fields = line.split()
        assert len(fields) == 9 and fields[0] == "CHECK"
        assert fields[1].lower() == row["session"]
        assert int(fields[2]) == int(fields[3]) == row["subset_hash"]
        for field, value in zip(
            ["preimage", "approval_preimage", "candidate_preimage"],
            fields[6:9],
            strict=True,
        ):
            assert row[field] == value, (name, field)
# Native boundaries must reject mismatched governing state and candidate identity.
controls = json.loads((r / "prepared.json.controls.json").read_text())
for name, state, block, candidate, slot, expected in [
    (
        "wrong-governing-state",
        controls["wrong_governing_state"],
        data["rows"][0]["block_boc"],
        data["rows"][0]["candidate"],
        99,
        13,
    ),
    (
        "wrong-candidate-block",
        data["state_boc"],
        data["rows"][0]["block_boc"],
        controls["wrong_candidate"],
        99,
        19,
    ),
]:
    done = subprocess.run(
        [str(helper), "--check"],
        input=f"{state} {block} {candidate} {slot}\n",
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )
    (r / (name + ".log")).write_text(done.stdout + done.stderr)
    assert done.returncode == expected, (name, done.returncode)
requests = []
for row_index, row in enumerate(data["rows"]):
    for field, preimage in [
        ("signatures", "preimage"),
        ("approval_signatures", "approval_preimage"),
        ("candidate_signatures", "candidate_preimage"),
    ]:
        for signature_index, signature in enumerate(row[field]):
            requests.append(
                {
                    "row": row_index,
                    "field": field,
                    "signature_index": signature_index,
                    "member": signature["index"],
                    "preimage": row[preimage],
                }
            )
assert len(requests) == 18
(r / "signing-requests.json").write_text(json.dumps(requests, indent=2) + "\n")
done = subprocess.run(
    [str(helper)],
    input="".join(f"{q['member']} {q['preimage']}\n" for q in requests),
    text=True,
    capture_output=True,
    timeout=30,
    check=True,
)
(r / "native-signed.log").write_text(done.stdout)
keys = {}
signatures = []
for line in done.stdout.splitlines():
    kind, index, payload = line.split()
    if kind == "KEY":
        keys[int(index)] = payload
    else:
        assert kind == "SIGNATURE"
        signatures.append((int(index), payload))
assert len(keys) == 3 and len(signatures) == len(requests)
for member, key in keys.items():
    assert key == data["public_custody"][member]["public_key"]
crypto = []
for request, (member, signature) in zip(requests, signatures, strict=True):
    assert member == request["member"]
    data["rows"][request["row"]][request["field"]][request["signature_index"]][
        "signature"
    ] = signature
    for label, body, context in [
        ("valid", bytes.fromhex(request["preimage"]), b"TOS-CONSENSUS-SIMPLEX-v1"),
        (
            "wrong-message",
            bytes.fromhex(request["preimage"]) + b"!",
            b"TOS-CONSENSUS-SIMPLEX-v1",
        ),
        ("wrong-domain", bytes.fromhex(request["preimage"]), b"TOS-CONFIG-ADMIN-v1"),
    ]:
        values = {
            "message": body,
            "context": context,
            "signature": bytes.fromhex(signature),
            "public_key": bytes.fromhex(keys[member]),
        }
        crypto.append(
            {
                "scheme": "mldsa44",
                "operation": "verify",
                "inputs": {k: base64.b64encode(v).decode() for k, v in values.items()},
            }
        )
inputs = "".join(json.dumps(c) + "\n" for c in crypto)
(r / "crypto-inputs.jsonl").write_text(inputs)
done = subprocess.run(
    [ref, "crypto"],
    input=inputs,
    text=True,
    capture_output=True,
    timeout=30,
    check=True,
)
(r / "crypto-effects.jsonl").write_text(done.stdout)
effects = [json.loads(line) for line in done.stdout.splitlines()]
assert len(effects) == 54
for i, effect in enumerate(effects):
    assert effect == {
        "outcome": "verdict",
        "verdict": "valid" if i % 3 == 0 else "invalid",
    }, (i, effect)
(r / "fixture.json").write_text(json.dumps(data, indent=2) + "\n")
(r / "generation-receipt.json").write_text(
    json.dumps(
        {
            "reference_info": json.loads(
                subprocess.check_output([ref, "--info"], text=True)
            ),
            "input_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
            "output_sha256": hashlib.sha256(
                (r / "fixture.json").read_bytes()
            ).hexdigest(),
            "native_binary_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
            "native_contexts": 4,
            "governing_state_negative_exit": 13,
            "candidate_block_negative_exit": 19,
            "native_signatures": 18,
            "native_valid": 18,
            "native_wrong_message_rejected": 18,
            "native_wrong_domain_rejected": 18,
            "qualification": "Native-defined replacement fixture; node acceptance is separate.",
        },
        indent=2,
    )
    + "\n"
)
print(
    "4 native contexts/preimage sets match;18 signatures valid and36 negative controls rejected",
    flush=True,
)

with (r / "rust-verify.log").open("w") as log:
    subprocess.run(
        cargo + ["verify", str(r / "fixture.json")],
        cwd=repo,
        stdout=log,
        stderr=subprocess.STDOUT,
        check=True,
    )
receipt = json.loads((r / "generation-receipt.json").read_text())
receipt["rust_verification"] = "final/approval and creator signatures verified"
receipt["source_commit"] = subprocess.check_output(
    ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
).strip()
receipt["generator_sources"] = {
    str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
    for p in [
        Path(__file__).resolve(),
        Path(__file__).with_name("publication_fixture_reference.py"),
        Path(__file__).with_name("publication_fixture_reference.cpp"),
        repo / "tl/rtos_api/examples/refresh_publication_fixture.rs",
    ]
}
(r / "generation-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
