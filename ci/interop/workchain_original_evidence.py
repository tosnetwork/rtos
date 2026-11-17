"""Collect original WC proofs without changing the caller's recovery deadline."""

import asyncio
import copy
import json
import time
from pathlib import Path

from mixed_matrix import child_checked, native_state, write
from workchain_output_evidence import (
    block_text,
    matches_workchain_outputs,
    sealed_workchain_outputs,
)


def plan_workchain_requests(intent, sealed, captures, checkpoint):
    """Plan every output using exact captured parent identities, not heights.

    Capture provenance and checkpoint provenance are caller obligations. This is
    only request construction: the native checker must authenticate all links,
    carriers, source creators, governing history and full states afterward.
    """
    blocks = sealed_workchain_outputs(intent, sealed)
    if not 1 <= len(captures) <= 128:
        raise ValueError("Original WC proof requires bounded captured carriers")
    by_block, by_role = {}, {}
    for row in captures:
        key = block_text(row["block"]["id"])
        body = (row["block"], row["previous"])
        if key in by_block and by_block[key] != body:
            raise ValueError("Captured WC body or parent identities are ambiguous")
        by_block[key] = body
        if type(row["is_final"]) is not bool:
            raise ValueError("Captured WC role is not explicit")
        role_key = (key, row["is_final"])
        carrier = row["signature_set"]
        if role_key in by_role and by_role[role_key] != carrier:
            raise ValueError("Captured WC carrier is ambiguous")
        by_role[role_key] = carrier
    anchor = checkpoint["workchain"]["block"]
    requests = []
    for output, block in zip(sealed["outputs"], blocks, strict=True):
        target = block_text(block)
        carrier = by_role.get((target, output["is_final"]))
        if carrier is None:
            raise ValueError("Missing original WC carrier; cannot omit obligation")
        cursor, chain, visited = anchor, [], set()
        while block_text(cursor["id"]) != target:
            key = block_text(cursor["id"])
            if key in visited or len(chain) >= 64:
                raise ValueError("Original WC ancestry exceeds the native bound")
            visited.add(key)
            if key not in by_block or by_block[key][0] != cursor:
                raise ValueError("Missing exact captured WC anchor body")
            parents = by_block[key][1]
            if len(parents) != 1:
                raise ValueError("Original WC split/merge ancestry is not supported")
            parent = block_text(parents[0])
            if parent not in by_block:
                raise ValueError("Missing captured WC ancestor")
            chain.append(copy.deepcopy(cursor))
            cursor = by_block[parent][0]
        request = copy.deepcopy(checkpoint)
        request["mode"] = "workchain-carrier"
        request["workchain"] = {
            "block": copy.deepcopy(by_block[target][0]),
            "states": [],
            "anchor_chain": chain,
        }
        request["workchain_certificate"] = {
            "is_final": output["is_final"],
            "signature_set": carrier,
        }
        requests.append(request)
    return requests


async def verify_workchain_intent(
    intent,
    sealed,
    *,
    captures,
    checkpoint,
    state_configs,
    snapshot,
    checker,
    directory,
    deadline,
):
    """Fetch fresh state copies and check all outputs under one original budget.

    The caller proves original file binding, original DB identity, unsigned role,
    cleanup and progress. Historical checkpoint RPC metadata remains historical;
    it is not represented as a fresh observation of current heads.
    """
    if time.monotonic() >= deadline:
        raise TimeoutError("Original WC recovery deadline expired")
    requests = plan_workchain_requests(intent, sealed, captures, checkpoint)
    expected = [x["name"] for x in checkpoint["workchain"]["states"]]
    if len(set(expected)) != len(expected) or set(state_configs) != set(expected):
        raise ValueError("Fresh WC states must cover every original declared source")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)

    async def collect():
        checked = []
        for ordinal, request in enumerate(requests):
            target = directory / str(ordinal)
            target.mkdir()
            block = request["workchain"]["block"]["id"]
            tasks = [
                asyncio.create_task(
                    native_state(
                        snapshot, state_configs[name], name, block, target / name
                    )
                )
                for name in expected
            ]
            try:
                request["workchain"]["states"] = await asyncio.gather(*tasks)
            finally:
                # gather does not cancel siblings when one source fails. Own
                # every native child until its cancellation cleanup finishes.
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            write(target / "request.json", request)
            await child_checked(
                [checker, target / "request.json", target / "checked.json"],
                target / "checker.log",
            )
            checked.append(json.loads((target / "checked.json").read_text()))
        if not matches_workchain_outputs(intent, sealed["outputs"], checked):
            raise ValueError("Native WC proofs do not cover the exact original set")
        return checked

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Original WC recovery deadline expired before collection")
    results = await asyncio.wait_for(collect(), remaining)
    if time.monotonic() >= deadline:
        raise TimeoutError("Original WC recovery deadline expired during verification")
    write(
        directory / "receipt.json",
        {
            "outputs_checked": len(results),
            "fresh_state_sources": expected,
            "exact_final_trigger_and_complete_set_checked": True,
            "scope": "Original WC proofs only; caller separately qualifies recovery",
        },
    )
    return results
