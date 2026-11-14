"""Compare native served masterchain states; never infer sync from log messages."""

from copy import deepcopy


def identity(block):
    return (
        int(block["workchain"]),
        int(block["shard"]),
        int(block["seqno"]),
        block["root_hash"],
        block["file_hash"],
    )


class SyncObservation:
    def __init__(self, zero, min_height, max_checkpoints=512):
        if min_height < 1 or max_checkpoints < 1:
            raise ValueError("Require positive progress and bounded checkpoint storage")
        self.zero = deepcopy(zero)
        self.min_height = min_height
        self.max_checkpoints = max_checkpoints
        self.checkpoints = {}

    def observe(self, references, rust):
        if not references:
            raise ValueError("C++ reference observations are required")
        for item in [*references, rust]:
            if identity(item["init"]) != identity(self.zero):
                raise ValueError("Running node network identity differs from Genesis")
            if identity(item["last"])[0:2] != identity(self.zero)[0:2]:
                raise ValueError("Expected a masterchain observation")
        first = references[0]
        key = identity(first["last"])
        if all(
            identity(item["last"]) == key
            and item["state_root_hash"] == first["state_root_hash"]
            for item in references
        ):
            self.checkpoints[key] = deepcopy(references)
        while len(self.checkpoints) > self.max_checkpoints:
            del self.checkpoints[next(iter(self.checkpoints))]
        key = identity(rust["last"])
        matching = self.checkpoints.get(key)
        if key[2] < self.min_height or matching is None:
            return None
        if rust["state_root_hash"] != matching[0]["state_root_hash"]:
            raise ValueError(
                "Rust state root differs for the same C++ masterchain block"
            )
        return deepcopy({"zerostate": self.zero, "references": matching, "rust": rust})
