#!/usr/bin/env python3
"""Inspect the fixed interop inventory and plan dependency-ordered selections."""

import argparse
import hashlib
import json
from pathlib import Path

CATALOG = Path(__file__).with_name("scenario_catalog.json")


def validate(catalog, source_root):
    """Reject incomplete source inventories and invalid dependency graphs."""
    if catalog.get("schema") != 1:
        raise ValueError("Unsupported scenario catalog schema")
    entries = catalog["scenarios"]
    by_id = {entry["id"]: entry for entry in entries}
    if not entries or len(by_id) != len(entries):
        raise ValueError("Scenario IDs must be unique and nonempty")
    actual = {
        p.name
        for p in source_root.glob("*_fixture.py")
        if not p.name.startswith("test_")
    }
    if set(catalog["fixture_sources"]) != actual:
        raise ValueError("Fixture sources changed: review the fixed scenario inventory")
    for entry in entries:
        driver = entry["driver"]
        if Path(driver).name != driver or not (source_root / driver).is_file():
            raise ValueError("Scenario driver must be an existing local file")
        if entry["execution"] != "unintegrated":
            raise ValueError("No execution adapter is qualified by this inventory tool")
        if not entry["scope"].strip():
            raise ValueError("Every scenario needs an assertion scope")
        if any(dep not in by_id for dep in entry["depends_on"]):
            raise ValueError("Unknown scenario dependency")
    order(by_id, list(by_id))
    return by_id


def order(by_id, selected):
    """Expand controls before dependents, preserving declared selection order."""
    result, visiting, visited = [], set(), set()

    def visit(name):
        if name not in by_id:
            raise ValueError(f"Unknown scenario: {name}")
        if name in visiting:
            raise ValueError("Scenario dependency cycle")
        if name in visited:
            return
        visiting.add(name)
        for dependency in by_id[name]["depends_on"]:
            visit(dependency)
        visiting.remove(name)
        visited.add(name)
        result.append(name)

    for name in selected:
        visit(name)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["list", "plan"])
    parser.add_argument("scenarios", nargs="*")
    args = parser.parse_args()
    raw = CATALOG.read_bytes()
    catalog = json.loads(raw)
    by_id = validate(catalog, CATALOG.parent)
    if args.command == "list" and args.scenarios:
        parser.error("list takes no scenario selections")
    selected = args.scenarios or list(by_id)
    names = order(by_id, selected)
    print(
        json.dumps(
            {
                "schema": 1,
                "catalog_sha256": hashlib.sha256(raw).hexdigest(),
                "status": "inventory_only"
                if args.command == "list"
                else "not_executed",
                "qualification": catalog["qualification"],
                "selected": selected,
                "scenarios": [by_id[name] for name in names],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
