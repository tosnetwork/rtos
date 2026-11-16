#!/usr/bin/env python3
"""Probe native RLDP2 query eviction and subsequent connection recovery."""

from pathlib import Path

from rldp2_runtime_reference import main

if __name__ == "__main__":
    main(Path(__file__).with_suffix(".cpp"), "test-rldp2-refusal-lifetime")
