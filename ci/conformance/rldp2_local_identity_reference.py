#!/usr/bin/env python3
"""Probe healthy-peer progress beside silent native RLDP2 response transfers."""

from pathlib import Path

from rldp2_runtime_reference import main

if __name__ == "__main__":
    main(Path(__file__).with_suffix(".cpp"), "test-rldp2-refusal-lifetime")
