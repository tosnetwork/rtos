#!/usr/bin/env python3
"""Measure native shared identity quotas and independent-peer recovery."""

from pathlib import Path

from rldp2_runtime_reference import main

if __name__ == "__main__":
    main(Path(__file__).with_suffix(".cpp"))
