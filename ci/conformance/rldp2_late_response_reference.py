#!/usr/bin/env python3
"""Run the pinned native late-response fixture, retaining source/build receipts."""

from pathlib import Path

from rldp2_runtime_reference import main

if __name__ == "__main__":
    main(Path(__file__).with_suffix(".cpp"), "test-rldp2-refusal-lifetime")
