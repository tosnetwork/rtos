#!/usr/bin/env python3
"""Probe native query correlation by authenticated transfer rather than envelope ID."""

from pathlib import Path

from rldp2_runtime_reference import main

if __name__ == "__main__":
    main(Path(__file__).with_suffix(".cpp"), "test-rldp2-refusal-lifetime")
