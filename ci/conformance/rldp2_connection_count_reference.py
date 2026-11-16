#!/usr/bin/env python3
"""Probe the native RLDP2 global connection cap through send_message."""

from pathlib import Path

from rldp2_runtime_reference import main

if __name__ == "__main__":
    main(Path(__file__).with_suffix(".cpp"), "test-rldp2-refusal-lifetime")
