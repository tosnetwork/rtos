#!/usr/bin/env python3
"""Freeze the native RLDP2 local-identity connection eviction policy."""

from pathlib import Path

from rldp2_runtime_reference import main

if __name__ == "__main__":
    main(Path(__file__).with_suffix(".cpp"))
