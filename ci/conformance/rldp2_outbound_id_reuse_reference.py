#!/usr/bin/env python3
"""Reproduce the pinned native active outbound ID duplicate rejection."""

from pathlib import Path

from rldp2_runtime_reference import main

if __name__ == "__main__":
    main(Path(__file__).with_suffix(".cpp"))
