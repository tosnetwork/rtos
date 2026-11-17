#!/usr/bin/env python3
"""Probe repeated native outbound saturation and real decode/ACK retirement."""

from pathlib import Path

from rldp2_runtime_reference import main

if __name__ == "__main__":
    main(Path(__file__).with_suffix(".cpp"))
