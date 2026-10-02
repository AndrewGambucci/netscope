#!/usr/bin/env python3
"""Convenience launcher for a source checkout: `python3 app.py` (same as `python3 -m netscope`)."""
import sys

from netscope.cli import main

if __name__ == "__main__":
    sys.exit(main())
