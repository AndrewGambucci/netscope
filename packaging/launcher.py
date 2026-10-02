"""Entry point for the frozen (PyInstaller) app."""
import multiprocessing
import sys

from netscope.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
