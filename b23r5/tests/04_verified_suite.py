#!/usr/bin/env python3
"""Exact stdlib unittest enumeration and result oracle. No skip/expected failure allowed."""
import runpy
from pathlib import Path
runpy.run_path(str(Path(__file__).resolve().parents[2]/"b23r6a/run_verified.py"),run_name="__main__")
