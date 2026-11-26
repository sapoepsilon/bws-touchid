#!/usr/bin/python3
"""Fake age-plugin-batchpass: only has to exist on PATH; tests/fakes/fake_age.py does the work."""
import sys

sys.stderr.write("fake age-plugin-batchpass: not meant to be run directly\n")
sys.exit(1)
