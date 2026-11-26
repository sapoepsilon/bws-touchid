#!/usr/bin/python3
"""Fake /usr/bin/tmutil: logs argv to state/tmutil.log; state/tmutil.json {"mode": "ok|error"}."""
import json
import os
import sys

STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))), "state")
try:
    ctl = json.load(open(os.path.join(STATE, "tmutil.json")))
except (OSError, ValueError):
    ctl = {}
with open(os.path.join(STATE, "tmutil.log"), "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:]}) + "\n")
if ctl.get("mode") == "error":
    sys.stderr.write("tmutil: addexclusion requires Full Disk Access privileges.\n")
    sys.exit(80)
