#!/usr/bin/python3
"""Fake /usr/bin/osascript for the passcode dialog. Logs argv + env to state/osascript.log, then answers
like the real `display dialog ... with hidden answer` script in bws-touchid would.

state/osascript.json: {"answers": ["pass1", "pass2"], "mode": "ok|cancel|gaveup|hang|error", "delay": 0}
Each run takes the next answer (state/osascript.n counts runs); with answers used up it answers
"cancel". mode applies to every run.
"""
import json
import os
import sys
import time

STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))), "state")
try:
    ctl = json.load(open(os.path.join(STATE, "osascript.json")))
except (OSError, ValueError):
    ctl = {}
counter = os.path.join(STATE, "osascript.n")
n = int(open(counter).read()) if os.path.exists(counter) else 0
open(counter, "w").write(str(n + 1))
with open(os.path.join(STATE, "osascript.log"), "a") as f:
    f.write(json.dumps({"pid": os.getpid(), "argv": sys.argv, "env": dict(os.environ), "n": n}) + "\n")
time.sleep(float(ctl.get("delay", 0)))
mode = ctl.get("mode", "ok")
answers = ctl.get("answers", [])
if mode == "hang":
    time.sleep(3600)
if mode == "error":
    sys.stderr.write("execution error: Not authorized to send Apple events. (-1743)\n")
    sys.exit(1)
if mode == "cancel" or n >= len(answers):
    sys.stderr.write("execution error: User canceled. (-128)\n")
    sys.exit(1)
if mode == "gaveup":
    sys.stdout.write("T\n")
    sys.exit(0)
sys.stdout.write("P" + answers[n] + "\n")
