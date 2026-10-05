#!/usr/bin/python3
"""Fake `age` for the broker tests. NOT encryption: a file is "FAKEAGE\n<recipient>\n<payload>".

Copied into <sandbox>/bin/age; state lives in <sandbox>/state. Decrypt behaviour per leg (identity file
basename identity.txt = "touchid", anything else = "iphone") comes from state/age.json:
  {"touchid": {"mode": "ok|cancel|error|hang", "delay": 0.2}, "iphone": {...}}
Every run appends {"pid", "leg", "identity", "file", "mode"} to state/age.log.
"""
import json
import os
import sys
import time

STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))), "state")


def opt(args, name):
    return args[args.index(name) + 1] if name in args else None


def main():
    args = sys.argv[1:]
    if "-d" in args:
        ident, path = opt(args, "-i"), args[-1]
        leg = "touchid" if os.path.basename(ident) == "identity.txt" else "iphone"
        try:
            ctl = json.load(open(os.path.join(STATE, "age.json"))).get(leg, {})
        except (OSError, ValueError):
            ctl = {}
        mode = ctl.get("mode", "ok")
        with open(os.path.join(STATE, "age.log"), "a") as f:
            f.write(json.dumps({"pid": os.getpid(), "leg": leg, "identity": ident, "file": path, "mode": mode}) + "\n")
        time.sleep(float(ctl.get("delay", 0)))
        if mode == "hang":
            time.sleep(3600)
        if mode == "cancel":
            sys.stderr.write("age: error: Error Domain=com.apple.LocalAuthentication Code=-2 \"Canceled by user.\"\n")
            sys.exit(1)
        if mode == "error":
            sys.stderr.write("age: error: biometry is not available on this device\n")
            sys.exit(1)
        data = open(path).read().split("\n", 2)
        if len(data) != 3 or data[0] != "FAKEAGE" or data[1] != open(ident).read().strip():
            sys.stderr.write("age: error: no identity matched any of the recipients\n")
            sys.exit(1)
        sys.stdout.write(data[2])
        return
    rfile, out = opt(args, "-R"), opt(args, "-o")
    if not rfile or not out:
        sys.stderr.write("fake age: unsupported argv\n")
        sys.exit(2)
    payload = sys.stdin.read()
    with open(out, "w") as f:
        f.write("FAKEAGE\n%s\n%s" % (open(rfile).read().strip(), payload))
    with open(os.path.join(STATE, "age.log"), "a") as f:
        f.write(json.dumps({"pid": os.getpid(), "leg": "encrypt", "recipient": rfile, "file": out}) + "\n")


main()
