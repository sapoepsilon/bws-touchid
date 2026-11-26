#!/usr/bin/python3
"""Fake `age` for the broker tests. NOT encryption: a file is "FAKEAGE\n<recipient>\n<payload>".

Copied into <sandbox>/bin/age; state lives in <sandbox>/state. Decrypt behaviour per leg (identity file
basename identity.txt = "touchid", anything else = "iphone", `-j batchpass` = "passcode") comes from
state/age.json:
  {"touchid": {"mode": "ok|cancel|error|hang", "delay": 0.2, "until": "/path"}, "iphone": {...}, "passcode": {...}}
"until": do not answer before that file exists (the test releases the "sensor" when it is ready).
Every run appends {"pid", "leg", "identity", "file", "mode"} to state/age.log.

`-j batchpass` mimics age >= 1.3 with age-plugin-batchpass: the plugin must be on PATH, the passphrase
comes from the fd in AGE_PASSPHRASE_FD (AGE_PASSPHRASE itself is refused here so a test catches it), and
the file is "FAKEAGE-SCRYPT\n<salt>\n<sha256(salt + passphrase)>\n<payload>". Those runs also log their
full argv and environment, so tests can prove the passcode is in neither.
"""
import hashlib
import json
import os
import shutil
import sys
import time

STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))), "state")


def opt(args, name):
    return args[args.index(name) + 1] if name in args else None


def logline(obj):
    with open(os.path.join(STATE, "age.log"), "a") as f:
        f.write(json.dumps(obj) + "\n")


def control(leg):
    try:
        return json.load(open(os.path.join(STATE, "age.json"))).get(leg, {})
    except (OSError, ValueError):
        return {}


def wait_for(ctl):
    time.sleep(float(ctl.get("delay", 0)))
    end = time.time() + 60
    while ctl.get("until") and not os.path.exists(ctl["until"]) and time.time() < end:
        time.sleep(0.02)


def batchpass(args):
    if not shutil.which("age-plugin-batchpass", path=os.environ.get("PATH", "")):
        sys.stderr.write("age: error: age-plugin-batchpass: executable file not found in $PATH\n")
        sys.exit(1)
    if "AGE_PASSPHRASE" in os.environ:
        sys.stderr.write("fake age: refusing AGE_PASSPHRASE in the environment (use AGE_PASSPHRASE_FD)\n")
        sys.exit(3)
    try:
        fd = int(os.environ["AGE_PASSPHRASE_FD"])
        chunks = []
        while True:
            b = os.read(fd, 4096)
            if not b:
                break
            chunks.append(b)
    except (KeyError, ValueError, OSError) as e:
        sys.stderr.write("age: error: batchpass plugin: failed to read passphrase from fd: %s\n" % e)
        sys.exit(1)
    secret = b"".join(chunks).rstrip(b"\n")
    decrypt = "-d" in args
    leg = "passcode" if decrypt else "passcode-encrypt"
    ctl = control("passcode") if decrypt else {}
    mode = ctl.get("mode", "ok")
    logline({"pid": os.getpid(), "leg": leg, "identity": "batchpass", "file": args[-1] if decrypt else opt(args, "-o"),
             "mode": mode, "argv": sys.argv, "env": dict(os.environ), "work_factor":
             os.environ.get("AGE_PASSPHRASE_WORK_FACTOR", "")})
    if decrypt:
        wait_for(ctl)
        if mode == "hang":
            time.sleep(3600)
        if mode == "error":
            sys.stderr.write("age: error: something else broke\n")
            sys.exit(1)
        data = open(args[-1]).read().split("\n", 3)
        if len(data) != 4 or data[0] != "FAKEAGE-SCRYPT":
            sys.stderr.write("age: error: no identity matched any of the recipients\n")
            sys.exit(1)
        if hashlib.sha256(data[1].encode() + secret).hexdigest() != data[2]:
            sys.stderr.write("age: error: batchpass plugin: incorrect passphrase\n")
            sys.exit(1)
        sys.stdout.write(data[3])
        return
    out = opt(args, "-o")
    salt = os.urandom(8).hex()
    payload = sys.stdin.read()
    with open(out, "w") as f:
        f.write("FAKEAGE-SCRYPT\n%s\n%s\n%s" % (salt, hashlib.sha256(salt.encode() + secret).hexdigest(), payload))


def main():
    args = sys.argv[1:]
    if opt(args, "-j") == "batchpass":
        return batchpass(args)
    if "-d" in args:
        ident, path = opt(args, "-i"), args[-1]
        leg = "touchid" if os.path.basename(ident) == "identity.txt" else "iphone"
        ctl = control(leg)
        mode = ctl.get("mode", "ok")
        logline({"pid": os.getpid(), "leg": leg, "identity": ident, "file": path, "mode": mode})
        wait_for(ctl)
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
    logline({"pid": os.getpid(), "leg": "encrypt", "recipient": rfile, "file": out})


main()
