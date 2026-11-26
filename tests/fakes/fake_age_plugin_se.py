#!/usr/bin/python3
"""Fake age-plugin-se: `keygen --access-control X -o FILE` and `recipients -i FILE -o OUT`.
The fake identity string doubles as its recipient (see fake_age.py). No Secure Enclave involved."""
import binascii
import json
import os
import sys

STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))), "state")
args = sys.argv[1:]
with open(os.path.join(STATE, "plugin.log"), "a") as f:
    f.write(json.dumps(args) + "\n")
out = args[args.index("-o") + 1]
if args[0] == "keygen":
    ac = args[args.index("--access-control") + 1]
    data = "AGE-PLUGIN-SE-FAKE-%s-%s" % (ac, binascii.hexlify(os.urandom(4)).decode())
else:
    data = open(args[args.index("-i") + 1]).read().strip()
with open(out, "w") as f:
    f.write(data + "\n")
