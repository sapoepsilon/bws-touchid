#!/usr/bin/python3
"""Fake `bws` (Bitwarden SM CLI) for the broker tests. Logs argv + which token it got to state/bws.log."""
import json
import os
import sys

STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))), "state")
AGENTS = "11111111-1111-1111-1111-111111111111"
MAIL = "22222222-2222-2222-2222-222222222222"
NEW = "33333333-3333-3333-3333-333333333333"
args = [a for a in sys.argv[1:]]
with open(os.path.join(STATE, "bws.log"), "a") as f:
    f.write(json.dumps({"argv": args, "token": os.environ.get("BWS_ACCESS_TOKEN", "")}) + "\n")
pos = [a for i, a in enumerate(args) if not a.startswith("-") and (i == 0 or args[i - 1] not in ("--color", "--output", "--note", "--value", "--server-url"))]
if pos[:2] == ["project", "list"]:
    out = [{"id": AGENTS, "name": "agents"}, {"id": MAIL, "name": "mail"}]
elif pos[:2] == ["secret", "list"]:
    out = [{"id": NEW, "key": "MAIL_PASSWORD", "projectId": MAIL}] if len(pos) < 3 or pos[2] == MAIL else []
elif pos[:2] == ["secret", "create"]:
    out = {"id": NEW, "key": pos[2]}
elif pos[:2] == ["secret", "get"]:
    out = {"id": pos[2], "key": "SOME_KEY", "value": "fake-value", "projectId": AGENTS}
elif pos[:2] == ["project", "get"]:
    out = {"id": pos[2], "name": "agents"}
else:
    sys.stderr.write("fake bws: unsupported %r\n" % pos)
    sys.exit(2)
print(json.dumps(out))
