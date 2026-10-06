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
# Parse like bws 2.x (clap): known options take the next arg or "=value"; after "--" everything is
# positional; any other "-"-leading arg before "--" is the real CLI's "unexpected argument" error.
WITH_VALUE = ("--color", "--output", "--note", "--value", "--server-url")
pos, opts, i = [], {}, 0
while i < len(args):
    a = args[i]
    if a == "--":
        pos += args[i + 1:]
        break
    if a.split("=", 1)[0] in WITH_VALUE:
        if "=" in a:
            k, v = a.split("=", 1)
            i += 1
        else:
            k, v = a, (args[i + 1] if i + 1 < len(args) else "")
            i += 2
        opts[k] = v
        continue
    if a.startswith("-"):
        sys.stderr.write("error: unexpected argument '%s' found\n\n  tip: to pass '%s' as a value, use '-- %s'\n" % (a, a, a))
        sys.exit(2)
    pos.append(a)
    i += 1
if pos[:2] == ["project", "list"]:
    out = [{"id": AGENTS, "name": "agents"}, {"id": MAIL, "name": "mail"}]
elif pos[:2] == ["secret", "list"]:
    out = [{"id": NEW, "key": "MAIL_PASSWORD", "projectId": MAIL}] if len(pos) < 3 or pos[2] == MAIL else []
    try:  # tests may seed existing keys in the agents project (state/existing.json = ["KEY", ...])
        with open(os.path.join(STATE, "existing.json")) as f:
            if len(pos) == 3 and pos[2] == AGENTS:
                out = [{"id": "44444444-4444-4444-4444-44444444444%d" % n, "key": k, "projectId": AGENTS}
                       for n, k in enumerate(json.load(f))]
    except OSError:
        pass
elif pos[:2] == ["secret", "create"] and len(pos) == 5:
    out = {"id": NEW, "key": pos[2]}
elif pos[:2] == ["secret", "edit"] and len(pos) == 3 and "--value" in opts:
    out = {"id": pos[2]}
elif pos[:2] == ["secret", "get"]:
    out = {"id": pos[2], "key": "SOME_KEY", "value": "fake-value", "projectId": AGENTS}
elif pos[:2] == ["project", "get"]:
    out = {"id": pos[2], "name": "agents"}
else:
    sys.stderr.write("fake bws: unsupported %r\n" % pos)
    sys.exit(2)
print(json.dumps(out))
