"""Regression tests for the 2026-10-06 security audit (broker findings). Each test replays the audit's
PoC against the sandbox and asserts the attack now FAILS. Same sandbox as the other tests: temp HOME, fake
age / bws / approvals socket, throwaway P-256 keys. No real broker, Touch ID or Bitwarden.

  M4  denied project by name only / case-sensitive key prefix   TestMailPolicy
  H1  same-user "second route" through the broker (pin drop)    TestPinFileDropRoute
  M1  unsigned deny / unknown device cancels Touch ID           TestAdvisoryAnswers
  M5  a read request picks the write token                      TestReadTokenAllowList
  L5  ticket collected by anyone who knows its id               TestTicketKey
  L6  local process named `ssh` poses as a tunnel               TestSshOrigin
  L7  ticket queue spam                                         TestTicketSpam
  M7  client-claimed host/caller text (look-alikes, bidi)       TestClaimedFields
"""
import base64
import json
import os
import subprocess
import time
import unittest

from tests.fakes.fake_daemon import FakeDaemon, SoftPhone
from tests.helpers import (AGENTS_ID, FAKE_IPHONE_TOKENS, FAKE_TOKENS, MAIL_ID, Sandbox, open_iphone_payload, pem_fp,
                           write_text)

BOTH = ["touchid", "iphone"]
UID = os.getuid()
READ = {"op": "bws", "args": ["project", "list", "-o", "json"], "host": "build-box", "caller": "agent-A"}
MAILSEC = "55555555-5555-5555-5555-555555555555"

# The audit's fake bws: mail secrets whose keys do NOT start with upper-case MAIL_, `secret get` of a mail
# secret reports the mail projectId. `project list` is controlled by state/projects.json (or fails).
MAIL_BWS = r'''#!/usr/bin/python3
import json, os, sys
STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))), "state")
AGENTS = "11111111-1111-1111-1111-111111111111"
MAIL = "22222222-2222-2222-2222-222222222222"
args = sys.argv[1:]
with open(os.path.join(STATE, "bws.log"), "a") as f:
    f.write(json.dumps({"argv": args, "token": os.environ.get("BWS_ACCESS_TOKEN", "")}) + "\n")
pos = [a for a in args if not a.startswith("-") and a not in ("json", "no")]
if pos[:2] == ["project", "list"]:
    try:
        out = json.load(open(os.path.join(STATE, "projects.json")))
    except OSError:
        sys.stderr.write("error: project list failed\n")
        sys.exit(1)
elif pos[:2] == ["secret", "list"]:
    out = [{"id": "55555555-5555-5555-5555-555555555555", "key": "Mail_Imap_Password", "value": "FAKE-MAIL-VALUE",
            "projectId": MAIL},
           {"id": "66666666-6666-6666-6666-666666666666", "key": "imap_password", "value": "FAKE-MAIL-VALUE",
            "projectId": MAIL},
           {"id": "77777777-7777-7777-7777-777777777777", "key": "AGENT_KEY", "value": "fake-agent-value",
            "projectId": AGENTS}]
    if len(pos) == 3:
        out = [s for s in out if s["projectId"] == pos[2]]
elif pos[:2] == ["secret", "get"]:
    out = {"id": pos[2], "key": "imap_password", "value": "FAKE-MAIL-VALUE", "projectId": MAIL}
else:
    out = []
print(json.dumps(out))
'''


class Base(unittest.TestCase):
    approvers = None

    def setUp(self):
        self.sb = Sandbox(approvers=self.approvers)
        self.phone = SoftPhone(self.sb.root)
        self.daemon = None
        self.mod = self.sb.module()
        self.mod.TOUCHID_WINDOW_S = 8

    def tearDown(self):
        if self.daemon:
            self.daemon.stop()
        self.sb.cleanup()

    def daemon_with(self, phone, **kw):
        if self.daemon:
            self.daemon.stop()
        self.daemon = FakeDaemon(self.sb.sock, phone, **kw)
        self.daemon.start()
        return self.daemon

    def handle(self, req, mod=None):
        return (mod or self.mod).handle(dict(req), os.getpid())

    def last_log(self):
        lines = self.sb.log_lines()
        return lines[-1] if lines else ""


# ------------------------------------------------------------------ M4

class TestMailPolicy(Base):
    def setUp(self):
        Base.setUp(self)
        p = os.path.join(self.sb.bin, "bws")
        write_text(p, MAIL_BWS)
        os.chmod(p, 0o755)
        # the audit's config: mail denied by NAME only, no id for it in project_names
        self.sb.write_config(dict(self.sb.config, project_names={AGENTS_ID: "agents"}))

    def projects(self, *items):
        write_text(os.path.join(self.sb.state, "projects.json"), json.dumps(list(items)))

    def out(self, r):
        return base64.b64decode(r.get("stdout_b64") or "").decode()

    def read(self, *args):
        return self.handle({"op": "bws", "args": list(args), "host": "h", "caller": "c"})

    def test_name_only_denial_no_longer_leaks(self):
        """PoC TestMailPolicy.test_name_only_denial_leaks_mail_secrets: all three calls returned the value."""
        self.projects({"id": AGENTS_ID, "name": "agents"}, {"id": MAIL_ID, "name": "Mail"})
        r1 = self.read("secret", "list", "-o", "json")
        self.assertTrue(r1["ok"], r1)
        self.assertNotIn("FAKE-MAIL-VALUE", self.out(r1))
        self.assertEqual([s["key"] for s in json.loads(self.out(r1))], ["AGENT_KEY"])
        r2 = self.read("secret", "list", MAIL_ID, "-o", "json")
        self.assertFalse(r2["ok"])
        self.assertIn("denied or not visible", r2["error"])
        self.assertNotIn("FAKE-MAIL-VALUE", json.dumps(r2))
        r3 = self.read("secret", "get", MAILSEC)
        self.assertEqual(self.out(r3), "{}")
        # the mail project was never read: only project list + the agents-scoped / unscoped reads ran
        self.assertNotIn(["secret", "list", MAIL_ID], [b["argv"][-3:] for b in self.sb.bws_runs()])

    def test_denied_name_resolved_by_id_case_insensitively(self):
        self.projects({"id": AGENTS_ID, "name": "agents"}, {"id": MAIL_ID.upper(), "name": "MAIL"})
        r = self.read("project", "get", MAIL_ID)
        self.assertFalse(r["ok"])
        r = self.read("project", "list", "-o", "json")
        self.assertEqual(json.loads(self.out(r)), [{"id": AGENTS_ID, "name": "agents"}])

    def test_unresolvable_denied_name_fails_closed(self):
        """project list fails: nothing is read at all."""
        r = self.read("secret", "list", "-o", "json")
        self.assertFalse(r["ok"])
        self.assertIn("could not resolve denied project names", r["error"])
        self.assertEqual([b["argv"][-2:] for b in self.sb.bws_runs()], [["project", "list"]])
        self.assertIn("result=rejected", self.last_log())

    def test_invisible_denied_project_drops_unknown_project_ids(self):
        """mail is not visible to the token (its name cannot be resolved): secrets of any project that is
        not a visible, allowed one are dropped anyway."""
        self.projects({"id": AGENTS_ID, "name": "agents"})
        r = self.read("secret", "list", "-o", "json")
        self.assertEqual([s["key"] for s in json.loads(self.out(r))], ["AGENT_KEY"])
        self.assertEqual(self.out(self.read("secret", "get", MAILSEC)), "{}")

    def test_key_prefix_is_case_insensitive(self):
        """PoC: denied_key('mail_x')=False, denied_key('Mail_X')=False."""
        c = self.mod.load_config()
        for k in ("MAIL_X", "mail_x", "Mail_X", "mAiL_"):
            self.assertTrue(self.mod.denied_key(k, c), k)
        self.assertFalse(self.mod.denied_key("EMAIL_X", c))
        # output scrubbing by key: a mapped config, a secret whose key is lower-case mail_
        out = self.mod.scrub(json.dumps([{"key": "mail_pw", "projectId": AGENTS_ID},
                                         {"key": "OK", "projectId": AGENTS_ID}]).encode(), c)
        self.assertEqual([s["key"] for s in json.loads(out)], ["OK"])

    def test_mapped_name_needs_no_lookup(self):
        """With the id in project_names (the default sandbox) there is no extra bws run: same as before."""
        self.sb.write_config(dict(self.sb.config, project_names={AGENTS_ID: "agents", MAIL_ID: "mail"}))
        r = self.read("secret", "get", MAILSEC)
        self.assertEqual(self.out(r), "{}")
        self.assertEqual([b["argv"][-3:-1] for b in self.sb.bws_runs()], [["secret", "get"]])


# ------------------------------------------------------------------ H1 (broker route)

class TestPinFileDropRoute(Base):
    """PoC TestSameUserMintsApprovals: same-user code drops its own pin file, flips config to iphone-only,
    answers on its own approvals socket with its own signatures."""
    approvers = ["iphone"]

    def test_self_pinned_key_and_fake_daemon_refused(self):
        evil = SoftPhone(self.sb.root)
        self.sb.pin(evil, bind=False)                   # == write ~/.bws-broker/approvers/<dev>.pub
        self.daemon_with(evil, decision="approve", delay=0.1)
        r = self.handle(dict(READ, caller="malware"))
        self.assertFalse(r["ok"], r)
        self.assertIn("iPhone answer not accepted (unbound_device)", r["error"])
        self.assertEqual(self.sb.bws_runs(), [], "bws must not run with the iPhone copy")
        self.daemon.eof_seen.wait(5)
        self.assertEqual([x["outcome"] for x in self.daemon.received], ["unknown_device"])
        self.assertIn("iphone-ignored:unbound_device", self.last_log())

    def test_bound_pin_still_works(self):
        self.sb.pin(self.phone)
        self.daemon_with(self.phone, decision="approve", delay=0.1)
        r = self.handle(READ)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_IPHONE_TOKENS["read"])

    def test_legacy_copy_is_unbound(self):
        self.sb.pin(self.phone)
        self.sb.write_iphone_copies(legacy=True)        # a pre-binding copy: bare token
        self.daemon_with(self.phone, decision="approve", delay=0.1)
        r = self.handle(READ)
        self.assertFalse(r["ok"])
        self.assertIn("unbound_device(legacy-copy)", r["error"])
        self.assertEqual(self.sb.bws_runs(), [])

    def test_unsafe_copy_mode_skips_phone(self):
        self.sb.pin(self.phone)
        os.chmod(os.path.join(self.sb.tokens, "read.iphone.age"), 0o644)
        self.daemon_with(self.phone, decision="approve", delay=0.1)
        r = self.handle(READ)
        self.assertFalse(r["ok"])
        self.assertEqual(self.daemon.connections, 0)
        self.assertIn("iphone-unavailable:unsafe-file-mode", self.last_log())

    def test_approver_add_binds_and_migrates_legacy_copies(self):
        self.sb.write_iphone_copies(legacy=True)
        pem = os.path.join(self.sb.root, "approve.pem")
        write_text(pem, self.phone.pem())
        der = self.mod.spki_from_pem(self.phone.pem())
        last4 = self.mod.display_fp(der).replace("-", "")[-4:]
        r = self.sb.cli("bws-touchid", "approver", "add", self.phone.device_id, pem, input=last4 + "\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("bound into the iPhone token copies: read, write", r.stdout)
        for name in ("read", "write"):
            path = os.path.join(self.sb.tokens, name + ".iphone.age")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            out = subprocess.run([os.path.join(self.sb.bin, "age"), "-d", "-i",
                                  os.path.join(self.sb.conf, "identity-iphone.txt"), path],
                                 capture_output=True, text=True, env=self.sb.env()).stdout
            self.assertEqual(open_iphone_payload(out), (FAKE_IPHONE_TOKENS[name], [pem_fp(self.phone.pem())]))
        r = self.sb.cli("bws-touchid", "status")
        self.assertIn("(bound)", r.stdout)
        self.daemon_with(self.phone, decision="approve", delay=0.1)
        self.assertTrue(self.handle(READ)["ok"])
        # store keeps the binding for a new token copy; remove unbinds
        tok = "0.00000000-0000-0000-0000-000000000009.fakenew:ZmFrZQ=="
        self.assertEqual(self.sb.cli("bws-touchid", "store", "extra", "--stdin", input=tok + "\n").returncode, 0)
        r = self.sb.cli("bws-touchid", "approver", "remove", self.phone.device_id)
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in ("read", "write", "extra"):
            out = subprocess.run([os.path.join(self.sb.bin, "age"), "-d", "-i",
                                  os.path.join(self.sb.conf, "identity-iphone.txt"),
                                  os.path.join(self.sb.tokens, name + ".iphone.age")],
                                 capture_output=True, text=True, env=self.sb.env()).stdout
            self.assertEqual(open_iphone_payload(out)[1], [], name)
        self.sb.pin(self.phone, bind=False)             # re-dropping the pin file does not re-enable it
        self.daemon_with(self.phone, decision="approve", delay=0.1)
        self.assertFalse(self.handle(READ)["ok"])

    def test_iphone_teardown(self):
        self.sb.pin(self.phone)
        r = self.sb.cli("bws-touchid", "iphone-teardown", "--unpin")
        self.assertEqual(r.returncode, 0, r.stderr)
        left = sorted(os.listdir(self.sb.tokens))
        self.assertEqual(left, ["read.age", "write.age"])
        for f in ("identity-iphone.txt", "recipient-iphone.txt"):
            self.assertFalse(os.path.exists(os.path.join(self.sb.conf, f)))
        self.assertTrue(os.path.exists(os.path.join(self.sb.conf, "identity.txt")))
        self.assertEqual(os.listdir(self.sb.approvers_dir), [])
        self.assertIn('set "approvers": ["touchid"]', r.stdout)
        self.assertIn("op=iphone-teardown", self.last_log())
        self.assertEqual(self.sb.age_runs(), [], "teardown needs no Touch ID")


# ------------------------------------------------------------------ M1 (broker side)

class TestAdvisoryAnswers(Base):
    approvers = BOTH

    def test_unsigned_deny_from_unpinned_device_does_not_cancel_touchid(self):
        self.sb.pin(self.phone)                          # the real phone (keeps the leg configured)
        rogue = SoftPhone(self.sb.root)                  # paired with the daemon, never pinned
        self.sb.hold_touchid()                           # Touch ID answers only after the deny was handled
        self.daemon_with(rogue, decision="deny", delay=0.1, after=self.sb.release_touchid)
        r = self.handle(READ)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_TOKENS["read"])
        self.daemon.eof_seen.wait(5)
        self.assertEqual([x["outcome"] for x in self.daemon.received], ["unknown_device"])
        self.assertIn("iphone-ignored:deny-from-unpinned-device", self.last_log())
        self.assertIn("approver=touchid", self.last_log())

    def test_unsigned_deny_iphone_only_still_fails_closed(self):
        self.sb.write_config(dict(self.sb.config, approvers=["iphone"]))
        self.sb.pin(self.phone)
        self.daemon_with(SoftPhone(self.sb.root), decision="deny", delay=0.1)
        r = self.handle(READ)
        self.assertFalse(r["ok"])
        self.assertIn("not accepted (deny-from-unpinned-device)", r["error"])
        self.assertEqual(self.sb.bws_runs(), [])

    def test_pinned_approver_deny_is_final(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.daemon_with(self.phone, decision="deny", delay=0.1)
        r = self.handle(READ)
        self.assertEqual(r, {"ok": False, "error": "denied on iPhone"})


# ------------------------------------------------------------------ M5

class TestReadTokenAllowList(Base):
    def test_read_with_write_token_refused(self):
        """PoC TestClientPicksToken: bws got the write token, the notification did not say so."""
        r = self.handle(dict(READ, token="write"))
        self.assertEqual(r, {"ok": False, "error": "token 'write' is not allowed for reads (config read_tokens: read)"})
        self.assertEqual(self.sb.bws_runs(), [])
        self.assertEqual(self.sb.age_runs(), [])
        self.assertEqual(self.sb.notified, [])

    def test_allowed_extra_token_is_named_in_the_prompt(self):
        self.sb.write_config(dict(self.sb.config, read_tokens=["read", "write"]))
        r = self.handle(dict(READ, token="write"))
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.sb.notified[-1][0], "Touch ID: list projects (token write)")


# ------------------------------------------------------------------ L5

class TestTicketKey(Base):
    def test_ticket_id_alone_no_longer_collects(self):
        """PoC TestTicketTheft: a thief with the id + claimed host/caller got the result."""
        job = self.mod.dispatch(dict(READ, **{"async": True}), os.getpid(), UID)
        tid, key = job["ticket"], job["ticket_key"]
        stolen = self.mod.dispatch({"op": "ticket.get", "ticket": tid, "host": "build-box", "caller": "agent-A",
                                    "wait": 10}, 99999, UID)
        self.assertEqual(stolen["status"], "expired")
        self.assertNotIn("result", stolen)
        legit = self.mod.dispatch({"op": "ticket.get", "ticket": tid, "ticket_key": key, "host": "build-box",
                                   "caller": "agent-A", "wait": 10}, os.getpid(), UID)
        self.assertEqual(legit["status"], "approved")

    def test_cli_keeps_the_key_off_stdout_and_argv(self):
        srv = subprocess.Popen(["/usr/bin/python3", os.path.join(self.sb.bin, "bws-touchid"), "serve"],
                               env=self.sb.env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            sock = os.path.join(self.sb.home, ".bws-broker", "broker.sock")
            for _ in range(50):
                if os.path.exists(sock):
                    break
                time.sleep(0.1)
            env = {"BWS_TOUCHID_CALLER": "mcp"}
            r = self.sb.cli("bws-gated", "--async", "project", "list", env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(list(json.loads(r.stdout)), ["ticket"])
            tid = json.loads(r.stdout)["ticket"]
            kdir = os.path.join(self.sb.home, ".bws-broker", "tickets")
            self.assertEqual(os.stat(kdir).st_mode & 0o777, 0o700)
            keyfile = os.path.join(kdir, os.listdir(kdir)[0])
            self.assertEqual(os.stat(keyfile).st_mode & 0o777, 0o600)
            os.rename(keyfile, keyfile + ".away")         # a thief without the key file
            self.assertEqual(self.sb.cli("bws-touchid", "ticket", "wait", tid, "--timeout", "5", env=env).returncode, 6)
            os.rename(keyfile + ".away", keyfile)
            r = self.sb.cli("bws-touchid", "ticket", "wait", tid, "--timeout", "20", env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(os.path.exists(keyfile), "key dropped after collection")
        finally:
            srv.terminate()
            srv.wait(5)


# ------------------------------------------------------------------ L7

class TestTicketSpam(Base):
    def test_per_caller_pending_cap(self):
        self.mod.MAX_PENDING_PER_CALLER = 2
        self.mod.GATE_LOCK.acquire()                     # nothing gets approved while we count
        try:
            a = self.mod.dispatch(dict(READ, **{"async": True}), os.getpid(), UID)
            b = self.mod.dispatch(dict(READ, **{"async": True}), os.getpid(), UID)
            c = self.mod.dispatch(dict(READ, **{"async": True}), os.getpid(), UID)
            other = self.mod.dispatch(dict(READ, caller="agent-B", **{"async": True}), os.getpid(), UID)
        finally:
            self.mod.GATE_LOCK.release()
        self.assertTrue(a["ok"] and b["ok"] and other["ok"])
        self.assertEqual(c, {"ok": False, "error": "too many pending requests from this host/caller (2)"})

    def test_queue_dropped_after_owner_deny(self):
        self.sb.set_age(touchid={"mode": "cancel", "delay": 0.5})
        self.mod.GATE_LOCK.acquire()                     # all four are queued before the first prompt
        try:
            tickets = [self.mod.dispatch(dict(READ, **{"async": True}), os.getpid(), UID) for _ in range(4)]
        finally:
            self.mod.GATE_LOCK.release()
        out = []
        for t in tickets:
            r = self.mod.dispatch({"op": "ticket.get", "ticket": t["ticket"], "ticket_key": t["ticket_key"],
                                   "host": "build-box", "caller": "agent-A", "wait": 20}, os.getpid(), UID)
            out.append(r["status"])
        self.assertEqual(out, ["denied"] * 4)
        self.assertEqual(len(self.sb.age_runs("touchid")), 1, "one prompt, then the queue is dropped")


# ------------------------------------------------------------------ L6

class TestSshOrigin(Base):
    def test_local_process_named_ssh_is_local(self):
        """PoC TestSpoofSshOrigin: the log said `via=ssh session to <host>` for a local process."""
        p = subprocess.Popen(["/usr/bin/python3", os.path.join(self.sb.bin, "bws-touchid"), "serve"],
                             env=self.sb.env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            sock = os.path.join(self.sb.home, ".bws-broker", "broker.sock")
            for _ in range(50):
                if os.path.exists(sock):
                    break
                time.sleep(0.1)
            work = os.path.join(self.sb.root, "evil")
            os.makedirs(work)
            os.symlink("/usr/bin/nc", os.path.join(work, "ssh"))
            os.symlink(sock, os.path.join(work, "remote-box"))
            req = dict(READ, host="remote-box", caller="agent (remote box)", dryrun=True)
            subprocess.run(["./ssh", "-U", "remote-box"], cwd=work, input=json.dumps(req).encode() + b"\n",
                           capture_output=True, timeout=20)
            line = [l for l in self.sb.log_lines() if "DRYRUN" in l][-1]
            self.assertNotIn("via=ssh session", line)
            self.assertIn("via=local: ", line)
            self.assertIn("peer-claims-ssh:nc", line)
        finally:
            p.terminate()
            p.wait(5)


# ------------------------------------------------------------------ M7 (broker side)

class TestClaimedFields(Base):
    approvers = BOTH

    def test_lookalike_and_bidi_never_reach_prompt_or_canonical(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.daemon_with(self.phone, decision="approve", delay=0.2)
        r = self.handle(dict(READ, host="rem\u043ete", caller="git\u202e(pid 1)\u200b\nevil"))
        self.assertTrue(r["ok"], r)
        canon = json.loads(base64.b64decode(self.daemon.requests[0]["canonical_b64"]))
        self.assertEqual((canon["host"], canon["caller"]), ("rem?te", "git(pid 1)evil"))
        self.assertIn("host=rem?te caller=git(pid 1)evil", self.last_log())

    def test_secret_get_summary_shows_full_id(self):
        self.sb.write_config(dict(self.sb.config, approvers=["touchid"]))
        sid = "44444444-4444-4444-4444-444444444444"
        self.handle({"op": "bws", "args": ["--server-url", "https://vault.bitwarden.eu", "secret", "get", sid],
                     "host": "h", "caller": "c"})
        self.assertEqual(self.sb.notified[-1][0][:60], ("Touch ID: read secret %s @ vault.bitwarden.eu" % sid)[:60])


if __name__ == "__main__":
    unittest.main()
