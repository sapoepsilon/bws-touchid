"""Provider interface, the 5-minute iPhone window, async tickets and the prefer_device hint.

Run from the repo root:  python3 -m unittest -v
Same sandbox as test_broker: temp HOME, fake age / bws / approvals socket. No Touch ID, no Bitwarden.
"""
import base64
import json
import os
import subprocess
import threading
import time
import unittest

from tests.fakes.fake_daemon import FakeDaemon, SoftPhone
from tests.helpers import AGENTS_ID, FAKE_IPHONE_TOKENS, FAKE_TOKENS, Sandbox

BOTH = ["touchid", "iphone"]
UID = os.getuid()
READ_REQ = {"op": "bws", "args": ["secret", "list", AGENTS_ID, "-o", "json"], "host": "build-box", "caller": "unit test"}
GET_REQ = {"op": "bws", "args": ["secret", "get", "44444444-4444-4444-4444-444444444444"], "host": "build-box",
           "caller": "unit test"}
SAVE_REQ = {"op": "save", "key": "UNIT_TEST_KEY", "value": "fake-value-123", "host": "build-box", "caller": "unit test",
            "note": "test"}


class Base(unittest.TestCase):
    approvers = None

    def setUp(self):
        self.sb = Sandbox(approvers=self.approvers)
        self.phone = SoftPhone(self.sb.root)
        self.daemon = None
        self.mod = self.sb.module()
        self.mod.TOUCHID_WINDOW_S = 10

    def tearDown(self):
        if self.daemon:
            self.daemon.stop()
        self.sb.cleanup()

    def start_daemon(self, **kw):
        self.daemon = FakeDaemon(self.sb.sock, self.phone, **kw)
        self.daemon.start()
        return self.daemon

    def last_log(self):
        lines = self.sb.log_lines()
        return lines[-1] if lines else ""


# ------------------------------------------------------------------ providers

class RecordingProvider(object):
    """A provider stub that records what the gate hands it."""

    def __init__(self, mod):
        base = mod.Provider

        class P(base):
            name, enabled, token_env = "recording", True, "X_TOKEN"
            calls = []

            def parse_read(self, raw, c):
                if raw[:1] == ["list"]:
                    return {"kind": "list", "args": raw, "summary": "list things", "project": "p1"}
                if raw[:1] == ["get"] and len(raw) == 2:
                    return {"kind": "get", "args": raw, "summary": "get " + raw[1], "project": ""}
                return None

            def list(self, op, token, c):
                self.calls.append(("list", token))
                return 0, b'[{"key":"A"},{"key":"MAIL_X"}]', ""

            def get(self, op, token, c):
                self.calls.append(("get", token, op["args"][1]))
                return 0, b'{"key":"A","value":"v"}', ""

            def save(self, key, value, note, project, token, c):
                self.calls.append(("save", token, key, value, project))
                return "created", "id=r1", {"ok": True, "id": "r1", "action": "created", "project": project}

            def scrub(self, stdout, c):
                return json.dumps([e for e in json.loads(stdout) if not e["key"].startswith("MAIL_")]).encode() \
                    if stdout.startswith(b"[") else stdout
        self.cls = P


class TestProviders(Base):
    def test_default_is_bitwarden(self):
        c = self.mod.load_config()
        p, why = self.mod.provider_of(c)
        self.assertEqual((p.name, why), ("bitwarden", None))
        self.assertEqual(p.token_env, "BWS_ACCESS_TOKEN")
        self.assertEqual(sorted(self.mod.PROVIDERS), ["bitwarden"], "only bitwarden ships enabled")

    def test_skeletons_not_enabled_fail_closed(self):
        for name, want in (("1password", "provider '1password' is not enabled in this version"),
                           ("keychain", "provider 'keychain' is not enabled in this version"),
                           ("nope", "unknown provider 'nope'"), (["x"], "unknown provider \"['x']\"")):
            self.sb.write_config(dict(self.sb.config, provider=name))
            for req in (READ_REQ, SAVE_REQ, dict(SAVE_REQ, dryrun=True)):
                self.assertEqual(self.mod.handle(dict(req), os.getpid()), {"ok": False, "error": want})
        self.assertEqual(self.sb.age_runs(), [], "no approval asked for a disabled provider")
        self.assertEqual(self.sb.bws_runs(), [])
        self.assertIn("result=rejected", self.last_log())

    def test_skeleton_interface(self):
        for name, env in (("1password", "OP_SERVICE_ACCOUNT_TOKEN"), ("keychain", "")):
            p = self.mod.PROVIDER_SKELETONS[name]
            self.assertFalse(p.enabled)
            self.assertEqual(p.token_env, env)
            for call in (lambda: p.parse_read([], {}), lambda: p.list({}, "t", {}), lambda: p.get({}, "t", {}),
                         lambda: p.save("K", "v", "", "p", "t", {})):
                self.assertRaises(NotImplementedError, call)

    def test_bitwarden_parse_read(self):
        p = self.mod.PROVIDERS["bitwarden"]
        c = self.mod.load_config()
        self.assertEqual(p.parse_read(["secret", "list", AGENTS_ID, "-o", "json"], c),
                         {"kind": "list", "args": ["--output", "json", "secret", "list", AGENTS_ID],
                          "summary": "read all secrets in agents", "project": "agents"})
        op = p.parse_read(["--server-url", "https://vault.bitwarden.eu", "project", "get", AGENTS_ID], c)
        self.assertEqual((op["kind"], op["project"]), ("get", "agents"))
        self.assertIsNone(p.parse_read(["secret", "create", "K", "v", AGENTS_ID], c))
        self.assertIsNone(p.parse_read(["secret", "list", "22222222-2222-2222-2222-222222222222"], c))

    def test_gate_is_independent_of_backend(self):
        """A different provider behind the same gate: same approval, its own token names, no bws."""
        P = RecordingProvider(self.mod).cls
        self.mod.PROVIDERS["recording"] = P()
        self.sb.write_config(dict(self.sb.config, provider="recording"))
        r = self.mod.handle({"op": "bws", "args": ["list"], "host": "h", "caller": "c"}, os.getpid())
        self.assertTrue(r["ok"], r)
        self.assertEqual(json.loads(base64.b64decode(r["stdout_b64"])), [{"key": "A"}], "provider scrub applied")
        r = self.mod.handle({"op": "bws", "args": ["get", "abc"], "host": "h", "caller": "c"}, os.getpid())
        self.assertTrue(r["ok"], r)
        r = self.mod.handle(dict(SAVE_REQ), os.getpid())
        self.assertEqual(r, {"ok": True, "id": "r1", "action": "created", "project": "agents"})
        r = self.mod.handle({"op": "bws", "args": ["drop", "all"], "host": "h", "caller": "c"}, os.getpid())
        self.assertFalse(r["ok"])
        self.assertEqual(P.calls, [("list", FAKE_TOKENS["read"]), ("get", FAKE_TOKENS["read"], "abc"),
                                   ("save", FAKE_TOKENS["write"], "UNIT_TEST_KEY", "fake-value-123", "agents")])
        self.assertEqual(self.sb.bws_runs(), [])
        self.assertEqual(len(self.sb.age_runs("touchid")), 3, "one approval per op")
        self.assertEqual(self.sb.notified[0][0], "Touch ID: list things")
        self.assertNotIn("fake-value-123", "\n".join(self.sb.log_lines()))

    def test_status_shows_provider_and_windows(self):
        r = self.sb.cli("bws-touchid", "status")
        self.assertIn("provider:  bitwarden\n", r.stdout)
        self.assertIn("approval wait: Touch ID 120s, iPhone 300s", r.stdout)


# ------------------------------------------------------------------ approval window

class TestWindow(Base):
    approvers = BOTH

    def test_budgets_nest(self):
        m = self.sb.module()
        self.assertEqual((m.APPROVAL_WAIT_DEFAULT_S, m.PHONE_WINDOW_MAX, m.TOUCHID_WINDOW_S), (300, 300, 120))
        self.assertEqual(m.GATE_MAX_S, 305)
        self.assertGreater(m.BROKER_CONN_S, m.GATE_MAX_S + 3 * m.BWS_TIMEOUT_S)
        self.assertGreater(m.CLIENT_TIMEOUT_S, m.BROKER_CONN_S + m.GATE_QUEUE_S)
        self.assertLess(m.TICKET_WAIT_MAX_S, 60, "one ticket.get must fit in a 60 s MCP call")
        self.assertGreater(m.TICKET_TTL_S, m.GATE_MAX_S)

    def test_phone_may_answer_after_touchid_window(self):
        """Touch ID gives up at its own deadline; the iPhone leg keeps the longer approval_wait_s."""
        self.sb.write_config(dict(self.sb.config, approval_wait_s=6))
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="approve", delay=2.5)
        self.mod.TOUCHID_WINDOW_S, self.mod.PHONE_WINDOW_MIN = 1, 1
        t0 = time.time()
        r = self.mod.handle(dict(READ_REQ), os.getpid())
        self.assertTrue(r["ok"], r)
        self.assertGreater(time.time() - t0, 2.4)
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_IPHONE_TOKENS["read"])
        canon = json.loads(base64.b64decode(self.daemon.requests[0]["canonical_b64"]))
        self.assertEqual(canon["expires_at"] - canon["created_at"], 6)
        self.assertIn("touchid-unavailable:timeout", self.last_log())
        self.assertIn("approver=iphone:", self.last_log())

    def test_without_phone_touchid_window_unchanged(self):
        """Phone leg unavailable: the gate ends at the Touch ID deadline, not the 5-minute window."""
        self.sb.pin(self.phone)  # but no daemon
        self.sb.set_age(touchid={"mode": "hang"})
        self.mod.TOUCHID_WINDOW_S = 1
        t0 = time.time()
        r = self.mod.handle(dict(READ_REQ), os.getpid())
        self.assertFalse(r["ok"])
        self.assertLess(time.time() - t0, 2.5)
        self.assertEqual(r["error"], "no approval within 1s (Touch ID or iPhone)")

    def test_iphone_only_uses_approval_wait(self):
        self.sb.write_config(dict(self.sb.config, approvers=["iphone"], approval_wait_s=2))
        self.sb.pin(self.phone)
        self.start_daemon(decision="silent", delay=60)
        self.mod.PHONE_WINDOW_MIN, self.mod.PHONE_GRACE_S = 1, 1
        r = self.mod.handle(dict(READ_REQ), os.getpid())
        self.assertEqual(r, {"ok": False, "error": "no approval within 3s (Touch ID or iPhone)"})


# ------------------------------------------------------------------ prefer_device

class TestPreferDevice(Base):
    approvers = BOTH

    def run_read(self, req):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="approve", delay=0.3)
        r = self.mod.handle(dict(req), os.getpid())
        self.assertTrue(r["ok"], r)
        return self.daemon.requests[0]

    def test_from_request(self):
        req = self.run_read(dict(READ_REQ, prefer_device=self.phone.device_id))
        self.assertEqual(req["prefer_device"], self.phone.device_id)
        canon = json.loads(base64.b64decode(req["canonical_b64"]))
        self.assertNotIn("prefer_device", canon, "a routing hint, never part of what the phone signs")

    def test_from_helper_file(self):
        d = os.path.join(self.sb.home, ".whispera-link")
        os.makedirs(d)
        with open(os.path.join(d, "last_device"), "w") as f:
            f.write(self.phone.device_id + "\n")
        self.assertEqual(self.run_read(READ_REQ)["prefer_device"], self.phone.device_id)

    def test_bad_hint_dropped(self):
        req = self.run_read(dict(READ_REQ, prefer_device="dev_NOT/valid"))
        self.assertIsNone(req["prefer_device"])

    def test_unsafe_file_ignored(self):
        p = os.path.join(self.sb.root, "hint")
        with open(p, "w") as f:
            f.write(self.phone.device_id)
        os.chmod(p, 0o666)
        c = dict(self.mod.load_config(), prefer_device_file=p)
        self.assertEqual(self.mod.prefer_device_of({}, c), "")
        os.chmod(p, 0o600)
        self.assertEqual(self.mod.prefer_device_of({}, c), self.phone.device_id)


# ------------------------------------------------------------------ tickets

class TestTickets(Base):
    def dispatch(self, req, uid=UID):
        return self.mod.dispatch(dict(req), os.getpid(), uid)

    def get(self, tid, wait=0, uid=UID, host="build-box", caller="unit test"):
        return self.dispatch({"op": "ticket.get", "ticket": tid, "host": host, "caller": caller, "wait": wait}, uid)

    def wait_done(self, tid, **kw):
        end = time.time() + 15
        while time.time() < end:
            r = self.get(tid, wait=2, **kw)
            if r["status"] != "pending":
                return r
        self.fail("ticket still pending")

    def test_async_returns_at_once_then_approved(self):
        self.sb.set_age(touchid={"mode": "ok", "delay": 1.0})
        t0 = time.time()
        r = self.dispatch(dict(READ_REQ, **{"async": True}))
        self.assertLess(time.time() - t0, 0.8, "the ticket must not wait for the approval")
        self.assertEqual((r["ok"], r["status"]), (True, "pending"))
        self.assertRegex(r["ticket"], r"^tkt_[a-z2-7]{24}$")
        tid = r["ticket"]
        self.assertEqual(self.get(tid), {"ok": True, "status": "pending", "ticket": tid})
        r = self.wait_done(tid)
        self.assertEqual((r["ok"], r["status"], r["op"]), (True, "approved", "bws"))
        self.assertTrue(r["result"]["ok"])
        self.assertEqual(json.loads(base64.b64decode(r["result"]["stdout_b64"])), [])
        self.assertIn("result=exit=0", self.last_log())
        # single retrieval
        self.assertEqual(self.get(tid)["status"], "expired")

    def test_async_save(self):
        r = self.dispatch(dict(SAVE_REQ, **{"async": True}))
        r = self.wait_done(r["ticket"])
        self.assertEqual(r["status"], "approved")
        self.assertEqual(r["result"]["action"], "created")
        self.assertEqual(r["op"], "save")

    def test_denied(self):
        self.sb.set_age(touchid={"mode": "cancel", "delay": 0.2})
        r = self.wait_done(self.dispatch(dict(READ_REQ, **{"async": True}))["ticket"])
        self.assertEqual((r["ok"], r["status"]), (False, "denied"))
        self.assertIn("Touch ID / decrypt failed", r["error"])
        self.assertNotIn("result", r)
        self.assertEqual(self.sb.bws_runs(), [])

    def test_expire_after_ttl(self):
        self.mod.TICKET_TTL_S = 0.5
        tid = self.dispatch(dict(READ_REQ, **{"async": True}))["ticket"]
        while self.mod.TICKETS.items[tid]["status"] == "pending":
            time.sleep(0.05)
        time.sleep(0.8)
        r = self.get(tid)
        self.assertEqual(r, {"ok": False, "status": "expired",
                             "error": "no such ticket (expired, already collected, or not yours)"})
        self.assertNotIn(tid, self.mod.TICKETS.items, "expired results are dropped from memory")

    def test_bound_to_uid_host_caller(self):
        tid = self.dispatch(dict(GET_REQ, **{"async": True}))["ticket"]
        while self.mod.TICKETS.items[tid]["status"] == "pending":
            time.sleep(0.05)
        for kw in ({"caller": "someone else"}, {"host": "other-box"}, {"uid": UID + 1}):
            r = self.get(tid, **kw)
            self.assertEqual(r["status"], "expired", kw)
            self.assertNotIn("result", r)
        r = self.get(tid)  # the wrong callers did not consume it
        self.assertEqual(r["status"], "approved")
        self.assertEqual(json.loads(base64.b64decode(r["result"]["stdout_b64"]))["value"], "fake-value")
        self.assertEqual(self.get(tid)["status"], "expired")

    def test_unknown_and_malformed_ids(self):
        for tid in ("tkt_" + "a" * 24, "nope", None, 5):
            self.assertEqual(self.get(tid)["status"], "expired")

    def test_validation_errors_are_immediate(self):
        r = self.dispatch(dict(SAVE_REQ, key="MAIL_PASSWORD", **{"async": True}))
        self.assertEqual(r, {"ok": False, "error": "that key prefix is owner-only"})
        r = self.dispatch(dict(READ_REQ, dryrun=True, **{"async": True}))
        self.assertEqual(r["stdout_b64"], base64.b64encode(b"[]").decode())
        self.assertEqual(self.mod.TICKETS.items, {})

    def test_results_never_on_disk(self):
        tid = self.dispatch(dict(GET_REQ, **{"async": True}))["ticket"]
        while self.mod.TICKETS.items[tid]["status"] == "pending":
            time.sleep(0.05)
        for d in (self.sb.home, self.sb.state):
            for root, _dirs, files in os.walk(d):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        with open(p, "rb") as fh:
                            data = fh.read(1 << 20)
                    except OSError:
                        continue
                    self.assertNotIn(b"fake-value", data, p)
                    self.assertNotIn(tid.encode(), data, p)

    def test_max_tickets(self):
        self.mod.MAX_TICKETS = 2
        self.sb.set_age(touchid={"mode": "ok", "delay": 1.5})
        a = self.dispatch(dict(READ_REQ, **{"async": True}))
        b = self.dispatch(dict(READ_REQ, **{"async": True}))
        c = self.dispatch(dict(READ_REQ, **{"async": True}))
        self.assertTrue(a["ok"] and b["ok"])
        self.assertFalse(c["ok"])
        self.assertIn("too many outstanding tickets", c["error"])
        self.wait_done(a["ticket"])
        self.wait_done(b["ticket"])

    def test_one_approval_at_a_time(self):
        self.sb.set_age(touchid={"mode": "ok", "delay": 0.6})
        tids = [self.dispatch(dict(READ_REQ, **{"async": True}))["ticket"] for _ in range(3)]
        for t in tids:
            self.assertEqual(self.wait_done(t)["status"], "approved")
        runs = self.sb.age_runs("touchid")
        self.assertEqual(len(runs), 3)

    def test_sync_waits_for_slot_then_busy(self):
        self.mod.GATE_QUEUE_S = 0.3
        self.mod.GATE_LOCK.acquire()
        try:
            r = self.mod.handle(dict(READ_REQ), os.getpid())
        finally:
            self.mod.GATE_LOCK.release()
        self.assertEqual(r, {"ok": False, "error": "broker busy: another approval is pending; retry, or use --async"})
        self.assertEqual(self.sb.age_runs(), [])

    def test_long_poll_returns_when_decided(self):
        self.sb.set_age(touchid={"mode": "ok", "delay": 0.8})
        tid = self.dispatch(dict(READ_REQ, **{"async": True}))["ticket"]
        t0 = time.time()
        r = self.get(tid, wait=20)
        self.assertEqual(r["status"], "approved")
        self.assertLess(time.time() - t0, 5)

    def test_phone_approval_through_ticket(self):
        self.sb.write_config(dict(self.sb.config, approvers=BOTH))
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="approve", delay=0.5)
        tid = self.dispatch(dict(READ_REQ, prefer_device=self.phone.device_id, **{"async": True}))["ticket"]
        r = self.wait_done(tid)
        self.assertEqual(r["status"], "approved")
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_IPHONE_TOKENS["read"])
        self.assertEqual(self.daemon.requests[0]["prefer_device"], self.phone.device_id)


class TestTicketCli(Base):
    """bws-gated --async / BWS_TOUCHID_ASYNC + bws-touchid ticket wait|get through a served socket."""

    def setUp(self):
        Base.setUp(self)
        self.srv = subprocess.Popen(["/usr/bin/python3", os.path.join(self.sb.bin, "bws-touchid"), "serve"],
                                    env=self.sb.env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sock = os.path.join(self.sb.home, ".bws-broker", "broker.sock")
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.1)

    def tearDown(self):
        self.srv.terminate()
        self.srv.wait(5)
        Base.tearDown(self)

    def test_gated_async_then_wait(self):
        self.sb.set_age(touchid={"mode": "ok", "delay": 1.5})
        env = {"BWS_TOUCHID_CALLER": "mcp test"}
        t0 = time.time()
        r = self.sb.cli("bws-gated", "--async", "project", "list", "-o", "json", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLess(time.time() - t0, 1.4)
        tid = json.loads(r.stdout)["ticket"]
        self.assertIn("bws-touchid ticket wait " + tid, r.stderr)
        # the broker still answers while the approval is pending
        self.assertEqual(self.sb.cli("bws-touchid", "ping").returncode, 0)
        r = self.sb.cli("bws-touchid", "ticket", "get", tid, env=env)
        self.assertEqual(r.returncode, 75, r.stderr)
        r = self.sb.cli("bws-touchid", "ticket", "wait", tid, env={"BWS_TOUCHID_CALLER": "someone else"})
        self.assertEqual(r.returncode, 6, r.stderr)
        r = self.sb.cli("bws-touchid", "ticket", "wait", tid, "--timeout", "20", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), [{"id": AGENTS_ID, "name": "agents"}])
        r = self.sb.cli("bws-touchid", "ticket", "wait", tid, env=env)
        self.assertEqual(r.returncode, 6)
        self.assertIn("no such ticket", r.stderr)
        self.assertIn("caller=mcp test", "\n".join(self.sb.log_lines()))

    def test_save_async_env_and_deny(self):
        env = {"BWS_TOUCHID_CALLER": "mcp test", "BWS_TOUCHID_ASYNC": "1"}
        r = self.sb.cli("bws-save", "UNIT_TEST_KEY", input="fake", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        tid = json.loads(r.stdout)["ticket"]
        r = self.sb.cli("bws-touchid", "ticket", "wait", tid, env=env)
        self.assertEqual((r.returncode, r.stdout), (0, "ok created id=33333333-3333-3333-3333-333333333333\n"), r.stderr)
        self.sb.set_age(touchid={"mode": "cancel"})
        r = self.sb.cli("bws-save", "--async", "UNIT_TEST_KEY", input="fake", env=env)
        tid = json.loads(r.stdout)["ticket"]
        r = self.sb.cli("bws-touchid", "ticket", "wait", tid, env=env)
        self.assertEqual(r.returncode, 5)
        self.assertIn("refused: Touch ID / decrypt failed", r.stderr)

    def test_wait_times_out_pending(self):
        self.sb.set_age(touchid={"mode": "ok", "delay": 4})
        env = {"BWS_TOUCHID_CALLER": "mcp test"}
        tid = json.loads(self.sb.cli("bws-gated", "--async", "project", "list", env=env).stdout)["ticket"]
        t0 = time.time()
        r = self.sb.cli("bws-touchid", "ticket", "wait", tid, "--timeout", "1", env=env)
        self.assertEqual(r.returncode, 75, r.stderr)
        self.assertLess(time.time() - t0, 3)
        r = self.sb.cli("bws-touchid", "ticket", "wait", tid, "--timeout", "20", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_save_pem_file_on_stdin(self):
        """Regression: `bws-save KEY < key.p8` - a value starting with dashes must not be read as a flag."""
        pem = "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgZmFrZQ==\n-----END PRIVATE KEY-----\n"
        path = os.path.join(self.sb.root, "AuthKey_FAKE.p8")
        with open(path, "w") as f:
            f.write(pem)
        with open(path) as f:
            r = subprocess.run(["/usr/bin/python3", os.path.join(self.sb.bin, "bws-save"), "--note", "-- dashes too",
                                "APNS_TEST_KEY_P8"], stdin=f, env=self.sb.env(), capture_output=True, text=True,
                               timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok created APNS_TEST_KEY_P8", r.stdout)
        argv = self.sb.bws_runs()[-1]["argv"]
        self.assertEqual(argv[argv.index("--") + 1:], ["APNS_TEST_KEY_P8", pem.rstrip("\n"), AGENTS_ID])
        self.assertNotIn("BEGIN PRIVATE", "\n".join(self.sb.log_lines()))

    def test_fake_bws_rejects_bare_dash_values_like_real_bws(self):
        r = subprocess.run([os.path.join(self.sb.bin, "bws"), "--output", "json", "secret", "create", "K",
                            "-----BEGIN X-----", AGENTS_ID], capture_output=True, text=True, env=self.sb.env())
        self.assertEqual(r.returncode, 2)
        self.assertIn("unexpected argument '-----BEGIN X-----'", r.stderr)

    def test_usage(self):
        self.assertEqual(self.sb.cli("bws-touchid", "ticket").returncode, 2)
        self.assertEqual(self.sb.cli("bws-touchid", "ticket", "wait", "bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
