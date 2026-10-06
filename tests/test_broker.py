"""Broker tests: approver race (Touch ID vs iPhone), default-config compatibility, policy, CLI.

Run from the repo root:  python3 -m unittest -v
Uses a temp HOME, fake age / age-plugin-se / bws and a fake whispera-link approvals socket. Never
touches the Secure Enclave, real tokens, the real ~/.bws-broker or Bitwarden.
"""
import base64
import json
import os
import re
import socket
import subprocess
import time
import unittest

from tests.fakes.fake_daemon import FakeDaemon, SoftPhone
from tests.helpers import (AGENTS_ID, FAKE_IPHONE_TOKENS, FAKE_TOKENS, MAIL_ID, REPO, VECTORS, Sandbox,
                           load_module, pid_alive, write_bytes, write_text)

BOTH = ["touchid", "iphone"]
READ_REQ = {"op": "bws", "args": ["secret", "list", AGENTS_ID, "-o", "json"], "host": "build-box", "caller": "unit test"}
SAVE_REQ = {"op": "save", "key": "UNIT_TEST_KEY", "value": "fake-value-123", "host": "build-box", "caller": "unit test",
            "note": "test"}


class Base(unittest.TestCase):
    approvers = BOTH

    def setUp(self):
        self.sb = Sandbox(approvers=self.approvers)
        self.phone = SoftPhone(self.sb.root)
        self.daemon = None
        self.mod = None

    def tearDown(self):
        if self.daemon:
            self.daemon.stop()
        self.sb.cleanup()

    def start_daemon(self, **kw):
        self.daemon = FakeDaemon(self.sb.sock, self.phone, **kw)
        self.daemon.start()
        return self.daemon

    def handle(self, req, mod=None):
        if mod is None and self.mod is None:
            mod = self.sb.module()
            mod.TOUCHID_WINDOW_S = 10  # no test may sit in a 120 s window by accident
        mod = mod or self.mod
        self.mod = mod
        t0 = time.time()
        r = mod.handle(dict(req), os.getpid())
        self.elapsed = time.time() - t0
        return r

    def last_log(self):
        lines = self.sb.log_lines()
        return lines[-1] if lines else ""

    def broker_lines(self):
        self.daemon.eof_seen.wait(5)
        return self.daemon.received

    def assert_touchid_killed(self):
        runs = self.sb.age_runs("touchid")
        self.assertTrue(runs, "Touch ID leg never started")
        self.assertFalse(pid_alive(runs[-1]["pid"]), "Touch ID age process still alive")


class TestVectors(unittest.TestCase):
    """Known-answer tests from whispera-link docs/vectors/v1.json (throwaway keys)."""

    def setUp(self):
        self.sb = Sandbox()
        self.mod = self.sb.module()

    def tearDown(self):
        self.sb.cleanup()

    def test_canonical_bytes_match_vector(self):
        a = VECTORS["approval"]
        raw = self.mod.canonical_bytes(a["request"])
        self.assertEqual(raw, a["canonical_utf8"].encode("utf-8"))
        self.assertEqual(base64.b64encode(raw).decode(), a["canonical_b64"])
        self.assertEqual(base64.b64encode(b"WL1-APPROVE\n" + raw).decode(), a["signed_message_b64"])

    def test_vector_signatures_verify(self):
        m = self.mod
        a = VECTORS["approval"]
        spki = base64.b64decode(VECTORS["approve"]["spki_der_b64"])
        msg = base64.b64decode(a["signed_message_b64"])
        sig = base64.b64decode(a["signature_der_b64"])
        self.assertTrue(m.p256_verify(spki, msg, sig))
        self.assertFalse(m.p256_verify(spki, msg + b"x", sig))
        flipped = bytearray(sig)
        flipped[-1] ^= 1
        self.assertFalse(m.p256_verify(spki, msg, bytes(flipped)))
        link = base64.b64decode(VECTORS["link"]["spki_der_b64"])
        self.assertFalse(m.p256_verify(link, msg, sig), "wrong key must not verify")
        ra = VECTORS["request_auth"]
        self.assertTrue(m.p256_verify(link, ra["string_to_sign_utf8"].encode(), base64.b64decode(ra["signature_der_b64"])))

    def test_upstream_vectors_if_checked_out(self):
        """The unmodified whispera-link vector file, when that repo sits next to this one."""
        path = os.environ.get("WHISPERA_LINK_VECTORS") or os.path.join(
            os.path.dirname(REPO), "whispera-link", "docs", "vectors", "v1.json")
        if not os.path.exists(path):
            self.skipTest("whispera-link vectors not checked out at %s" % path)
        with open(path) as f:
            up = json.load(f)
        a = up["approval"]
        raw = self.mod.canonical_bytes(a["request"])
        self.assertEqual(raw, a["canonical_utf8"].encode("utf-8"))
        self.assertEqual(base64.b64encode(raw).decode(), a["canonical_b64"])
        self.assertTrue(self.mod.p256_verify(base64.b64decode(up["approve"]["spki_der_b64"]),
                                             b"WL1-APPROVE\n" + raw, base64.b64decode(a["signature_der_b64"])))

    def test_key_encodings(self):
        m = self.mod
        for k in ("link", "approve", "daemon"):
            v = VECTORS[k]
            der = base64.b64decode(v["spki_der_b64"])
            self.assertEqual(der, bytes.fromhex(VECTORS["prefix_spki_p256_hex"]) + base64.b64decode(v["public_x963_b64"]))
            self.assertEqual(m.spki_from_pem(m.pem_from_spki(der)), der)
            self.assertEqual(m.fingerprint(der), v["fingerprint"])
        self.assertEqual(m.display_fp(base64.b64decode(VECTORS["daemon"]["spki_der_b64"])), "087b-057a-3759-19bc")
        self.assertIsNone(m.spki_from_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"))
        self.assertIsNone(m.spki_from_pem(VECTORS["approve"]["private_pkcs8_pem"]))

    def test_openssl_missing_is_false(self):
        a = VECTORS["approval"]
        self.mod.OPENSSL = "/nonexistent/openssl"
        self.assertFalse(self.mod.p256_verify(base64.b64decode(VECTORS["approve"]["spki_der_b64"]),
                                              base64.b64decode(a["signed_message_b64"]),
                                              base64.b64decode(a["signature_der_b64"])))

    def test_build_canonical_fields(self):
        c = self.mod.load_config()
        obj = self.mod.build_canonical(c, op="bws", key="", summary="read secret 3f1c2a9b…", project="",
                                       token="read", host="build-box", caller="x", via="local: y", now=1791158400)
        self.assertEqual(set(obj), set(VECTORS["approval"]["request"]))
        self.assertRegex(obj["request_id"], r"^apr_[a-z2-7]{24}$")
        self.assertRegex(obj["nonce"], r"^[A-Za-z0-9_-]{22}$")
        self.assertEqual(obj["expires_at"], 1791158700)   # default approval wait: 300 s
        self.assertIn(b"\\u2026", self.mod.canonical_bytes(obj))
        c["phone_window_s"] = 5000                         # legacy key still read, clamped
        self.assertEqual(self.mod.phone_window(c), 300)
        c["phone_window_s"] = 1
        self.assertEqual(self.mod.phone_window(c), 30)
        c["approval_wait_s"] = 120                          # the new key wins over the legacy one
        self.assertEqual(self.mod.phone_window(c), 120)
        c["approval_wait_s"] = "junk"
        self.assertEqual(self.mod.phone_window(c), 300)


class TestDefaultUnchanged(unittest.TestCase):
    """approvers absent or ["touchid"]: same responses, prompts, age runs and log lines as main."""

    def run_both(self, req, age=None, approvers=None):
        results = []
        for which in ("main", "branch"):
            sb = Sandbox(approvers=approvers)
            try:
                if age:
                    sb.set_age(touchid=age)
                if which == "main":
                    path = os.path.join(sb.root, "bws-touchid-main")
                    src = subprocess.run(["git", "-C", REPO, "show", "main:bws-touchid"], capture_output=True,
                                         check=True).stdout
                    write_bytes(path, src)
                    mod = sb.module(path)
                else:
                    mod = sb.module()
                # a live daemon must never be contacted in the default config
                d = FakeDaemon(sb.sock, SoftPhone(sb.root))
                d.start()
                resp = mod.handle(dict(req), os.getpid())
                d.stop()
                strip = lambda line: re.sub(r"^ts=\S+ ", "", line)  # noqa: E731
                results.append({"resp": resp, "notify": sb.notified,
                                "age": [(r["leg"], os.path.basename(r["identity"]), os.path.basename(r["file"]))
                                        for r in sb.age_runs()],
                                "bws": sb.bws_runs(), "log": [strip(x) for x in sb.log_lines()],
                                "daemon_connections": d.connections})
            finally:
                sb.cleanup()
        return results

    def check(self, req, **kw):
        main, branch = self.run_both(req, **kw)
        self.assertEqual(main, branch)
        self.assertEqual(branch["daemon_connections"], 0)
        return branch

    def test_read_ok(self):
        r = self.check(READ_REQ)
        self.assertTrue(r["resp"]["ok"])
        self.assertEqual(r["notify"][0][0], "Touch ID: read all secrets in agents")
        self.assertNotIn("approver=", r["log"][-1])

    def test_read_ok_explicit_touchid(self):
        self.check(READ_REQ, approvers=["touchid"])

    def test_save_ok(self):
        r = self.check(SAVE_REQ)
        self.assertEqual(r["resp"]["action"], "created")

    def test_touchid_cancel(self):
        r = self.check(READ_REQ, age={"mode": "cancel"})
        self.assertFalse(r["resp"]["ok"])
        self.assertIn("Touch ID / decrypt failed", r["resp"]["error"])

    def test_touchid_error(self):
        self.check(SAVE_REQ, age={"mode": "error"})

    def test_mail_denied(self):
        self.check(dict(SAVE_REQ, key="MAIL_PASSWORD"))
        self.check(dict(READ_REQ, args=["secret", "list", MAIL_ID]))

    def test_dry_run(self):
        self.check(dict(SAVE_REQ, dryrun=True))
        self.check(dict(READ_REQ, dryrun=True))


class TestRace(Base):
    def test_phone_approve_wins(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="approve", delay=0.8)
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        # the iPhone copy was decrypted with the iPhone identity and given to bws
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_IPHONE_TOKENS["read"])
        self.assertEqual(os.path.basename(self.sb.age_runs("iphone")[-1]["file"]), "read.iphone.age")
        self.assert_touchid_killed()
        self.assertEqual(self.broker_lines(), [{"op": "approval.result", "request_id": self.daemon.requests[0]["request_id"],
                                                "outcome": "accepted"}])
        # canonical request as sent
        req = self.daemon.requests[0]
        canon = json.loads(base64.b64decode(req["canonical_b64"]))
        self.assertEqual(req["expires_at"], canon["expires_at"])
        self.assertEqual(canon["expires_at"] - canon["created_at"], 300)
        self.assertIsNone(req["prefer_device"])
        self.assertEqual((canon["op"], canon["summary"], canon["project"], canon["token"], canon["broker"]),
                         ("bws", "read all secrets in agents", "agents", "read", "Test Broker"))
        self.assertEqual(self.sb.notified[0][1][-len(" — or approve on iPhone"):], " — or approve on iPhone")
        log = self.last_log()
        self.assertIn("approver=iphone:%s request_id=%s" % (self.phone.device_id, canon["request_id"]), log)
        self.assertIn("result=exit=0", log)

    def test_phone_approve_save(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="approve")
        r = self.handle(SAVE_REQ)
        self.assertEqual(r.get("action"), "created", r)
        canon = json.loads(base64.b64decode(self.daemon.requests[0]["canonical_b64"]))
        self.assertEqual((canon["key"], canon["summary"], canon["project"], canon["token"]),
                         ("UNIT_TEST_KEY", "save UNIT_TEST_KEY → agents", "agents", "write"))
        self.assertTrue(all(b["token"] == FAKE_IPHONE_TOKENS["write"] for b in self.sb.bws_runs()))
        self.assertNotIn("fake-value-123", "\n".join(self.sb.log_lines()))

    def test_phone_deny(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="deny")
        r = self.handle(READ_REQ)
        self.assertEqual(r, {"ok": False, "error": "denied on iPhone"})
        self.assertEqual(self.sb.bws_runs(), [])
        self.assertEqual(self.sb.age_runs("iphone"), [])
        self.assert_touchid_killed()
        self.assertEqual([x["outcome"] for x in self.broker_lines()], ["accepted"])
        self.assertIn("result=denied", self.last_log())
        self.assertIn("by=iphone:" + self.phone.device_id, self.last_log())

    def _assert_rejected(self, outcome):
        r = self.handle(READ_REQ)
        self.assertFalse(r["ok"])
        self.assertIn(outcome, r["error"])
        self.assertEqual(self.sb.bws_runs(), [])
        self.assertEqual(self.sb.age_runs("iphone"), [], "iPhone token decrypted without a verified signature")
        self.assert_touchid_killed()
        self.assertEqual([x.get("outcome") for x in self.broker_lines()], [outcome])
        self.assertIn("result=denied", self.last_log())
        self.assertIn("outcome=" + outcome, self.last_log())

    def test_bad_signature_denies(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="approve_bad")
        self._assert_rejected("bad_signature")

    def test_signature_from_other_key_denies(self):
        other = SoftPhone(self.sb.root)
        other.device_id = self.phone.device_id
        self.sb.pin(other)                      # pinned key differs from the signing key
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="approve")
        self._assert_rejected("bad_signature")

    def test_unknown_device_denies(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="approve_wrong_device")
        self._assert_rejected("unknown_device")

    def test_group_writable_pin_refused(self):
        self.sb.pin(self.phone, mode=0o620)
        other = SoftPhone(self.sb.root)
        self.sb.pin(other)                      # keeps the leg configured; the signer's pin is unsafe
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="approve")
        self._assert_rejected("unknown_device")

    def test_symlink_pin_refused(self):
        real = self.sb.pin(self.phone)
        moved = real + ".real"
        os.rename(real, moved)
        os.symlink(moved, real)
        other = SoftPhone(self.sb.root)
        self.sb.pin(other)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="approve")
        self._assert_rejected("unknown_device")

    def test_malformed_line_denies(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="garbage")
        self._assert_rejected("malformed")

    def test_touchid_wins_while_phone_pending(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "ok", "delay": 0.3})
        self.start_daemon(decision="silent", delay=30)
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_TOKENS["read"])
        self.assertEqual(self.sb.age_runs("iphone"), [])
        lines = self.broker_lines()
        self.assertEqual(lines, [{"op": "approval.cancel", "request_id": self.daemon.requests[0]["request_id"],
                                  "reason": "touchid_approved"}])
        self.assertIn("approver=touchid", self.last_log())

    def test_touchid_cancel_denies(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "cancel", "delay": 0.2})
        self.start_daemon(decision="silent", delay=30)
        r = self.handle(READ_REQ)
        self.assertFalse(r["ok"])
        self.assertIn("Touch ID / decrypt failed", r["error"])
        self.assertEqual([x["reason"] for x in self.broker_lines()], ["touchid_denied"])
        self.assertIn("result=denied", self.last_log())
        self.assertIn("by=touchid", self.last_log())

    def test_touchid_error_keeps_waiting_for_phone(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "error", "delay": 0.1})
        self.start_daemon(decision="approve", delay=0.8)
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_IPHONE_TOKENS["read"])
        self.assertIn("touchid-unavailable:error", self.last_log())

    def test_both_timeout(self):
        """Touch ID keeps its own (shorter) window; the gate waits for the phone's approval_wait_s + grace."""
        self.sb.write_config(dict(self.sb.config, approval_wait_s=3))
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"})
        self.start_daemon(decision="silent", delay=60)
        mod = self.sb.module()
        mod.TOUCHID_WINDOW_S, mod.PHONE_WINDOW_MIN, mod.PHONE_GRACE_S = 1, 1, 1
        r = self.handle(READ_REQ, mod)
        self.assertEqual(r, {"ok": False, "error": "no approval within 4s (Touch ID or iPhone)"})
        self.assertGreater(self.elapsed, 2.9)  # created_at is whole seconds: deadline is 3-4 s away
        self.assertLess(self.elapsed, 6)
        self.assertIn("touchid-unavailable:timeout", self.last_log())
        self.assert_touchid_killed()
        self.assertEqual([x["reason"] for x in self.broker_lines()], ["timeout"])
        self.assertIn("result=timeout", self.last_log())
        self.assertIn("approver=none", self.last_log())
        self.assertEqual(self.sb.bws_runs(), [])

    def test_iphone_only_timeout(self):
        self.sb.write_config(dict(self.sb.config, approvers=["iphone"], phone_window_s=1))
        self.sb.pin(self.phone)
        self.start_daemon(decision="silent", delay=60)
        mod = self.sb.module()
        mod.PHONE_WINDOW_MIN, mod.PHONE_GRACE_S = 1, 1
        r = self.handle(READ_REQ, mod)
        self.assertFalse(r["ok"])
        self.assertIn("no approval within 2s", r["error"])
        self.assertEqual(self.sb.age_runs(), [])
        self.assertEqual([x["reason"] for x in self.broker_lines()], ["timeout"])

    def test_iphone_only_approve(self):
        self.sb.write_config(dict(self.sb.config, approvers=["iphone"]))
        self.sb.pin(self.phone)
        self.start_daemon(decision="approve")
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.sb.age_runs("touchid"), [])
        self.assertEqual(self.sb.notified, [])

    def test_phone_approved_but_copy_fails_no_fallback(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "hang"}, iphone={"mode": "error"})
        self.start_daemon(decision="approve")
        r = self.handle(READ_REQ)
        self.assertFalse(r["ok"])
        self.assertIn("iPhone token decrypt failed", r["error"])
        self.assertEqual(self.sb.bws_runs(), [])
        self.assertEqual(len(self.sb.age_runs("touchid")), 1, "must not fall back to the Touch ID token")
        self.assert_touchid_killed()


class TestFallback(Base):
    """The daemon is absent, slow or broken: Touch ID alone, no hang."""

    def test_daemon_absent(self):
        self.sb.pin(self.phone)
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertLess(self.elapsed, 2)
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_TOKENS["read"])
        self.assertNotIn("or approve on iPhone", self.sb.notified[0][1])
        self.assertIn("iphone-unavailable:daemon-unreachable", self.last_log())
        self.assertIn("approver=touchid", self.last_log())

    def test_daemon_absent_touchid_fails_today_error(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "error"})
        r = self.handle(READ_REQ)
        self.assertFalse(r["ok"])
        self.assertTrue(r["error"].startswith("Touch ID / decrypt failed: "), r)
        self.assertLess(self.elapsed, 2)

    def test_daemon_never_acks(self):
        self.sb.pin(self.phone)
        self.start_daemon(ack="none")
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertLess(self.elapsed, 3.5)
        self.assertIn("iphone-unavailable:no-ack", self.last_log())

    def test_daemon_zero_devices(self):
        self.sb.pin(self.phone)
        self.start_daemon(ack="zero")
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("iphone-unavailable:no-devices", self.last_log())

    def test_daemon_error(self):
        self.sb.pin(self.phone)
        self.start_daemon(ack="error")
        self.assertTrue(self.handle(READ_REQ)["ok"])
        self.assertIn("iphone-unavailable:daemon-error(malformed)", self.last_log())

    def test_daemon_eof_after_ack(self):
        self.sb.pin(self.phone)
        self.sb.set_age(touchid={"mode": "ok", "delay": 0.6})
        self.start_daemon(decision="eof", delay=0.1)
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("iphone-unavailable:daemon-eof", self.last_log())

    def test_no_pin_skips_daemon(self):
        self.start_daemon()
        self.assertTrue(self.handle(READ_REQ)["ok"])
        self.assertEqual(self.daemon.connections, 0)
        self.assertIn("iphone-unavailable:no-pinned-device", self.last_log())

    def test_no_iphone_copy_skips_daemon(self):
        os.remove(os.path.join(self.sb.tokens, "read.iphone.age"))
        self.sb.pin(self.phone)
        self.start_daemon()
        self.assertTrue(self.handle(READ_REQ)["ok"])
        self.assertEqual(self.daemon.connections, 0)
        self.assertIn("iphone-unavailable:no-iphone-token-copy", self.last_log())

    def test_iphone_only_daemon_absent(self):
        self.sb.write_config(dict(self.sb.config, approvers=["iphone"]))
        self.sb.pin(self.phone)
        r = self.handle(READ_REQ)
        self.assertEqual(r, {"ok": False, "error": "no approver available (Touch ID unavailable, iPhone not connected)"})
        self.assertLess(self.elapsed, 2)
        self.assertIn("result=no-approver", self.last_log())


class TestPolicy(Base):
    def test_mail_denied_regardless_of_approver(self):
        self.sb.pin(self.phone)
        for approvers in (["touchid"], BOTH, ["iphone"]):
            self.sb.write_config(dict(self.sb.config, approvers=approvers))
            self.start_daemon(decision="approve")
            mod = self.sb.module()
            for req in (dict(SAVE_REQ, key="MAIL_PASSWORD"), dict(SAVE_REQ, project="mail"),
                        dict(READ_REQ, args=["secret", "list", MAIL_ID]),
                        dict(READ_REQ, args=["project", "get", MAIL_ID])):
                r = mod.handle(dict(req), os.getpid())
                self.assertFalse(r["ok"], (approvers, req, r))
            # an allowed read still scrubs MAIL_ secrets from the output
            r = mod.handle(dict(READ_REQ, args=["secret", "list"]), os.getpid())
            self.assertEqual(json.loads(base64.b64decode(r["stdout_b64"])), [])
            self.daemon.stop()
            self.assertEqual(self.daemon.connections, 0 if approvers == ["touchid"] else 1,
                             "only the allowed read may reach the approvers")
            self.daemon = None
        self.assertEqual([b["argv"][-1] for b in self.sb.bws_runs()].count(MAIL_ID), 0)

    def test_bad_approvers_config_fails_closed(self):
        for bad in (["touchid", "faceid"], [], "touchid", ["iphone", "iphone"]):
            self.sb.write_config(dict(self.sb.config, approvers=bad))
            mod = self.sb.module()
            for req in (READ_REQ, SAVE_REQ):
                self.assertEqual(mod.handle(dict(req), os.getpid()), {"ok": False, "error": "bad approvers config"})
        self.assertEqual(self.sb.age_runs(), [])

    def test_ping_unaffected(self):
        self.sb.write_config(dict(self.sb.config, approvers=["nope"]))
        self.assertTrue(self.handle({"op": "ping"})["ok"])


class TestCli(Base):
    def test_serve_ping_and_dry_runs(self):
        p = subprocess.Popen(["/usr/bin/python3", os.path.join(self.sb.bin, "bws-touchid"), "serve"], env=self.sb.env(),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            sock = os.path.join(self.sb.home, ".bws-broker", "broker.sock")
            for _ in range(50):
                if os.path.exists(sock):
                    break
                time.sleep(0.1)
            r = self.sb.cli("bws-touchid", "ping")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("Test Broker", r.stdout)
            r = self.sb.cli("bws-save", "--dry-run", "UNIT_TEST_KEY", input="fake")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("ok dry-run UNIT_TEST_KEY id=dryrun", r.stdout)
            r = self.sb.cli("bws-gated", "project", "list", env={"BWS_BROKER_DRYRUN": "1"})
            self.assertEqual((r.returncode, r.stdout), (0, "[]"), r.stderr)
            # a real (fake-backed) phone approval through the served socket
            self.sb.pin(self.phone)
            self.sb.set_age(touchid={"mode": "hang"})
            self.start_daemon(decision="approve")
            r = self.sb.cli("bws-gated", "project", "list", "-o", "json", env={"BWS_TOUCHID_CALLER": "cli test"})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout), [{"id": AGENTS_ID, "name": "agents"}])
            self.assertIn("caller=cli test", self.last_log())
            self.assertIn("approver=iphone:", self.last_log())
            r = self.sb.cli("bws-touchid", "status")
            self.assertIn("approvers: touchid, iphone", r.stdout)
            self.assertIn("pinned:    %s" % self.phone.device_id, r.stdout)
            self.assertIn("iphone tokens: read, write", r.stdout)
            self.assertIn("approvals.sock: accepts connections", r.stdout)
            self.assertIn("tokens:    read, write\n", r.stdout)
        finally:
            p.terminate()
            p.wait(5)

    def test_approver_add_list_remove(self):
        pem = os.path.join(self.sb.root, "approve.pem")
        write_text(pem, self.phone.pem())
        mod = self.sb.module()
        der = mod.spki_from_pem(self.phone.pem())
        last4 = mod.display_fp(der).replace("-", "")[-4:]
        r = self.sb.cli("bws-touchid", "approver", "add", self.phone.device_id, pem, input="zzzz\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fingerprint mismatch", r.stderr)
        self.assertEqual(self.sb.age_runs(), [])
        r = self.sb.cli("bws-touchid", "approver", "add", self.phone.device_id, pem, input=last4.upper() + "\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(mod.display_fp(der), r.stdout)
        self.assertEqual(len(self.sb.age_runs("touchid")), 1, "approver add needs one Touch ID")
        pin = os.path.join(self.sb.approvers_dir, self.phone.device_id + ".pub")
        self.assertEqual(os.stat(pin).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.sb.approvers_dir).st_mode & 0o777, 0o700)
        self.assertEqual(mod.load_pin(mod.load_config(), self.phone.device_id)[0], der)
        r = self.sb.cli("bws-touchid", "approver", "list")
        self.assertIn("%s  %s" % (self.phone.device_id, mod.display_fp(der)), r.stdout)
        r = self.sb.cli("bws-touchid", "approver", "remove", self.phone.device_id)
        self.assertEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(pin))
        self.assertEqual(len(self.sb.age_runs("touchid")), 1, "remove needs no Touch ID")
        log = "\n".join(self.sb.log_lines())
        for op in ("approver-add", "approver-list", "approver-remove"):
            self.assertIn("op=" + op, log)
        r = self.sb.cli("bws-touchid", "approver", "add", "dev_BAD", pem, input="x\n")
        self.assertEqual(r.returncode, 2)
        r = self.sb.cli("bws-touchid", "approver", "add", self.phone.device_id, self.phone.key, input="x\n")
        self.assertIn("not a P-256 public key", r.stderr)

    def test_iphone_setup(self):
        for f in ("identity-iphone.txt", "recipient-iphone.txt", "tokens/read.iphone.age", "tokens/write.iphone.age"):
            os.remove(os.path.join(self.sb.conf, f))
        r = self.sb.cli("bws-touchid", "iphone-setup")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("approver add", r.stdout)
        self.assertEqual(len(self.sb.age_runs("touchid")), 2, "one Touch ID per token")
        self.assertIn(["keygen", "--access-control", "none", "-o", os.path.join(self.sb.conf, "identity-iphone.txt")],
                      self.sb.jsonl("plugin.log"))
        for name in ("read", "write"):
            path = os.path.join(self.sb.tokens, name + ".iphone.age")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            out = subprocess.run([os.path.join(self.sb.bin, "age"), "-d", "-i",
                                  os.path.join(self.sb.conf, "identity-iphone.txt"), path],
                                 capture_output=True, text=True, env=self.sb.env())
            self.assertEqual(out.stdout, FAKE_TOKENS[name])
        self.assertFalse([f for f in os.listdir(self.sb.tokens) if f.endswith(".tmp")])
        for run in self.sb.age_runs("encrypt"):
            self.assertNotIn("fake", " ".join(str(v) for v in run.values() if v != run["file"]))

    def test_store_writes_iphone_copy(self):
        tok = "0.00000000-0000-0000-0000-000000000009.fakenew:ZmFrZQ=="
        r = self.sb.cli("bws-touchid", "store", "extra", "--stdin", input=tok + "\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.sb.tokens, "extra.age")))
        self.assertTrue(os.path.exists(os.path.join(self.sb.tokens, "extra.iphone.age")))
        r = self.sb.cli("bws-touchid", "delete", "extra")
        self.assertFalse(os.path.exists(os.path.join(self.sb.tokens, "extra.iphone.age")))
        os.remove(os.path.join(self.sb.conf, "recipient-iphone.txt"))
        r = self.sb.cli("bws-touchid", "store", "extra2", "--stdin", input=tok + "\n")
        self.assertFalse(os.path.exists(os.path.join(self.sb.tokens, "extra2.iphone.age")))


if __name__ == "__main__":
    unittest.main()
