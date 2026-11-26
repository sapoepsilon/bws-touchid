"""Passcode approver: opt-in, sealed copies (fake age -j batchpass), the dialog leg in the race, the
attempt counter / backoff / lockout, Touch ID unlock, and the `passcode` CLI on a real pseudo-terminal.

Uses the same sandbox as the other tests (temp HOME, fake age / age-plugin-se / age-plugin-batchpass /
osascript / bws). Never touches the real ~/.config/bws-touchid, ~/.bws-broker, a real dialog or Bitwarden.
"""
import fcntl
import json
import os
import pty
import re
import select
import signal
import subprocess
import threading
import time
import unittest

from tests.helpers import (AGENTS_ID, FAKE_PASSCODE_TOKENS, FAKE_TOKENS, PASSCODE, PASSCODE_MAGIC, REPO, Sandbox,
                           read_text, write_text)

READ_REQ = {"op": "bws", "args": ["secret", "list", AGENTS_ID, "-o", "json"], "host": "build-box", "caller": "unit test"}
SAVE_REQ = {"op": "save", "key": "UNIT_TEST_KEY", "value": "fake-value-123", "host": "build-box", "caller": "unit test",
            "note": "test"}
WRONG = "Wr0ng-Guess-%d"
TP = ["touchid", "passcode"]


def run_pty(sb, args, answers, env=None, timeout=60, on_prompt=None):
    """Run bws-touchid on a fresh pseudo-terminal that is its controlling tty, typing one answer per
    getpass prompt (on_prompt(i) runs just before answer i is typed). Returns (exit code, all the
    terminal showed)."""
    pid, fd = pty.fork()
    if pid == 0:  # child
        try:
            os.execve("/usr/bin/python3", ["/usr/bin/python3", os.path.join(sb.bin, "bws-touchid")] + list(args),
                      sb.env(**(env or {})))
        finally:
            os._exit(127)
    out, pending, end = b"", list(answers), time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:   # EIO: the child closed the terminal
                break
            if not chunk:
                break
            out += chunk
        prompts = out.count(b"hidden): ") + out.count(b"Repeat it: ")
        if pending and prompts > len(answers) - len(pending):
            if on_prompt:
                on_prompt(len(answers) - len(pending))
            os.write(fd, (pending.pop(0) + "\n").encode())
    else:
        os.kill(pid, signal.SIGKILL)
    os.close(fd)
    _, status = os.waitpid(pid, 0)
    code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
    return code, out.decode("utf-8", "replace")


class Base(unittest.TestCase):
    approvers = TP

    def setUp(self):
        self.sb = Sandbox(approvers=self.approvers, iphone=False)
        self.sb.write_passcode_copies()
        self.sb.set_dialog([PASSCODE])
        self.mod = None

    def tearDown(self):
        self.sb.cleanup()

    def module(self):
        mod = self.sb.module()
        mod.TOUCHID_WINDOW_S = 10
        mod.PASSCODE_WINDOW_S = 10
        mod.PASSCODE_BACKOFF_S = 0.02
        return mod

    def handle(self, req, mod=None):
        self.mod = mod or self.mod or self.module()
        t0 = time.time()
        r = self.mod.handle(dict(req), os.getpid())
        self.elapsed = time.time() - t0
        return r

    def last_log(self):
        lines = [l for l in self.sb.log_lines() if " op=passcode " not in l]
        return lines[-1] if lines else ""

    def procs_alive(self, exe):
        r = subprocess.run(["/bin/ps", "-ax", "-o", "pid=,stat=,command="], capture_output=True, text=True)
        me = os.path.join(self.sb.bin, exe)
        return [l.split()[0] for l in r.stdout.splitlines() if me in l and not l.split()[1].startswith("Z")]

    def decrypt_copy(self, name, passcode):
        r, w = os.pipe()
        os.write(w, passcode.encode())
        os.close(w)
        env = self.sb.env(AGE_PASSPHRASE_FD=str(r))
        p = subprocess.run([os.path.join(self.sb.bin, "age"), "-d", "-j", "batchpass",
                            os.path.join(self.sb.tokens, name + ".passcode.age")], pass_fds=(r,), env=env,
                           capture_output=True, text=True)
        os.close(r)
        return p


class TestDisabledByDefault(Base):
    approvers = None

    def test_default_config_never_prompts_for_a_passcode(self):
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.sb.dialog_runs(), [])
        self.assertEqual(self.sb.age_runs("passcode"), [])
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_TOKENS["read"])
        self.assertNotIn("approver=", self.last_log())

    def test_touchid_iphone_config_ignores_passcode_copies(self):
        self.sb.write_config(dict(self.sb.config, approvers=["touchid", "iphone"]))
        r = self.handle(SAVE_REQ)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.sb.dialog_runs(), [])
        self.assertIn("approver=touchid", self.last_log())

    def test_shipped_defaults(self):
        mod = self.module()
        self.assertEqual(mod.DEFAULTS["approvers"], ["touchid"])
        with open(os.path.join(REPO, "config.example.json")) as f:
            example = json.load(f)
        self.assertEqual(example["approvers"], ["touchid"])
        self.assertIn("passcode", example["_approvers"])
        r = self.sb.cli("bws-touchid", "passcode", "status")
        self.assertIn("approver:  off", r.stdout)


class TestPasscodeGate(Base):
    def test_correct_passcode_unlocks_and_kills_touchid(self):
        self.sb.hold_touchid()      # Touch ID never answers
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_PASSCODE_TOKENS["read"], "decrypted the passcode copy")
        self.assertIn("approver=passcode", self.last_log())
        self.assertIn("— or enter passcode", self.sb.notified[0][1])
        self.assertEqual(self.sb.touchid_procs_alive(), [])
        self.assertEqual(self.sb.pc_state()["failures"], 0)
        run = self.sb.dialog_runs()[0]
        script = " ".join(run["argv"])
        self.assertIn("with hidden answer", script)
        self.assertIn("read all secrets in agents", script)

    def test_passcode_only_save(self):
        self.sb.write_config(dict(self.sb.config, approvers=["passcode"]))
        r = self.handle(SAVE_REQ)
        self.assertEqual(r.get("action"), "created", r)
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_PASSCODE_TOKENS["write"])
        self.assertEqual(self.sb.age_runs("touchid"), [])
        self.assertIn("approver=passcode", self.last_log())

    def test_touchid_still_wins_and_closes_the_dialog(self):
        self.sb.set_dialog(mode="hang")
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("approver=touchid", self.last_log())
        self.assertEqual(self.sb.bws_runs()[-1]["token"], FAKE_TOKENS["read"])
        self.assertEqual(self.procs_alive("osascript"), [], "dialog left open")

    def test_wrong_then_right_reprompts_and_counts(self):
        self.sb.write_config(dict(self.sb.config, approvers=["passcode"]))
        self.sb.set_dialog([WRONG % 1, PASSCODE])
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        runs = self.sb.dialog_runs()
        self.assertEqual(len(runs), 2)
        self.assertIn("Wrong passcode (1 of 5 attempts used)", " ".join(runs[1]["argv"]))
        log = "\n".join(self.sb.log_lines())
        self.assertRegex(log, r"op=passcode result=wrong token=read detail=failures=1/5 via=dialog")
        self.assertIn("passcode-wrong:1", self.last_log())
        self.assertEqual(self.sb.pc_state(), {"v": 1, "failures": 0, "last_failure": 0, "locked": False})

    def test_dialog_deny_is_final(self):
        self.sb.hold_touchid()
        self.sb.set_dialog(mode="cancel")
        r = self.handle(READ_REQ)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "denied in the passcode dialog")
        self.assertIn("result=denied", self.last_log())
        self.assertIn("by=passcode", self.last_log())
        self.assertEqual(self.sb.bws_runs(), [])
        self.assertEqual(self.sb.touchid_procs_alive(), [])
        self.assertEqual(self.sb.pc_state()["failures"], 0, "a deny is not a failed attempt")

    def test_dialog_unavailable_keeps_touchid(self):
        self.sb.set_dialog(mode="error")
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("approver=touchid", self.last_log())
        self.assertIn("passcode-unavailable:dialog-error", self.last_log())

    def test_swapped_copy_denies(self):
        write_text(os.path.join(self.sb.tokens, "read.passcode.age"),
                   read_text(os.path.join(self.sb.tokens, "write.passcode.age")))
        self.sb.write_config(dict(self.sb.config, approvers=["passcode"]))
        r = self.handle(READ_REQ)
        self.assertFalse(r["ok"])
        self.assertIn("copy-mismatch", r["error"])
        self.assertEqual(self.sb.bws_runs(), [])

    def test_unsafe_files_skip_the_leg(self):
        os.chmod(os.path.join(self.sb.tokens, "read.passcode.age"), 0o644)
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("passcode-unavailable:unsafe-file-mode", self.last_log())
        self.assertEqual(self.sb.dialog_runs(), [])

    def test_no_copy_skips_the_leg(self):
        os.remove(os.path.join(self.sb.tokens, "read.passcode.age"))
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("passcode-unavailable:no-passcode-copy", self.last_log())

    def test_missing_plugin_skips_the_leg(self):
        os.remove(os.path.join(self.sb.bin, "age-plugin-batchpass"))   # configured path, now missing
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("passcode-unavailable:no-batchpass-plugin", self.last_log())

    def test_three_approvers_coexist(self):
        self.sb.write_config(dict(self.sb.config, approvers=["touchid", "iphone", "passcode"]))
        self.sb.hold_touchid()
        r = self.handle(READ_REQ)      # no whispera-link daemon: the phone leg is skipped
        self.assertTrue(r["ok"], r)
        self.assertIn("approver=passcode", self.last_log())
        self.assertIn("iphone-unavailable:", self.last_log())

    def test_bad_approver_name_still_fails_closed(self):
        self.sb.write_config(dict(self.sb.config, approvers=["touchid", "pin"]))
        r = self.handle(READ_REQ)
        self.assertEqual(r["error"], "bad approvers config")


class TestBruteForce(Base):
    approvers = ["passcode"]

    def test_lockout_after_five_and_touchid_unlock(self):
        self.sb.set_dialog([WRONG % i for i in range(1, 8)])
        r = self.handle(READ_REQ)
        self.assertFalse(r["ok"])
        self.assertIn("passcode-unavailable:locked", r["error"])
        self.assertEqual(len(self.sb.dialog_runs()), 5, "no sixth prompt")
        st = self.sb.pc_state()
        self.assertEqual((st["failures"], st["locked"]), (5, True))
        self.assertEqual(os.stat(self.sb.pc_state_path).st_mode & 0o777, 0o600)
        log = "\n".join(self.sb.log_lines())
        self.assertEqual(log.count("op=passcode result=wrong"), 4)
        self.assertIn("op=passcode result=locked token=read detail=failures=5/5", log)
        self.assertIn("bws-touchid: passcode locked", [t for t, _m in self.sb.notified])
        # locked: even the right passcode is never asked for
        self.sb.set_dialog([PASSCODE])
        r = self.handle(READ_REQ)
        self.assertFalse(r["ok"])
        self.assertEqual(self.sb.dialog_runs()[-1]["n"], 4, "dialog shown while locked")
        self.assertEqual(len(self.sb.dialog_runs()), 5)
        # Touch ID still works while the passcode is locked, and does not clear the lock by itself
        self.sb.write_config(dict(self.sb.config, approvers=TP))
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("passcode-unavailable:locked", self.last_log())
        self.assertTrue(self.sb.pc_state()["locked"])
        # only Touch ID (passcode unlock) clears it
        self.sb.set_age(touchid={"mode": "cancel"})
        r = self.sb.cli("bws-touchid", "passcode", "unlock")
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(self.sb.pc_state()["locked"])
        self.sb.set_age()
        n_touch = len(self.sb.age_runs("touchid"))
        r = self.sb.cli("bws-touchid", "passcode", "unlock")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.sb.age_runs("touchid")), n_touch + 1, "unlock needs one Touch ID")
        self.assertEqual(self.sb.pc_state(), {"v": 1, "failures": 0, "last_failure": 0, "locked": False})
        self.assertIn("op=passcode-unlock result=ok", self.sb.log_lines()[-1])
        self.sb.write_config(dict(self.sb.config, approvers=["passcode"]))
        self.sb.set_dialog([PASSCODE])
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)

    def test_backoff_grows_exponentially(self):
        mod = self.module()
        mod.PASSCODE_BACKOFF_S = 5.0
        self.assertEqual([mod.passcode_backoff(n) for n in range(0, 5)], [0.0, 5.0, 20.0, 80.0, 320.0])
        now = time.time()
        self.sb.write_pc_state(failures=2, last_failure=now)
        self.assertEqual(mod.passcode_check(mod.passcode_state(), now + 1)[0], "backoff")
        self.assertEqual(mod.passcode_check(mod.passcode_state(), now + 21), ("", 0.0))
        r = self.handle(READ_REQ, mod)        # 20 s backoff is longer than the 10 s window: no prompt
        self.assertFalse(r["ok"])
        self.assertIn("passcode-unavailable:backoff(", r["error"])
        self.assertEqual(self.sb.dialog_runs(), [])

    def test_short_backoff_is_waited_out_before_the_prompt(self):
        mod = self.module()
        mod.PASSCODE_BACKOFF_S = 0.6
        self.sb.write_pc_state(failures=1, last_failure=time.time())
        r = self.handle(READ_REQ, mod)
        self.assertTrue(r["ok"], r)
        self.assertGreaterEqual(self.elapsed, 0.5)
        self.assertEqual(len(self.sb.dialog_runs()), 1)

    def test_missing_corrupt_or_unsafe_state_is_locked(self):
        p = self.sb.pc_state_path
        elsewhere = os.path.join(self.sb.root, "elsewhere.json")
        self.sb._write(elsewhere, json.dumps({"v": 1, "failures": 0, "last_failure": 0, "locked": False}))

        def symlinked():
            os.remove(p)
            os.symlink(elsewhere, p)
        for setup in (lambda: os.remove(p), lambda: write_text(p, "{not json"), lambda: os.chmod(p, 0o644),
                      lambda: write_text(p, json.dumps({"failures": 0, "last_failure": 0})), symlinked):
            if os.path.lexists(p):
                os.remove(p)
            self.sb.write_pc_state()
            setup()
            self.sb.set_dialog([PASSCODE])
            r = self.handle(READ_REQ)
            self.assertFalse(r["ok"])
            self.assertIn("passcode-unavailable:locked(state-missing-or-unsafe)", r["error"])
            self.assertEqual(self.sb.dialog_runs(), [])

    def test_attempt_is_counted_before_the_decrypt(self):
        self.sb.set_age(passcode={"mode": "hang"})
        mod = self.module()
        mod.PASSCODE_DECRYPT_S = 1
        r = self.handle(READ_REQ, mod)
        self.assertFalse(r["ok"])
        self.assertEqual(self.sb.pc_state()["failures"], 1, "a verify that never finished still counts")


class TestNoLeaks(Base):
    def test_passcode_never_in_argv_env_logs_or_notifications(self):
        self.sb.write_config(dict(self.sb.config, approvers=["passcode"]))
        self.sb.set_dialog([WRONG % 1, PASSCODE])
        self.assertTrue(self.handle(READ_REQ)["ok"])
        pc_runs = self.sb.age_runs("passcode")
        self.assertEqual(len(pc_runs), 2)
        for run in pc_runs:
            self.assertIn("AGE_PASSPHRASE_FD", run["env"])
            self.assertNotIn("AGE_PASSPHRASE", run["env"])
            self.assertEqual(run["argv"][1:4], ["-d", "-j", "batchpass"])
        blobs = [read_text(os.path.join(self.sb.state, f)) for f in os.listdir(self.sb.state)
                 if f.endswith(".log")]
        blobs += self.sb.log_lines() + [json.dumps(self.sb.notified)]
        for secret in (PASSCODE, WRONG % 1):
            for blob in blobs:
                self.assertNotIn(secret, blob)
        for run in self.sb.dialog_runs():
            self.assertNotIn(PASSCODE, json.dumps(run))


class TestCli(Base):
    def test_set_change_remove_status(self):
        for f in os.listdir(self.sb.tokens):
            if ".passcode." in f:
                os.remove(os.path.join(self.sb.tokens, f))
        os.remove(self.sb.pc_state_path)
        r = self.sb.cli("bws-touchid", "passcode", "status")
        self.assertIn("passcode:  not set", r.stdout)
        # too short, then mismatch: nothing written
        code, out = run_pty(self.sb, ["passcode", "set"], ["short"])
        self.assertEqual(code, 1, out)
        self.assertIn("at least 8 characters", out)
        code, out = run_pty(self.sb, ["passcode", "set"], [PASSCODE, PASSCODE + "x"])
        self.assertEqual(code, 1, out)
        self.assertIn("differ", out)
        self.assertFalse([f for f in os.listdir(self.sb.tokens) if ".passcode." in f])
        # set
        n_touch = len(self.sb.age_runs("touchid"))
        code, out = run_pty(self.sb, ["passcode", "set"], [PASSCODE, PASSCODE])
        self.assertEqual(code, 0, out)
        self.assertNotIn(PASSCODE, out, "the terminal echoed the passcode")
        self.assertEqual(len(self.sb.age_runs("touchid")), n_touch + 2, "one Touch ID per token")
        for name in ("read", "write"):
            path = os.path.join(self.sb.tokens, name + ".passcode.age")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            p = self.decrypt_copy(name, PASSCODE)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout[len(PASSCODE_MAGIC):]), {"token": FAKE_TOKENS[name], "name": name})
            self.assertNotEqual(self.decrypt_copy(name, "not-the-passcode").returncode, 0)
        self.assertEqual(os.stat(self.sb.pc_state_path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.sb.tokens).st_mode & 0o777, 0o700)
        self.assertEqual(self.sb.pc_state()["failures"], 0)
        self.assertFalse([f for f in os.listdir(self.sb.tokens) if f.endswith(".tmp")])
        enc = self.sb.age_runs("passcode-encrypt")
        self.assertEqual(len(enc), 2)
        self.assertTrue(all(e["work_factor"] == "18" for e in enc))
        r = self.sb.cli("bws-touchid", "passcode", "status")
        self.assertIn("passcode:  set (read, write), 0/5 failed", r.stdout)
        self.assertIn("approver:  on", r.stdout)
        r = self.sb.cli("bws-touchid", "status")
        self.assertIn("passcode:  set (read, write)", r.stdout)
        self.assertIn("tokens:    read, write\n", r.stdout)
        # set again is refused; change re-seals with the new passcode only
        code, out = run_pty(self.sb, ["passcode", "set"], [])
        self.assertEqual(code, 2, out)
        self.assertIn("already set", out)
        self.sb.write_pc_state(failures=3, last_failure=time.time())
        new = "An0ther-Passc0de!"
        code, out = run_pty(self.sb, ["passcode", "change"], [new, new])
        self.assertEqual(code, 0, out)
        self.assertEqual(self.decrypt_copy("read", new).returncode, 0)
        self.assertNotEqual(self.decrypt_copy("read", PASSCODE).returncode, 0)
        self.assertEqual(self.sb.pc_state()["failures"], 0, "change (Touch ID) resets the counter")
        log = "\n".join(self.sb.log_lines())
        self.assertIn("op=passcode-set result=ok detail=copies=read,write", log)
        self.assertIn("op=passcode-change result=ok", log)
        for secret in (PASSCODE, new):
            self.assertNotIn(secret, log)
            self.assertNotIn(secret, read_text(os.path.join(self.sb.state, "age.log")))
        # store rotates a token: its stale passcode copy goes
        r = self.sb.cli("bws-touchid", "store", "read", "--stdin",
                        input="0.00000000-0000-0000-0000-000000000009.fakenew:ZmFrZQ==\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.sb.tokens, "read.passcode.age")))
        self.assertIn("passcode change", r.stdout)
        # remove
        r = self.sb.cli("bws-touchid", "passcode", "remove")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse([f for f in os.listdir(self.sb.tokens) if ".passcode." in f])
        self.assertFalse(os.path.exists(self.sb.pc_state_path))
        self.assertIn('remove "passcode" from "approvers"', r.stdout)
        self.assertIn("op=passcode-remove result=ok", self.sb.log_lines()[-1])
        code, out = run_pty(self.sb, ["passcode", "change"], [])
        self.assertEqual(code, 2)
        self.assertIn("no passcode set", out)

    def test_set_needs_touchid_first(self):
        for f in os.listdir(self.sb.tokens):
            if ".passcode." in f:
                os.remove(os.path.join(self.sb.tokens, f))
        self.sb.set_age(touchid={"mode": "cancel"})
        code, out = run_pty(self.sb, ["passcode", "set"], [PASSCODE, PASSCODE])
        self.assertEqual(code, 1, out)
        self.assertNotIn("New passcode", out, "asked for the passcode before Touch ID")
        self.assertFalse([f for f in os.listdir(self.sb.tokens) if ".passcode." in f])
        self.assertIn("op=passcode-set result=auth-failed", "\n".join(self.sb.log_lines()))

    def test_set_without_a_terminal_refuses(self):
        r = self.sb.cli("bws-touchid", "passcode", "change", input=PASSCODE + "\n" + PASSCODE + "\n",
                        start_new_session=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("needs a terminal", r.stderr)
        self.assertEqual(self.sb.age_runs(), [], "no Touch ID or sealing without a terminal")

    def test_run_with_passcode_on_the_tty(self):
        code, out = run_pty(self.sb, ["run", "--passcode", "--", "/usr/bin/printenv", "BWS_ACCESS_TOKEN"], [PASSCODE])
        self.assertEqual(code, 0, out)
        self.assertIn(FAKE_PASSCODE_TOKENS["read"], out)
        self.assertEqual(self.sb.age_runs("touchid"), [])
        self.assertIn("approver=passcode", self.sb.log_lines()[-1])
        code, out = run_pty(self.sb, ["run", "--passcode", "--", "/usr/bin/true"], [WRONG % 1])
        self.assertEqual(code, 5, out)
        self.assertIn("wrong passcode (1 of 5 attempts used)", out)
        self.assertEqual(self.sb.pc_state()["failures"], 1)
        self.assertIn("op=passcode result=wrong token=read detail=failures=1/5 via=run", self.sb.log_lines()[-1])
        self.sb.write_pc_state(failures=5, last_failure=time.time(), locked=True)
        code, out = run_pty(self.sb, ["run", "--passcode", "--", "/usr/bin/true"], [PASSCODE])
        self.assertEqual(code, 5, out)
        self.assertIn("passcode locked", out)
        self.assertNotIn("hidden): ", out, "prompted while locked")

    def test_run_passcode_refused_when_approver_off(self):
        self.sb.write_config(dict(self.sb.config, approvers=["touchid"]))
        code, out = run_pty(self.sb, ["run", "--passcode", "--", "/usr/bin/true"], [PASSCODE])
        self.assertEqual(code, 2, out)
        self.assertIn("passcode approver is off", out)

    def test_usage(self):
        r = self.sb.cli("bws-touchid", "passcode", "frobnicate")
        self.assertEqual(r.returncode, 2)
        self.assertIn("passcode set | change | remove | status | unlock", r.stderr)


class TestReviewFixes(Base):
    """Security review round 1."""

    def test_touchid_win_abandons_a_slow_verify_promptly(self):
        # finding 1: Touch ID answers at ~0.8 s while the passcode verify takes 6 s
        self.sb.set_age(touchid={"mode": "ok", "delay": 0.8}, passcode={"mode": "ok", "delay": 6})
        self.sb.set_dialog([WRONG % 1])
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("approver=touchid", self.last_log())
        self.assertLess(self.elapsed, 4, "cancel waited for the in-flight verify")
        self.assertEqual(self.sb.pc_state()["failures"], 1, "the abandoned attempt still counts")
        log = "\n".join(self.sb.log_lines())
        self.assertRegex(log, r"op=passcode result=abandoned token=read detail=failures=1/5 via=dialog "
                              r"reason=touchid_approved")
        self.assertIn("passcode-abandoned:1", self.last_log())
        self.assertEqual(self.procs_alive("age"), [], "verify left running")

    def test_abandoned_fifth_attempt_notifies_the_lockout(self):
        self.sb.write_pc_state(failures=4, last_failure=0)
        self.sb.set_age(touchid={"mode": "ok", "delay": 0.8}, passcode={"mode": "ok", "delay": 6})
        self.sb.set_dialog([WRONG % 5])
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("op=passcode result=abandoned token=read detail=failures=5/5", "\n".join(self.sb.log_lines()))
        self.assertIn("bws-touchid: passcode locked", [t for t, _m in self.sb.notified])
        self.assertTrue(self.sb.pc_state()["locked"])

    def test_hanging_verify_waits_the_bound_once(self):
        self.sb.write_config(dict(self.sb.config, approvers=["passcode"]))
        self.sb.set_age(passcode={"mode": "hang"})
        mod = self.module()
        mod.PASSCODE_DECRYPT_S = 2
        r = self.handle(READ_REQ, mod)
        self.assertFalse(r["ok"])
        self.assertLess(self.elapsed, 3.5, "the verify timeout waited twice")
        self.assertGreaterEqual(self.elapsed, 1.9)
        self.assertIn("passcode-unavailable:error", r["error"])
        self.assertIn("passcode-error:1", r["error"])
        log = "\n".join(self.sb.log_lines())
        self.assertIn("op=passcode result=error token=read detail=failures=1/5 via=dialog", log)   # as documented
        self.assertNotIn("result=abandoned", log)
        self.assertEqual(self.sb.pc_state()["failures"], 1)

    def test_tool_error_counts_but_ends_the_leg(self):
        # finding 4: a plugin crash is not a wrong passcode: no "Wrong passcode" re-prompt
        self.sb.write_config(dict(self.sb.config, approvers=["passcode"]))
        self.sb.set_age(passcode={"mode": "error"})
        self.sb.set_dialog([PASSCODE, PASSCODE])
        r = self.handle(READ_REQ)
        self.assertFalse(r["ok"])
        self.assertEqual(len(self.sb.dialog_runs()), 1, "re-prompted after a tool error")
        self.assertIn("passcode-unavailable:error", r["error"])
        self.assertIn("passcode-error:1", r["error"])
        self.assertEqual(self.sb.pc_state()["failures"], 1, "still counted (conservative)")
        self.assertIn("op=passcode result=error token=read detail=failures=1/5 via=dialog",
                      "\n".join(self.sb.log_lines()))

    def test_tool_error_falls_back_to_touchid(self):
        self.sb.set_age(touchid={"mode": "ok", "delay": 1.5}, passcode={"mode": "error"})
        self.sb.set_dialog([PASSCODE, PASSCODE])
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("approver=touchid", self.last_log())
        self.assertEqual(len(self.sb.dialog_runs()), 1)

    def test_busy_state_lock_does_not_hang_the_gate(self):
        # finding 5: someone holds the counter's flock; the passcode leg gives up, Touch ID still works
        fd = os.open(self.sb.pc_state_path, os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        release = threading.Timer(8, lambda: os.close(fd))
        release.start()
        try:
            mod = self.module()
            mod.PASSCODE_LOCK_S = 0.3
            r = self.handle(READ_REQ, mod)
        finally:
            release.cancel()
            try:
                os.close(fd)
            except OSError:
                pass
        self.assertTrue(r["ok"], r)
        self.assertLess(self.elapsed, 4, "the gate waited on the state lock")
        self.assertIn("approver=touchid", self.last_log())
        self.assertIn("passcode-unavailable:locked(state-busy)", self.last_log())
        self.assertEqual(self.sb.dialog_runs(), [])
        self.assertEqual(self.sb.pc_state()["failures"], 0)

    def test_busy_state_lock_never_deletes_the_counter(self):
        mod = self.module()
        mod.PASSCODE_LOCK_S = 0.2
        self.sb.write_pc_state(failures=3, last_failure=1)
        fd = os.open(self.sb.pc_state_path, os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        release = threading.Timer(3, lambda: fcntl.flock(fd, fcntl.LOCK_UN))   # so a blocking flock cannot hang
        release.start()
        t0 = time.time()
        try:
            self.assertEqual(mod.passcode_begin_attempt(), (None, "locked(state-busy)"))
            self.assertFalse(mod.passcode_reset(create=True))
            self.assertEqual(mod.passcode_check(mod.passcode_state(), time.time())[0], "locked(state-busy)")
        finally:
            release.cancel()
            os.close(fd)
        self.assertLess(time.time() - t0, 2.5)
        self.assertEqual(self.sb.pc_state()["failures"], 3)

    def test_summary_reads_the_state_once(self):
        # finding 7: the state vanishing between two reads raised TypeError
        mod = self.module()
        answers = [{"failures": 1, "last_failure": time.time(), "locked": False}, None]
        mod.passcode_state = lambda: answers.pop(0) if answers else None
        mod.PASSCODE_BACKOFF_S = 60
        self.assertRegex(mod.passcode_summary(), r"set \(read, write\), 1/5 failed, next try in \d+s")


class TestRound2Gate(Base):
    """Security review round 2: the verify near the deadline, kill/finish races, OSErrors."""

    def short(self):
        mod = self.module()
        mod.TOUCHID_WINDOW_S = 3   # created_at is whole seconds: the real window is 2-3 s
        mod.PASSCODE_WINDOW_S = 3
        return mod

    def test_passcode_typed_at_the_deadline_is_verified(self):
        # item 1: the dialog answers at ~1.2 s of a 2-3 s window, the verify takes 2.5 s more
        self.sb.write_config(dict(self.sb.config, approvers=["passcode"]))
        self.sb.set_dialog([PASSCODE], delay=1.0)
        self.sb.set_age(passcode={"mode": "ok", "delay": 2.5})
        r = self.handle(READ_REQ, self.short())
        self.assertTrue(r["ok"], r)
        self.assertGreater(self.elapsed, 3.2, "the verify did not outlive the deadline")
        self.assertIn("approver=passcode", self.last_log())
        self.assertEqual(self.sb.pc_state()["failures"], 0)
        self.assertNotIn("result=abandoned", "\n".join(self.sb.log_lines()))

    def test_late_verify_with_touchid_held_still_approves(self):
        self.sb.hold_touchid()
        self.sb.set_dialog([PASSCODE], delay=1.0)
        self.sb.set_age(touchid={"mode": "ok", "until": self.sb.touchid_go}, passcode={"mode": "ok", "delay": 2.5})
        r = self.handle(READ_REQ, self.short())
        self.assertTrue(r["ok"], r)
        self.assertIn("approver=passcode", self.last_log())
        self.assertEqual(self.sb.touchid_procs_alive(), [], "Touch ID left running past the deadline")

    def test_late_wrong_passcode_times_out_and_counts(self):
        self.sb.write_config(dict(self.sb.config, approvers=["passcode"]))
        self.sb.set_dialog([WRONG % 1, PASSCODE], delay=1.0)
        self.sb.set_age(passcode={"mode": "ok", "delay": 2.5})
        r = self.handle(READ_REQ, self.short())
        self.assertFalse(r["ok"])
        self.assertIn("no approval within", r["error"])
        self.assertEqual(len(self.sb.dialog_runs()), 1, "re-prompted past the deadline")
        self.assertEqual(self.sb.pc_state()["failures"], 1)
        self.assertRegex("\n".join(self.sb.log_lines()), r"op=passcode result=wrong token=read detail=failures=1/5")

    def verify_leg(self, mod, script):
        """A PasscodeLeg in its verify phase, its 'age' a shell script; attempt 2 already counted."""
        self.sb.write_pc_state(failures=2, last_failure=1)
        notes = []
        leg = mod.PasscodeLeg(mod.load_config(), "read", time.time() + 10, "p", notes)
        leg.live, leg.phase, leg.failures, leg.verify_by = True, "verify", 2, time.time() + 10
        leg.proc = subprocess.Popen(["/bin/sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True)
        return leg, notes

    def payload_script(self, mod, sleep):
        payload = mod.seal_passcode_payload(FAKE_PASSCODE_TOKENS["read"], "read")
        return "sleep %s; printf '%%s' '%s'" % (sleep, payload.replace("'", "'\\''"))

    def test_cancel_racing_a_finished_verify_settles_success(self):
        # item 3: the verify exits 0 while kill_group is sending its signal
        mod = self.module()
        leg, notes = self.verify_leg(mod, self.payload_script(mod, 0.3))
        real_kill = mod.kill_group
        mod.kill_group = lambda proc: (proc.wait(5), real_kill(proc))
        leg.cancel("touchid_approved")
        self.assertEqual(self.sb.pc_state()["failures"], 0, "a right passcode resets the counter")
        self.assertNotIn("result=abandoned", "\n".join(self.sb.log_lines()))
        self.assertEqual(leg.token(), (None, "no passcode token"), "the token is discarded")
        self.assertFalse(leg.live)

    def test_cancel_kills_a_running_verify_as_abandoned(self):
        mod = self.module()
        leg, notes = self.verify_leg(mod, "sleep 30")
        leg.cancel("touchid_approved")
        self.assertEqual(self.sb.pc_state()["failures"], 2)
        self.assertIn("passcode-abandoned:2", notes)
        self.assertIsNotNone(leg.proc.returncode)

    def test_verify_timeout_racing_a_finish_uses_the_result(self):
        mod = self.module()
        leg, notes = self.verify_leg(mod, self.payload_script(mod, 0.3))
        leg.verify_by = 0
        real_kill = mod.kill_group
        mod.kill_group = lambda proc: (proc.wait(5), real_kill(proc))
        d = leg.poll(time.time())
        self.assertEqual(d, {"kind": "approve", "approver": "passcode", "why": ""})
        self.assertEqual(leg.token()[0], FAKE_PASSCODE_TOKENS["read"])
        self.assertEqual(self.sb.pc_state()["failures"], 0)


    def test_dialog_that_cannot_exec_keeps_touchid(self):
        # item 4: Popen raising OSError must end the passcode leg, not the whole gate
        bad = os.path.join(self.sb.bin, "bad-osascript")
        self.sb._write(bad, "#!/nonexistent/interpreter\n", 0o755)
        self.sb.write_config(dict(self.sb.config, osascript_path=bad))
        self.sb.set_age(touchid={"mode": "ok", "delay": 1.0})
        r = self.handle(READ_REQ)
        self.assertTrue(r["ok"], r)
        self.assertIn("approver=touchid", self.last_log())
        self.assertIn("passcode-unavailable:error", self.last_log())
        self.assertEqual(self.sb.pc_state()["failures"], 0, "no attempt was made")

    def test_pipe_failure_is_counted_and_keeps_touchid(self):
        mod = self.module()

        def no_fds(secret):
            raise OSError(24, "Too many open files")
        mod.passcode_pipe = no_fds
        self.sb.set_age(touchid={"mode": "ok", "delay": 1.5})
        r = self.handle(READ_REQ, mod)
        self.assertTrue(r["ok"], r)
        self.assertIn("approver=touchid", self.last_log())
        self.assertIn("passcode-error:1", self.last_log())
        self.assertIn("passcode-unavailable:error", self.last_log())
        self.assertEqual(self.sb.pc_state()["failures"], 1, "the attempt was counted before the pipe")
        self.assertIn("op=passcode result=error token=read detail=failures=1/5 via=dialog",
                      "\n".join(self.sb.log_lines()))

class TestCliReviewFixes(Base):
    def setUp(self):
        Base.setUp(self)
        for f in os.listdir(self.sb.tokens):
            if ".passcode." in f:
                os.remove(os.path.join(self.sb.tokens, f))

    def tmutil_runs(self):
        return self.sb.jsonl("tmutil.log")

    def test_set_excludes_copies_from_time_machine(self):
        # finding 3
        code, out = run_pty(self.sb, ["passcode", "set"], [PASSCODE, PASSCODE])
        self.assertEqual(code, 0, out)
        runs = self.tmutil_runs()
        self.assertEqual(sorted(r["argv"][1] for r in runs),
                         sorted(os.path.join(self.sb.tokens, n + ".passcode.age") for n in ("read", "write")))
        self.assertTrue(all(r["argv"][0] == "addexclusion" for r in runs))
        new = "An0ther-Passc0de!"
        code, out = run_pty(self.sb, ["passcode", "change"], [new, new])
        self.assertEqual(code, 0, out)
        self.assertEqual(len(self.tmutil_runs()), 4, "change re-excludes the new files")

    def test_tmutil_failure_only_warns(self):
        self.sb._write(os.path.join(self.sb.state, "tmutil.json"), json.dumps({"mode": "error"}))
        code, out = run_pty(self.sb, ["passcode", "set"], [PASSCODE, PASSCODE])
        self.assertEqual(code, 0, out)
        self.assertIn("warning: could not exclude", out)
        self.assertTrue(os.path.exists(os.path.join(self.sb.tokens, "read.passcode.age")))

    def test_no_tmutil_is_a_no_op(self):
        self.sb.write_config(dict(self.sb.config, tmutil_path=os.path.join(self.sb.root, "no-such-tmutil")))
        code, out = run_pty(self.sb, ["passcode", "set"], [PASSCODE, PASSCODE])
        self.assertEqual(code, 0, out)
        self.assertNotIn("warning", out)

    def test_store_during_set_aborts_and_removes_new_copies(self):
        # finding 6: `store read` replaces tokens/read.age after set decrypted it with Touch ID
        def store_now(i):
            if i == 0:
                p = os.path.join(self.sb.tokens, "read.age")
                with open(p) as f:
                    head = f.read().split("\n")[:2]
                self.sb._write(p + ".tmp", "\n".join(head + ["0.00000000-0000-0000-0000-000000000009.new:ZmFrZQ=="]))
                os.replace(p + ".tmp", p)
        code, out = run_pty(self.sb, ["passcode", "set"], [PASSCODE, PASSCODE], on_prompt=store_now)
        self.assertEqual(code, 1, out)
        self.assertIn("token 'read' changed", out)
        self.assertFalse([f for f in os.listdir(self.sb.tokens) if ".passcode." in f])
        self.assertIn("op=passcode-set result=rejected token=read detail=token changed", "\n".join(self.sb.log_lines()))

    def test_store_during_change_keeps_the_old_copies(self):
        code, out = run_pty(self.sb, ["passcode", "set"], [PASSCODE, PASSCODE])
        self.assertEqual(code, 0, out)

        def touch(i):
            if i == 1:
                p = os.path.join(self.sb.tokens, "write.age")
                os.utime(p, ns=(time.time_ns() + 5 * 10**9,) * 2)
        new = "An0ther-Passc0de!"
        code, out = run_pty(self.sb, ["passcode", "change"], [new, new], on_prompt=touch)
        self.assertEqual(code, 1, out)
        self.assertEqual(self.decrypt_copy("read", PASSCODE).returncode, 0, "old copy replaced")
        self.assertFalse([f for f in os.listdir(self.sb.tokens) if f.endswith(".tmp")])


class TestFakeAgeNewlines(unittest.TestCase):
    """finding 8: fake batchpass strips trailing CR/LF the way the real age 1.3.2 plugin does (verified
    on dummy data: "pw", "pw\n", "pw\n\n", "pw\r\n", "pw\r" all open a file sealed with "pw"; "pw " does
    not; an inner "\n" is kept)."""

    def check(self, age, plugin):
        root = Sandbox(iphone=False)
        try:
            out = os.path.join(root.root, "x.age")

            def run(args, pw, inp=None):
                r, w = os.pipe()
                os.write(w, pw)
                os.close(w)
                env = dict(root.env(AGE_PASSPHRASE_FD=str(r), AGE_PASSPHRASE_WORK_FACTOR="10"))
                env["PATH"] = os.path.dirname(plugin) + ":" + env["PATH"]
                p = subprocess.run([age] + args, input=inp, env=env, pass_fds=(r,), capture_output=True)
                os.close(r)
                return p.returncode
            self.assertEqual(run(["-e", "-j", "batchpass", "-o", out], b"pass\nword\n", b"dummy"), 0)
            for pw, ok in ((b"pass\nword", True), (b"pass\nword\n\n", True), (b"pass\nword\r\n", True),
                           (b"pass\nword\r", True), (b"pass\nword ", False), (b"password", False), (b"pass", False)):
                self.assertEqual(run(["-d", "-j", "batchpass", out], pw) == 0, ok, pw)
        finally:
            root.cleanup()

    def test_fake(self):
        sb = Sandbox(iphone=False)
        try:
            self.check(os.path.join(sb.bin, "age"), os.path.join(sb.bin, "age-plugin-batchpass"))
        finally:
            sb.cleanup()


REAL_AGE = next((p for p in ("/opt/homebrew/bin/age", "/usr/local/bin/age") if os.path.exists(p)), "")
REAL_PLUGIN = next((p for p in ("/opt/homebrew/bin/age-plugin-batchpass", "/usr/local/bin/age-plugin-batchpass")
                    if os.path.exists(p)), "")


@unittest.skipUnless(REAL_AGE and REAL_PLUGIN, "real age >= 1.3 with age-plugin-batchpass not installed")
class TestRealAge(unittest.TestCase):
    """The argv / env / fd protocol against the real age binary (fake token, throwaway temp dir)."""

    def test_seal_and_open_with_real_age(self):
        sb = Sandbox(iphone=False)
        try:
            sb.write_config(dict(sb.config, age_path=REAL_AGE, age_plugin_batchpass_path=REAL_PLUGIN))
            mod = sb.module()
            mod.PASSCODE_WORK_FACTOR = 10          # fast; the shipped value is 18
            c = mod.load_config()
            self.assertEqual(mod.seal_passcode_copy(c, bytearray(PASSCODE.encode()), FAKE_TOKENS["read"], "read"), "")
            path = mod.passcode_token_path("read")
            os.replace(path + ".tmp", path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with open(path, "rb") as f:
                data = f.read()
            self.assertTrue(re.match(rb"age-encryption\.org/v1\n-> scrypt \S{22} 10\n", data[:80]), data[:80])
            self.assertNotIn(FAKE_TOKENS["read"].encode(), data)
            self.assertEqual(mod.open_passcode_copy(c, "read", bytearray(PASSCODE.encode())),
                             (FAKE_TOKENS["read"], "ok", ""))
            self.assertEqual(mod.open_passcode_copy(c, "read", bytearray(b"not-the-passcode"))[:2], (None, "wrong"))
        finally:
            sb.cleanup()

    def test_real_newline_handling_matches_the_fake(self):
        TestFakeAgeNewlines("check").check(REAL_AGE, REAL_PLUGIN)


if __name__ == "__main__":
    unittest.main()
