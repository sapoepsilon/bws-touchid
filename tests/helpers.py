"""Sandbox for the broker tests: temp HOME, fake age / age-plugin-se / bws on PATH, fake tokens.

Nothing here touches the real ~/.config/bws-touchid, ~/.bws-broker, the Secure Enclave or Bitwarden.
"""
import importlib.machinery
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "bws-touchid")
FAKES = os.path.join(REPO, "tests", "fakes")

AGENTS_ID = "11111111-1111-1111-1111-111111111111"
MAIL_ID = "22222222-2222-2222-2222-222222222222"
# Fake, clearly-not-real token strings (shape only).
FAKE_TOKENS = {"read": "0.00000000-0000-0000-0000-000000000001.fakeread:ZmFrZQ==",
               "write": "0.00000000-0000-0000-0000-000000000002.fakewrite:ZmFrZQ=="}
# The iPhone copies get a distinguishable value in tests so we can prove which file was decrypted.
FAKE_IPHONE_TOKENS = {k: v.replace("fake", "fakeiphone") for k, v in FAKE_TOKENS.items()}

_count = [0]


def read_text(path):
    with open(path) as f:
        return f.read()


def write_text(path, data):
    with open(path, "w") as f:
        f.write(data)


def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)


VECTORS = json.loads(read_text(os.path.join(FAKES, "vectors_v1.json")))


def load_module(path, home):
    """Import the single-file script fresh with HOME pointing at the sandbox."""
    old = dict(os.environ)
    os.environ["HOME"] = home
    os.environ.pop("BWS_TOUCHID_HOME", None)
    try:
        _count[0] += 1
        name = "bws_touchid_under_test_%d" % _count[0]
        loader = importlib.machinery.SourceFileLoader(name, path)
        spec = importlib.util.spec_from_loader(name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod
    finally:
        os.environ.clear()
        os.environ.update(old)


class Sandbox(object):
    def __init__(self, approvers=None, iphone=True, extra_config=None):
        self.root = tempfile.mkdtemp(prefix="bt")
        self.home = os.path.join(self.root, "h")
        self.bin = os.path.join(self.root, "bin")
        self.state = os.path.join(self.root, "state")
        for d in (self.home, self.bin, self.state):
            os.makedirs(d)
        for src, dst in (("fake_age.py", "age"), ("fake_bws.py", "bws"), ("fake_age_plugin_se.py", "age-plugin-se")):
            p = os.path.join(self.bin, dst)
            shutil.copy(os.path.join(FAKES, src), p)
            os.chmod(p, 0o755)
        os.symlink(SCRIPT, os.path.join(self.bin, "bws-touchid"))
        os.symlink(SCRIPT, os.path.join(self.bin, "bws-save"))
        os.symlink(SCRIPT, os.path.join(self.bin, "bws-gated"))
        self.conf = os.path.join(self.home, ".config", "bws-touchid")
        self.tokens = os.path.join(self.conf, "tokens")
        os.makedirs(self.tokens, mode=0o700)
        self.sock = os.path.join(self.root, "wl.sock")
        self.approvers_dir = os.path.join(self.home, ".bws-broker", "approvers")
        touch_id = "AGE-PLUGIN-SE-FAKE-any-biometry-0001"
        self._write(os.path.join(self.conf, "identity.txt"), touch_id + "\n")
        self._write(os.path.join(self.conf, "recipient.txt"), touch_id + "\n")
        for name, tok in FAKE_TOKENS.items():
            self._write(os.path.join(self.tokens, name + ".age"), "FAKEAGE\n%s\n%s" % (touch_id, tok))
        if iphone:
            ph_id = "AGE-PLUGIN-SE-FAKE-none-0002"
            self._write(os.path.join(self.conf, "identity-iphone.txt"), ph_id + "\n")
            self._write(os.path.join(self.conf, "recipient-iphone.txt"), ph_id + "\n")
            for name, tok in FAKE_IPHONE_TOKENS.items():
                self._write(os.path.join(self.tokens, name + ".iphone.age"), "FAKEAGE\n%s\n%s" % (ph_id, tok))
        cfg = {"broker_name": "Test Broker", "save_projects": ["agents"],
               "project_names": {AGENTS_ID: "agents", MAIL_ID: "mail"},
               "denied_projects": ["mail"], "denied_key_prefixes": ["MAIL_"],
               "age_path": os.path.join(self.bin, "age"), "bws_path": os.path.join(self.bin, "bws"),
               "age_plugin_se_path": os.path.join(self.bin, "age-plugin-se"),
               "notify": False, "approvals_socket": self.sock}
        if approvers is not None:
            cfg["approvers"] = approvers
        cfg.update(extra_config or {})
        self.write_config(cfg)
        self.set_age()

    @staticmethod
    def _write(path, data, mode=0o600):
        with open(path, "w") as f:
            f.write(data)
        os.chmod(path, mode)

    def write_config(self, cfg):
        self.config = cfg
        self._write(os.path.join(self.conf, "config.json"), json.dumps(cfg))

    def set_age(self, touchid=None, iphone=None):
        self._write(os.path.join(self.state, "age.json"),
                    json.dumps({"touchid": touchid or {"mode": "ok", "delay": 0.1}, "iphone": iphone or {"mode": "ok"}}))

    def pin(self, phone, mode=0o600):
        os.makedirs(self.approvers_dir, exist_ok=True)
        os.chmod(self.approvers_dir, 0o700)
        p = os.path.join(self.approvers_dir, phone.device_id + ".pub")
        self._write(p, phone.pem(), mode)
        return p

    def module(self, path=SCRIPT):
        mod = load_module(path, self.home)
        self.notified = []
        mod.notify = lambda title, msg, c: self.notified.append((title, msg))
        return mod

    def jsonl(self, name):
        p = os.path.join(self.state, name)
        return [json.loads(x) for x in read_text(p).splitlines()] if os.path.exists(p) else []

    def age_runs(self, leg=None):
        return [r for r in self.jsonl("age.log") if leg is None or r["leg"] == leg]

    def bws_runs(self):
        return self.jsonl("bws.log")

    def log_lines(self):
        p = os.path.join(self.home, "Library", "Logs", "bws-touchid.log")
        return read_text(p).splitlines() if os.path.exists(p) else []

    def env(self, **extra):
        e = {"HOME": self.home, "PATH": self.bin + ":/usr/bin:/bin", "LANG": "en_US.UTF-8"}
        e.update(extra)
        return e

    def cli(self, prog, *args, **kw):
        return subprocess.run(["/usr/bin/python3", os.path.join(self.bin, prog)] + list(args),
                              env=self.env(**kw.pop("env", {})), capture_output=True, text=True,
                              timeout=kw.pop("timeout", 60), **kw)

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # a zombie still answers kill(0); ps says Z
    r = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return bool(r.stdout.strip()) and not r.stdout.strip().startswith("Z")
