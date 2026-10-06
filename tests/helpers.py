"""Sandbox for the broker tests: temp HOME, fake age / age-plugin-se / bws on PATH, fake tokens.

Nothing here touches the real ~/.config/bws-touchid, ~/.bws-broker, the Secure Enclave or Bitwarden.
"""
import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
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
IPHONE_MAGIC = "bws-touchid-iphone-v2\n"   # plaintext header of a sealed iPhone copy (see the script)


def pem_fp(pem):
    """sha256 hex of the SPKI DER inside a public key PEM (the broker's fingerprint())."""
    body = "".join(l for l in pem.strip().splitlines() if not l.startswith("-----"))
    return hashlib.sha256(base64.b64decode(body)).hexdigest()


def iphone_payload(token, fps):
    return IPHONE_MAGIC + json.dumps({"token": token, "approvers": sorted(set(fps))}, sort_keys=True)


def open_iphone_payload(text):
    """(token, fps) of a decrypted sealed copy."""
    assert text.startswith(IPHONE_MAGIC), text[:40]
    obj = json.loads(text[len(IPHONE_MAGIC):])
    return obj["token"], obj["approvers"]

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
        self.bound = set()     # approve-key fingerprints sealed into the iPhone copies
        self.ph_id = "AGE-PLUGIN-SE-FAKE-none-0002"
        if iphone:
            self._write(os.path.join(self.conf, "identity-iphone.txt"), self.ph_id + "\n")
            self._write(os.path.join(self.conf, "recipient-iphone.txt"), self.ph_id + "\n")
            self.write_iphone_copies()
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

    def write_iphone_copies(self, legacy=False):
        """(Re)write tokens/<name>.iphone.age sealing FAKE_IPHONE_TOKENS with self.bound; legacy = the
        pre-binding format that holds the bare token."""
        for name, tok in FAKE_IPHONE_TOKENS.items():
            payload = tok if legacy else iphone_payload(tok, self.bound)
            self._write(os.path.join(self.tokens, name + ".iphone.age"), "FAKEAGE\n%s\n%s" % (self.ph_id, payload))

    # --- ordering helpers: make the Touch ID / phone race deterministic instead of timing it
    def touchid_started(self):
        """The fake Touch ID age process is running (it logged itself)."""
        return bool(self.age_runs("touchid"))

    def touchid_finished(self, settle=1.0):
        """The fake Touch ID process exited at least `settle` s ago, so the broker (which polls its legs
        every 0.1 s) has seen the result before the phone answers."""
        runs = self.age_runs("touchid")
        if not runs or pid_alive(runs[-1]["pid"]):
            return False
        self._finished_at = getattr(self, "_finished_at", None) or time.time()
        return time.time() - self._finished_at >= settle

    @property
    def touchid_go(self):
        return os.path.join(self.state, "touchid.go")

    def hold_touchid(self, mode="ok"):
        """Fake Touch ID that answers `mode` only after release_touchid()."""
        self.set_age(touchid={"mode": mode, "until": self.touchid_go})

    def release_touchid(self):
        open(self.touchid_go, "w").close()

    def touchid_procs_alive(self):
        """pids of this sandbox's fake age processes that are still running (not zombies)."""
        r = subprocess.run(["/bin/ps", "-ax", "-o", "pid=,stat=,command="], capture_output=True, text=True)
        me = os.path.join(self.bin, "age") + " "
        return [l.split()[0] for l in r.stdout.splitlines() if me in l and not l.split()[1].startswith("Z")]

    def pin(self, phone, mode=0o600, bind=True):
        """Pin an approve key the way `approver add` does: pin file + binding in the sealed iPhone copies.
        bind=False only drops the pin file (what a same-user process can do without the token)."""
        os.makedirs(self.approvers_dir, exist_ok=True)
        os.chmod(self.approvers_dir, 0o700)
        p = os.path.join(self.approvers_dir, phone.device_id + ".pub")
        self._write(p, phone.pem(), mode)
        if bind and os.path.exists(os.path.join(self.tokens, "read.iphone.age")):
            self.bound.add(pem_fp(phone.pem()))
            self.write_iphone_copies()
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
