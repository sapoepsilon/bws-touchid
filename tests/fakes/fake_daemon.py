"""Fake whispera-link approvals.sock (PROTOCOL.md §8) for the broker tests, plus a software "phone".

SoftPhone is a throwaway P-256 key made with /usr/bin/openssl for one test run; it stands in for the
iPhone Secure Enclave approve key. Nothing here is a real key.
"""
import base64
import json
import os
import select
import shutil
import socket
import subprocess
import tempfile
import threading
import time

OPENSSL = "/usr/bin/openssl"


def read_text(path):
    with open(path) as f:
        return f.read()


class SoftPhone(object):
    def __init__(self, workdir):
        self.dir = tempfile.mkdtemp(prefix="phone-", dir=workdir)
        self.key = os.path.join(self.dir, "approve-key.pem")
        self.pub = os.path.join(self.dir, "approve-pub.pem")
        subprocess.run([OPENSSL, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", self.key],
                       check=True, capture_output=True)
        subprocess.run([OPENSSL, "ec", "-in", self.key, "-pubout", "-out", self.pub], check=True, capture_output=True)
        self.device_id = "dev_" + base64.b32encode(os.urandom(15)).decode().lower()

    def sign(self, message):
        r = subprocess.run([OPENSSL, "dgst", "-sha256", "-sign", self.key], input=message,
                           capture_output=True, check=True)
        return base64.b64encode(r.stdout).decode()

    def pem(self):
        return read_text(self.pub)


class FakeDaemon(threading.Thread):
    """Serves approval connections on `path` with one scripted behaviour.

    ack:      "ok" | "none" (never ack) | "error" (approval.error) | "zero" (devices 0) | "eof"
    decision: "approve" | "approve_bad" (signs other bytes) | "approve_wrong_device" | "deny" | "silent"
              | "eof" | "garbage"
    delay:    seconds between ack and decision
    """

    def __init__(self, path, phone, ack="ok", decision="approve", delay=0.6):
        super(FakeDaemon, self).__init__(daemon=True)
        self.path, self.phone, self.ack, self.decision, self.delay = path, phone, ack, decision, delay
        self.connections = 0
        self.requests = []      # parsed approval.request objects
        self.received = []      # every later line from the broker (approval.result / approval.cancel)
        self.eof_seen = threading.Event()
        self._halt = False
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        os.chmod(path, 0o600)
        self.srv.listen(4)
        self.srv.settimeout(0.2)

    def stop(self):
        self._halt = True
        self.join(5)
        self.srv.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def run(self):
        while not self._halt:
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.connections += 1
            try:
                self._serve(conn)
            finally:
                conn.close()

    def _lines(self, conn, buf, until, until_eof=False):
        """Read lines until the first line(s) arrive (or, with until_eof, until EOF), `until` (monotonic)
        or EOF; returns (lines, buf, eof)."""
        out = []
        while time.monotonic() < until and (until_eof or not out):
            r, _, _ = select.select([conn], [], [], max(0.0, min(0.05, until - time.monotonic())))
            if not r:
                continue
            chunk = conn.recv(65536)
            if not chunk:
                return out, buf, True
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                out.append(json.loads(line))
        return out, buf, False

    def _send(self, conn, obj):
        try:
            conn.sendall(json.dumps(obj).encode() + b"\n")
        except OSError:
            pass

    def _serve(self, conn):
        lines, buf, eof = self._lines(conn, b"", time.monotonic() + 5)
        while not lines and not eof:
            more, buf, eof = self._lines(conn, buf, time.monotonic() + 5)
            lines += more
        if not lines:
            return
        req = lines[0]
        self.requests.append(req)
        rid = req.get("request_id")
        if self.ack == "none":
            more, buf, eof = self._lines(conn, buf, time.monotonic() + 30, True)
            self.received += more
            self.eof_seen.set()
            return
        if self.ack == "eof":
            return
        if self.ack == "error":
            self._send(conn, {"op": "approval.error", "request_id": rid, "code": "malformed"})
            return
        self._send(conn, {"op": "approval.ack", "request_id": rid, "devices": 0 if self.ack == "zero" else 1,
                          "push": "unconfigured"})
        more, buf, eof = self._lines(conn, buf, time.monotonic() + self.delay)
        self.received += more
        if eof or more:  # the broker cancelled or went away before we decided
            if not eof:
                more, buf, eof = self._lines(conn, buf, time.monotonic() + 5, True)
                self.received += more
            self.eof_seen.set()
            return
        canonical = base64.b64decode(req["canonical_b64"])
        dev = self.phone.device_id
        if self.decision == "eof":
            self.eof_seen.set()
            return
        if self.decision == "garbage":
            conn.sendall(b"this is not json\n")
        elif self.decision == "deny":
            self._send(conn, {"op": "approval.decision", "request_id": rid, "decision": "deny",
                              "device_id": dev, "decided_at": int(time.time())})
        elif self.decision.startswith("approve"):
            msg = b"WL1-APPROVE\n" + canonical
            if self.decision == "approve_bad":
                msg = b"WL1-APPROVE\n" + canonical.replace(b'"token":"', b'"token":"x')
            if self.decision == "approve_wrong_device":
                dev = "dev_" + "a" * 24
            self._send(conn, {"op": "approval.decision", "request_id": rid, "decision": "approve",
                              "device_id": dev, "signature": self.phone.sign(msg), "decided_at": int(time.time())})
        more, buf, eof = self._lines(conn, buf, time.monotonic() + 10, True)
        self.received += more
        self.eof_seen.set()
