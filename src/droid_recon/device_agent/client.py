"""Host-side client for the on-device HTTP agent.

Returns `shell.Proc` for drop-in compatibility with `shell.adb_shell()` call sites.
Uses only stdlib `urllib` — no requests dependency.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request

from .. import shell
from ..transport import DeviceAgentConfig


class DeviceAgentClient:
    """Talks to the on-device droid-recon agent over HTTP."""

    def __init__(self, config: DeviceAgentConfig):
        self.config = config
        self._base = config.base_url

    def _auth_headers(self, method: str, path: str, body: str = "") -> dict[str, str]:
        if not self.config.secret:
            return {}
        ts = str(int(time.time()))
        msg = f"{ts}:{method}:{path}:{body}"
        token = hmac.new(
            self.config.secret.encode(), msg.encode(), hashlib.sha256
        ).hexdigest()
        return {"X-Auth-Token": token, "X-Timestamp": ts}

    def _post_json(self, path: str, data: dict, timeout: int = 60) -> dict:
        body = json.dumps(data)
        headers = {"Content-Type": "application/json"}
        headers.update(self._auth_headers("POST", path, body))
        req = urllib.request.Request(
            f"{self._base}{path}",
            data=body.encode(),
            headers=headers,
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=timeout + 5)
        return json.loads(resp.read())

    def _get_json(self, path: str, timeout: int = 10) -> dict:
        headers = self._auth_headers("GET", path)
        req = urllib.request.Request(f"{self._base}{path}", headers=headers)
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read())

    def health(self) -> dict:
        return self._get_json("/health")

    def is_alive(self) -> bool:
        try:
            h = self.health()
            return h.get("ok", False)
        except Exception:
            return False

    def exec(self, argv: list[str], timeout: int = 60) -> shell.Proc:
        """Run a command on the device. Drop-in for `shell.adb_shell()`."""
        try:
            result = self._post_json("/exec", {"argv": argv, "timeout": timeout}, timeout)
            return shell.Proc(
                argv=argv,
                rc=result.get("rc", 1),
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                timed_out=result.get("timed_out", False),
            )
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            return shell.Proc(argv=argv, rc=1, stdout="", stderr=f"agent error: {exc}")

    def exec_script(self, script: str, timeout: int = 60) -> shell.Proc:
        """Run a shell script on the device. Drop-in for `shell.adb_script()`."""
        try:
            result = self._post_json(
                "/exec/script", {"script": script, "timeout": timeout}, timeout
            )
            return shell.Proc(
                argv=["sh", "-c", script[:80]],
                rc=result.get("rc", 1),
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                timed_out=result.get("timed_out", False),
            )
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            return shell.Proc(
                argv=["sh", "-c", script[:80]], rc=1, stdout="",
                stderr=f"agent error: {exc}",
            )

    def read_file(self, remote_path: str, timeout: int = 60) -> bytes | None:
        """Read a file from the device. Returns bytes, or None on failure."""
        body = json.dumps({"path": remote_path})
        headers = {"Content-Type": "application/json"}
        headers.update(self._auth_headers("POST", "/fs/read", body))
        req = urllib.request.Request(
            f"{self._base}/fs/read",
            data=body.encode(),
            headers=headers,
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.read()
        except Exception:
            return None

    def stat(self, remote_path: str) -> dict:
        """Stat a file on the device."""
        try:
            return self._post_json("/fs/stat", {"path": remote_path}, timeout=10)
        except Exception:
            return {"exists": False}
