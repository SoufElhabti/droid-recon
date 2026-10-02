#!/usr/bin/env python3
"""On-device HTTP agent for droid-recon.

Pushed to the Android device and executed as root. Replaces per-command `adb shell`
overhead with a persistent HTTP server that runs commands locally.

Stdlib-only — no pip, no venv, just whatever Python is on the device.
Binds 127.0.0.1 only: reachable from the host via `adb forward`, never from the network.

Auth: every request carries X-Auth-Token = HMAC-SHA256(secret, timestamp:method:path:body)
and X-Timestamp. The server rejects replays older than 120s.
"""

import hashlib
import hmac
import json
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "0.1.0"
MAX_BODY = 4 * 1024 * 1024  # 4 MB request body limit
CLOCK_SKEW = 120  # seconds


class AgentHTTPServer(HTTPServer):
    auth_secret: str


def _run(argv, timeout=60):
    try:
        cp = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "rc": cp.returncode,
            "stdout": cp.stdout.decode("utf-8", "replace"),
            "stderr": cp.stderr.decode("utf-8", "replace"),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode("utf-8", "replace")
        err = (exc.stderr or b"").decode("utf-8", "replace")
        return {"rc": 124, "stdout": out, "stderr": err, "timed_out": True}
    except Exception as exc:
        return {"rc": 127, "stdout": "", "stderr": str(exc), "timed_out": False}


def _run_script(script, timeout=60):
    try:
        cp = subprocess.run(
            ["sh", "-c", script],
            capture_output=True,
            timeout=timeout,
        )
        return {
            "rc": cp.returncode,
            "stdout": cp.stdout.decode("utf-8", "replace"),
            "stderr": cp.stderr.decode("utf-8", "replace"),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode("utf-8", "replace")
        err = (exc.stderr or b"").decode("utf-8", "replace")
        return {"rc": 124, "stdout": out, "stderr": err, "timed_out": True}
    except Exception as exc:
        return {"rc": 127, "stdout": "", "stderr": str(exc), "timed_out": False}


class AgentHandler(BaseHTTPRequestHandler):
    server_version = f"droid-recon-agent/{VERSION}"
    server: AgentHTTPServer

    def log_message(self, fmt, *args):
        pass  # silent — logs go to stderr which adb captures

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY:
            return None
        return self.rfile.read(length) if length else b""

    def _check_auth(self, body=b""):
        secret = self.server.auth_secret
        if not secret:
            return True
        token = self.headers.get("X-Auth-Token", "")
        ts = self.headers.get("X-Timestamp", "")
        if not token or not ts:
            return False
        try:
            if abs(time.time() - float(ts)) > CLOCK_SKEW:
                return False
        except ValueError:
            return False
        msg = f"{ts}:{self.command}:{self.path}:{body.decode('utf-8', 'replace')}"
        expected = hmac.new(
            secret.encode(), msg.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(token, expected)

    def _json_response(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, msg):
        self._json_response({"error": msg}, status)

    def do_GET(self):
        if not self._check_auth():
            return self._error(401, "unauthorized")
        if self.path == "/health":
            self._json_response({
                "ok": True,
                "version": VERSION,
                "uid": os.getuid(),
                "pid": os.getpid(),
                "whoami": _run(["whoami"], 5).get("stdout", "").strip(),
            })
        else:
            self._error(404, "not found")

    def do_POST(self):
        body = self._read_body()
        if body is None:
            return self._error(413, "body too large")
        if not self._check_auth(body):
            return self._error(401, "unauthorized")

        try:
            req = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return self._error(400, "invalid json")

        if self.path == "/exec":
            argv = req.get("argv")
            if not argv or not isinstance(argv, list):
                return self._error(400, "argv required")
            timeout = min(req.get("timeout", 60), 300)
            result = _run(argv, timeout)
            self._json_response(result)

        elif self.path == "/exec/script":
            script = req.get("script", "")
            if not script:
                return self._error(400, "script required")
            timeout = min(req.get("timeout", 60), 300)
            result = _run_script(script, timeout)
            self._json_response(result)

        elif self.path == "/fs/read":
            path = req.get("path", "")
            if not path:
                return self._error(400, "path required")
            try:
                with open(path, "rb") as f:
                    data = f.read(16 * 1024 * 1024)  # 16 MB cap
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except FileNotFoundError:
                self._error(404, f"file not found: {path}")
            except PermissionError:
                self._error(403, f"permission denied: {path}")
            except Exception as exc:
                self._error(500, str(exc))

        elif self.path == "/fs/stat":
            path = req.get("path", "")
            if not path:
                return self._error(400, "path required")
            try:
                st = os.stat(path)
                import stat
                self._json_response({
                    "exists": True,
                    "size": st.st_size,
                    "is_dir": stat.S_ISDIR(st.st_mode),
                    "mode": oct(st.st_mode),
                })
            except FileNotFoundError:
                self._json_response({"exists": False})
            except Exception as exc:
                self._error(500, str(exc))

        else:
            self._error(404, "not found")


def main():
    import argparse
    p = argparse.ArgumentParser(description="droid-recon device agent")
    p.add_argument("--port", type=int, default=18080)
    p.add_argument("--secret", default="")
    args = p.parse_args()

    server = AgentHTTPServer(("127.0.0.1", args.port), AgentHandler)
    server.auth_secret = args.secret
    print(f"[agent] listening on 127.0.0.1:{args.port} (pid={os.getpid()})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
