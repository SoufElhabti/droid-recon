"""TLS-intercepting proxy: mitmdump lifecycle, capture, and traffic analysis.

Three things have to line up for an app's HTTPS to be readable:

  1. Traffic reaches the proxy       -> emulator `-http-proxy`, or `settings put global
                                        http_proxy`, or per-app iptables.
  2. The app trusts the proxy CA     -> `certs.install_system_ca` (APEX overlay).
  3. The app is not certificate-pinned -> Frida `ssl_unpin.js`.

Each is independently checkable, and the capture reports which one failed rather than
silently returning an empty flow list. `handshake_failures` in the summary is the tell:
non-zero means (2) or (3) is unresolved, not that the app made no requests.
"""

from __future__ import annotations

import json
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .. import __version__, shell
from ..log import ok, say, warn

DEFAULT_PORT = 8080
MITM_HOME = Path.home() / ".mitmproxy"
CA_PEM = MITM_HOME / "mitmproxy-ca-cert.pem"

# Credential-shaped material in requests/responses.
_SECRET_IN_TRAFFIC = re.compile(
    r"(?i)\b(password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|session[_-]?id|authorization)\b"
)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")
# Values that look like a user/object identifier — IDOR candidates.
_ID_PARAM = re.compile(r"(?i)\b(\w*(?:user|account|customer|order|profile|doc|file|id))"
                       r"=(\d{2,}|[0-9a-f]{8,}-[0-9a-f-]+)")


def mitmdump_bin() -> str | None:
    return shell.which("mitmdump")


def ensure_ca() -> Path | None:
    """Return the mitmproxy CA, generating it if this is the first run.

    Done through mitmproxy's own `CertStore` rather than by spawning `mitmdump` and
    racing its startup — the process approach is timing-dependent and gave no CA at all
    on a cold `~/.mitmproxy`.
    """
    if CA_PEM.exists():
        return CA_PEM

    try:
        from mitmproxy.certs import CertStore
    except ImportError:
        warn("mitmproxy is not installed — `uv pip install mitmproxy`")
        return None

    say("net", "generating mitmproxy CA (first run)")
    MITM_HOME.mkdir(parents=True, exist_ok=True)
    try:
        CertStore.from_store(str(MITM_HOME), "mitmproxy", 2048)
    except Exception as exc:  # noqa: BLE001 - surface any cert-gen failure as a warning
        warn(f"CA generation failed: {exc}")
        return None

    return CA_PEM if CA_PEM.exists() else None


def host_ip_for_emulator() -> str:
    """From inside the emulator, the host loopback is 10.0.2.2."""
    return "10.0.2.2"


# ---- device proxy configuration ----

def set_device_proxy(port: int = DEFAULT_PORT, serial: str | None = None) -> bool:
    host = host_ip_for_emulator()
    res = shell.adb_shell(["settings", "put", "global", "http_proxy", f"{host}:{port}"],
                          serial=serial, timeout=30)
    return res.rc == 0


def clear_device_proxy(serial: str | None = None) -> None:
    shell.adb_shell(["settings", "put", "global", "http_proxy", ":0"], serial=serial, timeout=30)
    shell.adb_shell(["settings", "delete", "global", "http_proxy"], serial=serial, timeout=30)


def device_proxy(serial: str | None = None) -> str:
    return shell.adb_shell(["settings", "get", "global", "http_proxy"],
                           serial=serial, timeout=20).stdout.strip()


# ---- capture ----

@dataclass
class Capture:
    """A running mitmdump session writing newline-delimited JSON flows."""

    proc: subprocess.Popen
    flows_path: Path
    dump_path: Path
    port: int

    def stop(self, timeout: int = 15) -> None:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

    @property
    def running(self) -> bool:
        return self.proc.poll() is None


# Emitted as JSON lines by the addon below. Kept small on purpose — full bodies live in
# the mitmproxy dump file, which the operator can open in mitmweb.
_ADDON = '''
import json, os
from mitmproxy import http, ctx

OUT = os.environ["DROID_RECON_FLOWS"]
LIMIT = int(os.environ.get("DROID_RECON_BODY_LIMIT", "4000"))

def _body(msg):
    try:
        raw = msg.get_text(strict=False) or ""
    except Exception:
        raw = ""
    return raw[:LIMIT]

def _write(rec):
    with open(OUT, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\\n")

def response(flow: http.HTTPFlow):
    _write({
        "kind": "flow",
        "method": flow.request.method,
        "scheme": flow.request.scheme,
        "host": flow.request.host,
        "port": flow.request.port,
        "path": flow.request.path,
        "url": flow.request.pretty_url,
        "req_headers": dict(flow.request.headers),
        "req_body": _body(flow.request),
        "status": flow.response.status_code,
        "resp_headers": dict(flow.response.headers),
        "resp_body": _body(flow.response),
        "timestamp": flow.request.timestamp_start,
    })

def error(flow):
    if getattr(flow, "error", None) is not None:
        _write({
            "kind": "error",
            "url": getattr(getattr(flow, "request", None), "pretty_url", ""),
            "host": getattr(getattr(flow, "request", None), "host", ""),
            "msg": str(flow.error),
        })

def tls_failed_client(data):
    _write({
        "kind": "tls_fail",
        "side": "client",
        "sni": getattr(data.context.client, "sni", None) or "",
        "address": str(getattr(data.context.client, "peername", "")),
        "msg": str(getattr(data, "conn", "")) or "client rejected the proxy certificate",
    })
'''


def start_capture(out_dir: Path, port: int = DEFAULT_PORT,
                  body_limit: int = 4000) -> Capture | None:
    exe = mitmdump_bin()
    if not exe:
        warn("mitmdump not found — install with `uv pip install mitmproxy`")
        return None

    out_dir.mkdir(parents=True, exist_ok=True)
    addon_path = out_dir / "_dr_addon.py"
    addon_path.write_text(_ADDON, encoding="utf-8")
    flows_path = out_dir / "flows.jsonl"
    dump_path = out_dir / "traffic.mitm"

    import os
    env = os.environ.copy()
    env["DROID_RECON_FLOWS"] = str(flows_path)
    env["DROID_RECON_BODY_LIMIT"] = str(body_limit)

    argv = [exe, "-q", "--listen-port", str(port), "-s", str(addon_path),
            "-w", str(dump_path), "--set", "confdir=" + str(MITM_HOME)]

    say("net", f"starting mitmdump on :{port}")
    proc = subprocess.Popen(argv, stdout=open(out_dir / "mitmdump.log", "w", encoding="utf-8"),
                            stderr=subprocess.STDOUT, env=env, start_new_session=True)

    for _ in range(20):
        time.sleep(0.5)
        if proc.poll() is not None:
            warn(f"mitmdump exited immediately (rc={proc.returncode}) — see mitmdump.log")
            return None
        if _port_open(port):
            ok(f"mitmdump listening on :{port}")
            return Capture(proc, flows_path, dump_path, port)

    warn(f"mitmdump did not open :{port} in time")
    proc.terminate()
    return None


def _port_open(port: int) -> bool:
    import socket
    with socket.socket() as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) == 0


# ---- analysis ----

def read_flows(flows_path: Path) -> list[dict]:
    if not flows_path.exists():
        return []
    out = []
    for line in flows_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def analyse(records: list[dict], package: str = "") -> dict:
    """Turn raw flows into the things worth reporting."""
    flows = [r for r in records if r.get("kind") == "flow"]
    tls_fails = [r for r in records if r.get("kind") == "tls_fail"]
    errors = [r for r in records if r.get("kind") == "error"]

    cleartext: list[dict] = []
    secrets: list[dict] = []
    idor: list[dict] = []
    hosts: dict[str, int] = {}

    for f in flows:
        host = f.get("host", "")
        hosts[host] = hosts.get(host, 0) + 1

        if f.get("scheme") == "http":
            cleartext.append({
                "url": f.get("url", "")[:200],
                "method": f.get("method"),
                "status": f.get("status"),
                "why": "plaintext HTTP — readable and modifiable by any network attacker",
            })

        blob = " ".join([
            f.get("url", ""),
            json.dumps(f.get("req_headers", {})),
            f.get("req_body", "") or "",
        ])
        hits = set()
        for m in _SECRET_IN_TRAFFIC.finditer(blob):
            hits.add(m.group(1).lower())
        jwts = _JWT.findall(blob)
        if hits or jwts:
            secrets.append({
                "url": f.get("url", "")[:200],
                "method": f.get("method"),
                "keys": sorted(hits),
                "jwt_count": len(jwts),
                "in_url": bool(_SECRET_IN_TRAFFIC.search(f.get("url", ""))),
            })

        for m in _ID_PARAM.finditer(f.get("url", "") + " " + (f.get("req_body") or "")):
            idor.append({
                "url": f.get("url", "")[:200],
                "method": f.get("method"),
                "param": m.group(1),
                "value": m.group(2),
                "why": "object identifier in a request — candidate for an IDOR/BOLA test "
                       "by replaying it under a second account",
            })

    return {
        "summary": {
            "flows": len(flows),
            "hosts": len(hosts),
            "cleartext_http": len(cleartext),
            "requests_with_secrets": len(secrets),
            "idor_candidates": len(idor),
            "handshake_failures": len(tls_fails),
            "transport_errors": len(errors),
        },
        "top_hosts": sorted(hosts.items(), key=lambda kv: -kv[1])[:20],
        "cleartext": cleartext[:25],
        "secrets_in_traffic": secrets[:25],
        "idor_candidates": idor[:25],
        "tls_failures": [
            {"sni": t.get("sni", ""), "msg": str(t.get("msg", ""))[:160]} for t in tls_fails[:15]
        ],
        "interpretation": _interpret(len(flows), len(tls_fails)),
    }


def _interpret(n_flows: int, n_tls_fail: int) -> str:
    """Say WHY a capture is empty. An unexplained zero looks like 'app made no requests'."""
    if n_flows == 0 and n_tls_fail == 0:
        return ("No traffic captured at all. The proxy was not reached. Check "
                "`settings get global http_proxy`, and that the app was exercised while "
                "the capture ran. NOTE: Android WebView ignores the runtime proxy setting "
                "(it uses Chromium's own network stack) — for WebView traffic the "
                "emulator must be booted with `-http-proxy`, i.e. "
                "`droid-recon device up --http-proxy 10.0.2.2:8080`.")
    if n_tls_fail and n_flows == 0:
        return (f"{n_tls_fail} TLS handshake failure(s) and zero decrypted flows: traffic "
                f"IS reaching the proxy, but the app rejects its certificate. Either the "
                f"system CA is not installed (`droid-recon net setup`) or the app pins its "
                f"certificate — run `droid-recon frida run <pkg> --script ssl_unpin` first.")
    if n_tls_fail:
        return (f"{n_flows} flows captured, but {n_tls_fail} handshake(s) failed — some "
                f"endpoints are pinned. Findings from this capture are incomplete; the "
                f"pinned hosts are exactly the ones worth unpinning.")
    return f"{n_flows} flows captured cleanly with no handshake failures."


def export_har(records: list[dict], dest: Path) -> Path:
    """HAR 1.2, for loading into a browser devtools / Burp / any HAR viewer."""
    entries = []
    for f in (r for r in records if r.get("kind") == "flow"):
        entries.append({
            "startedDateTime": _iso(f.get("timestamp")),
            "time": 0,
            "request": {
                "method": f.get("method", "GET"),
                "url": f.get("url", ""),
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v}
                            for k, v in (f.get("req_headers") or {}).items()],
                "queryString": [], "cookies": [], "headersSize": -1,
                "bodySize": len(f.get("req_body") or ""),
                "postData": ({"mimeType": (f.get("req_headers") or {}).get("content-type", ""),
                              "text": f.get("req_body") or ""} if f.get("req_body") else None),
            },
            "response": {
                "status": f.get("status", 0), "statusText": "", "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v}
                            for k, v in (f.get("resp_headers") or {}).items()],
                "cookies": [], "redirectURL": "", "headersSize": -1,
                "bodySize": len(f.get("resp_body") or ""),
                "content": {"size": len(f.get("resp_body") or ""),
                            "mimeType": (f.get("resp_headers") or {}).get("content-type", ""),
                            "text": f.get("resp_body") or ""},
            },
            "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
        })
    har = {"log": {"version": "1.2",
                   "creator": {"name": "droid-recon", "version": __version__},
                   "entries": entries}}
    dest.write_text(json.dumps(har, indent=2), encoding="utf-8")
    return dest


def _iso(ts) -> str:
    from datetime import datetime, timezone
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).isoformat()
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).isoformat()
