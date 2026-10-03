"""App private-storage inspection (requires root) and world-readable file scanning.

Two distinct questions, often conflated:

  * "Is there a secret in SharedPreferences?" — needs root to read, and on its own is
    only a finding if something else can reach it (backup, an exported provider, a
    world-readable mode, or a rooted-device threat model). Reported as `info` context.
  * "Is a file world-readable / on shared external storage?" — reachable by any app
    with no root at all. That one is a real finding on a stock device.
"""

from __future__ import annotations

import re
from pathlib import Path

from .. import shell

SECRET_HINT = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|auth|bearer|credential|private[_-]?key|"
    r"session|refresh[_-]?token)", re.IGNORECASE
)

# Values that look like real credentials rather than a boolean flag named "token_enabled".
_VALUE_LIKE = re.compile(r'>[^<]{16,}<|"[A-Za-z0-9+/=_\-]{20,}"')


def data_dir(package: str) -> str:
    return f"/data/data/{package}"


def _ls(path: str, serial: str | None = None, *, agent=None) -> list[str]:
    from ..device_agent.runtime import exec_on_device
    proc = exec_on_device(["ls", "-la", path], agent=agent, serial=serial, timeout=45)
    if not proc.ok:
        return []
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


def pull_private_data(package: str, dest: Path, serial: str | None = None,
                      *, agent=None) -> dict:
    """Copy shared_prefs/ databases/ files/ off the device. Needs root."""
    from ..device_agent.runtime import exec_on_device

    dest.mkdir(parents=True, exist_ok=True)
    result: dict = {"pulled": [], "errors": [], "root_required": True}

    who = exec_on_device(["whoami"], agent=agent, serial=serial, timeout=15).stdout.strip()
    if who != "root":
        result["errors"].append("not root — cannot read /data/data; run `adb root` first")
        return result

    base = data_dir(package)
    for sub in ("shared_prefs", "databases", "files", "no_backup"):
        remote = f"{base}/{sub}"
        exists = exec_on_device(["test", "-d", remote], agent=agent, serial=serial, timeout=20)
        if exists.rc != 0:
            continue
        staging = f"/data/local/tmp/dr_{sub}"
        exec_on_device(["rm", "-rf", staging], agent=agent, serial=serial, timeout=30)
        cp = exec_on_device(["cp", "-r", remote, staging],
                            agent=agent, serial=serial, timeout=120)
        if cp.rc != 0:
            result["errors"].append(f"{sub}: {cp.stderr.strip()[:160]}")
            continue
        exec_on_device(["chmod", "-R", "777", staging],
                       agent=agent, serial=serial, timeout=60)
        # File transfer still goes through ADB — the agent has no recursive pull.
        pull = shell.adb("pull", staging, str(dest / sub), serial=serial, timeout=300)
        exec_on_device(["rm", "-rf", staging], agent=agent, serial=serial, timeout=30)
        if (dest / sub).exists():
            result["pulled"].append(sub)
        else:
            result["errors"].append(f"{sub}: pull failed {pull.stderr.strip()[:160]}")

    return result


def scan_prefs_for_secrets(dest: Path) -> list[dict]:
    """Grep pulled SharedPreferences XML for credential-shaped entries."""
    out: list[dict] = []
    prefs = dest / "shared_prefs"
    if not prefs.is_dir():
        return out
    for xml_file in sorted(prefs.rglob("*.xml")):
        try:
            text = xml_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            if SECRET_HINT.search(line) and _VALUE_LIKE.search(line):
                out.append({
                    "file": str(xml_file.relative_to(dest)),
                    "line": " ".join(line.split())[:240],
                })
    return out


def list_databases(dest: Path) -> list[dict]:
    out: list[dict] = []
    dbs = dest / "databases"
    if not dbs.is_dir():
        return out
    for db in sorted(dbs.rglob("*")):
        if db.is_file() and db.suffix in ("", ".db", ".sqlite", ".sqlite3"):
            out.append({"file": str(db.relative_to(dest)), "bytes": db.stat().st_size})
    return out


def dump_db_tables(package: str, db_remote_path: str, serial: str | None = None,
                   *, agent=None) -> list[str]:
    """List tables via the device's own sqlite3, avoiding a local sqlite dependency."""
    from ..device_agent.runtime import exec_on_device
    proc = exec_on_device(
        ["sqlite3", db_remote_path, ".tables"], agent=agent, serial=serial, timeout=60
    )
    if not proc.ok:
        return []
    return sorted({t for t in proc.stdout.split() if t})


def world_readable_scan(package: str, serial: str | None = None,
                        *, agent=None) -> list[dict]:
    """Files any unprivileged app can read: bad modes in the sandbox, or shared storage.

    This is the part that holds on a stock, non-rooted device — unlike everything else
    in this module, which needs root to observe.
    """
    from ..device_agent.runtime import exec_on_device

    findings: list[dict] = []

    proc = exec_on_device(
        ["find", data_dir(package), "-type", "f", "-perm", "-o+r"],
        agent=agent, serial=serial, timeout=120,
    )
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("find:"):
            findings.append({
                "path": line,
                "why": "world-readable inside the app sandbox (MODE_WORLD_READABLE or bad chmod)",
                "reachable_from": "third_party_app",
            })

    for ext in (f"/sdcard/Android/data/{package}", "/sdcard/Download"):
        proc = exec_on_device(["ls", "-la", ext], agent=agent, serial=serial, timeout=60)
        if proc.ok and proc.stdout.strip():
            files = [ln for ln in proc.stdout.splitlines()[1:] if ln.strip()]
            if files:
                findings.append({
                    "path": ext,
                    "why": f"{len(files)} entries on shared external storage",
                    "reachable_from": "third_party_app",
                    "sample": files[:10],
                })

    return findings[:200]
