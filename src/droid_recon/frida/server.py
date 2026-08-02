"""Optional Frida layer. Everything here fails soft.

Frida is genuinely useful (SSL unpinning, crypto key logging, WebView hooks) but it is
the most brittle part of the stack: the frida-server build on the device must match the
host frida version exactly, it needs a network fetch, and SELinux can block the attach.

So it is opt-in via `--frida`, and every failure downgrades to a warning plus a dead-end
note rather than aborting the audit. Development rule 9: fail open on non-critical tools.
"""

from __future__ import annotations

from datetime import datetime, timezone
import lzma
import re
import urllib.error
import urllib.request
from pathlib import Path

from .. import shell
from ..log import ok, say, warn

REMOTE_PATH = "/data/local/tmp/frida-server"
CACHE = Path.home() / ".cache" / "droid-recon" / "frida"
RELEASE_URL = ("https://github.com/frida/frida/releases/download/"
               "{ver}/frida-server-{ver}-android-{arch}.xz")
SCRIPTS_DIR = Path(__file__).parent / "scripts"


def host_version() -> str | None:
    exe = shell.which("frida")
    if not exe:
        return None
    proc = shell.run([exe, "--version"], timeout=30)
    return proc.stdout.strip() or None


def device_arch(serial: str | None = None) -> str:
    abi = shell.adb_shell(["getprop", "ro.product.cpu.abi"], serial=serial, timeout=20).stdout.strip()
    return {
        "arm64-v8a": "arm64",
        "armeabi-v7a": "arm",
        "x86_64": "x86_64",
        "x86": "x86",
    }.get(abi, "arm64")


def fetch_server(version: str, arch: str) -> Path | None:
    """Download and decompress a matching frida-server. Cached by version+arch."""
    CACHE.mkdir(parents=True, exist_ok=True)
    local = CACHE / f"frida-server-{version}-android-{arch}"
    if local.exists() and local.stat().st_size > 0:
        return local

    url = RELEASE_URL.format(ver=version, arch=arch)
    say("frida", f"downloading frida-server {version} ({arch})")
    try:
        with urllib.request.urlopen(url, timeout=180) as resp:
            compressed = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        warn(f"frida-server download failed: {exc}")
        return None

    try:
        local.write_bytes(lzma.decompress(compressed))
    except lzma.LZMAError as exc:
        warn(f"frida-server decompress failed: {exc}")
        return None
    local.chmod(0o755)
    return local


def is_running(serial: str | None = None) -> bool:
    proc = shell.adb_shell(["pgrep", "-f", "frida-server"], serial=serial, timeout=20)
    return bool(proc.stdout.strip())


def ensure_server(serial: str | None = None) -> tuple[bool, str]:
    """Push and start frida-server if needed. Returns (available, message)."""
    version = host_version()
    if not version:
        return False, "frida CLI not found on PATH (pip install frida-tools)"

    if is_running(serial):
        ok(f"frida-server already running (host frida {version})")
        return True, f"already running, host {version}"

    who = shell.adb_shell(["whoami"], serial=serial, timeout=15).stdout.strip()
    if who != "root":
        return False, "device is not rooted (`adb root` first) — frida-server cannot start"

    binary = fetch_server(version, device_arch(serial))
    if binary is None:
        return False, f"could not obtain frida-server {version}"

    push = shell.adb("push", str(binary), REMOTE_PATH, serial=serial, timeout=180)
    if not push.ok:
        return False, f"push failed: {push.stderr.strip()[:160]}"
    shell.adb_shell(["chmod", "755", REMOTE_PATH], serial=serial, timeout=20)

    # Detach so the shell returns; frida-server must outlive this command.
    shell.adb_shell(
        ["nohup", REMOTE_PATH, "-D", ">/dev/null", "2>&1", "&"], serial=serial, timeout=20
    )

    import time
    for _ in range(10):
        time.sleep(1)
        if is_running(serial):
            ok(f"frida-server {version} started on device")
            return True, f"started {version}"

    enforce = shell.adb_shell(["getenforce"], serial=serial, timeout=15).stdout.strip()
    return False, (f"frida-server did not start (SELinux={enforce}). "
                   f"`adb shell setenforce 0` may be required — note that it changes the "
                   f"security model of any result obtained afterwards.")


def list_scripts() -> dict[str, Path]:
    if not SCRIPTS_DIR.is_dir():
        return {}
    return {p.stem: p for p in sorted(SCRIPTS_DIR.glob("*.js"))}


# Frida's own error prefixes. Note `--pause` is opt-in in Frida 17 (there is no
# `--no-pause`), and `-q -t N` runs the script headless for N seconds then exits —
# which is exactly the collection window we want, without relying on a SIGKILL.
_FRIDA_ERRORS = (
    "Failed to", "unable to", "error:", "Unable to", "usage: frida",
    "Process not found", "Need Gadget", "unrecognized arguments",
)


def output_excerpt(output: str, limit: int = 6000) -> str:
    """Keep both startup hooks and late events while bounding terminal/MCP output."""
    if len(output) <= limit:
        return output
    notice = "\n... middle omitted; see artifact ...\n"
    available = max(0, limit - len(notice))
    head = available // 2
    tail = available - head
    suffix = output[-tail:] if tail else ""
    return output[:head] + notice + suffix


def persist_output(output: str, out_dir: Path, label: str) -> Path | None:
    """Persist a complete Frida transcript under a collision-resistant filename."""
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-.")[:80] or "frida"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = out_dir / f"{safe}-{stamp}.log"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(output + ("\n" if output and not output.endswith("\n") else ""),
                        encoding="utf-8")
    except OSError as exc:
        warn(f"could not persist Frida output: {exc}")
        return None
    return path


def _has_cli_error(output: str) -> bool:
    # Match Frida's own diagnostic lines, not words inside instrumented app events. A
    # Lottie payload or stack can legitimately contain strings such as "Unable to parse".
    return any(
        line.lstrip().startswith(marker)
        for line in output.splitlines()
        for marker in _FRIDA_ERRORS
    )


def run_script(package: str, script: Path, serial: str | None = None, *,
               spawn: bool = True, duration: int = 20) -> tuple[bool, str]:
    """Run a script and return its complete output; callers persist/bound presentation."""
    exe = shell.which("frida")
    if not exe:
        return False, "frida CLI not found"
    if not script.exists():
        return False, f"script not found: {script}"

    argv = [exe]
    argv += ["-D", serial] if serial else ["-U"]
    argv += ["-l", str(script), "--runtime=v8", "-q", "-t", str(duration)]
    argv += ["-f", package] if spawn else ["-n", package]

    say("frida", f"{'spawning' if spawn else 'attaching to'} {package} with {script.name} "
                 f"({duration}s window)")
    # +15s of slack so the subprocess timeout never fires before frida's own -t does.
    proc = shell.run(argv, timeout=duration + 15)
    output = (proc.stdout + proc.stderr).strip()

    if proc.timed_out:
        return False, f"frida did not exit within {duration + 15}s\n{output}"
    if not proc.ok or _has_cli_error(output):
        return False, output or f"frida exited with status {proc.rc}"
    return True, output
