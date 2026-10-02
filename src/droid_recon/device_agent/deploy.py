"""Deploy lifecycle for the on-device agent: push, start, port-forward, health-check.

The agent is a single Python file pushed to /data/local/tmp/ and executed as root.
Port-forwarding makes it reachable from the host via 127.0.0.1:{port}.
"""

from __future__ import annotations

import time
from pathlib import Path

from .. import shell
from ..log import say, warn
from ..transport import DeviceAgentConfig
from .client import DeviceAgentClient

REMOTE_DIR = "/data/local/tmp"
REMOTE_SCRIPT = f"{REMOTE_DIR}/droid-recon-agent.py"
_SERVER_PY = Path(__file__).parent / "server.py"


def _has_python(serial: str | None = None) -> str | None:
    """Check if Python 3 is available on the device. Returns the binary path or None."""
    for name in ("python3", "python"):
        proc = shell.adb_shell(["which", name], serial=serial, timeout=10)
        path = proc.stdout.strip()
        if proc.ok and path:
            ver = shell.adb_shell([path, "--version"], serial=serial, timeout=10)
            if ver.ok and "Python 3" in ver.stdout:
                return path
    return None


def _is_running(serial: str | None = None) -> bool:
    proc = shell.adb_shell(["pgrep", "-f", "droid-recon-agent"], serial=serial, timeout=10)
    return bool(proc.stdout.strip())


def _kill(serial: str | None = None) -> None:
    shell.adb_shell(["pkill", "-f", "droid-recon-agent"], serial=serial, timeout=10)
    time.sleep(0.5)


def push(serial: str | None = None) -> bool:
    """Push the agent script to the device."""
    if not _SERVER_PY.exists():
        warn(f"agent server.py not found at {_SERVER_PY}")
        return False
    proc = shell.adb("push", str(_SERVER_PY), REMOTE_SCRIPT, serial=serial, timeout=30)
    if not proc.ok:
        warn(f"failed to push agent: {proc.stderr.strip()}")
        return False
    shell.adb_shell(["chmod", "755", REMOTE_SCRIPT], serial=serial, timeout=10)
    return True


def start(config: DeviceAgentConfig, serial: str | None = None) -> bool:
    """Start the agent on the device. Returns True if started successfully."""
    python = _has_python(serial)
    if not python:
        warn("Python 3 not available on device — agent cannot start")
        return False

    if _is_running(serial):
        say("agent", "already running — restarting")
        _kill(serial)

    if not push(serial):
        return False

    cmd = (f"nohup {python} {REMOTE_SCRIPT}"
           f" --port {config.port}"
           f" --secret {config.secret}"
           f" >/dev/null 2>&1 &")
    shell.adb_script(cmd, serial=serial, timeout=10)

    # Port-forward so the host can reach the agent via localhost.
    fwd = shell.adb(
        "forward", f"tcp:{config.port}", f"tcp:{config.port}",
        serial=serial, timeout=10,
    )
    if not fwd.ok:
        warn(f"port forward failed: {fwd.stderr.strip()}")

    # Wait for the agent to become healthy.
    client = DeviceAgentClient(config)
    for _ in range(15):
        time.sleep(0.5)
        if client.is_alive():
            say("agent", f"running on device, forwarded to 127.0.0.1:{config.port}")
            return True

    warn("agent started but health check failed after 7.5s")
    return False


def ensure_agent(config: DeviceAgentConfig, serial: str | None = None) -> DeviceAgentClient | None:
    """Ensure the agent is running and return a connected client, or None."""
    if not config.enabled:
        return None

    client = DeviceAgentClient(config)
    if client.is_alive():
        return client

    if start(config, serial):
        return DeviceAgentClient(config)
    return None


def stop(serial: str | None = None) -> None:
    """Stop the agent on the device."""
    if _is_running(serial):
        _kill(serial)
        say("agent", "stopped")
