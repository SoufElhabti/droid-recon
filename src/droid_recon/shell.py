"""Subprocess and ADB wrappers.

Two rules, both learned the hard way:

1. Never `shell=True`. Target package names and provider URIs are attacker-influenced
   strings; they go in an argv list, never through a shell.
2. Every invocation MUST have a timeout. macOS has no `timeout` binary, and `adb shell`
   against a wedged device blocks forever — which would deadlock an unattended run.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT = 60


@dataclass
class Proc:
    """Result of a subprocess invocation. Never raises on non-zero exit."""

    argv: list[str]
    rc: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out

    def to_dict(self) -> dict:
        return {
            "argv": self.argv,
            "rc": self.rc,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
        }


def run(argv: list[str], timeout: int = DEFAULT_TIMEOUT, cwd: Path | None = None) -> Proc:
    """Run `argv`, capturing output. Returns a Proc even on failure or timeout."""
    try:
        cp = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
        return Proc(argv, cp.returncode, cp.stdout, cp.stderr)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return Proc(argv, 124, out, err, timed_out=True)
    except FileNotFoundError:
        return Proc(argv, 127, "", f"{argv[0]}: not found")


# ---- tool discovery ----

def android_home() -> Path | None:
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        val = os.environ.get(var)
        if val and Path(val).is_dir():
            return Path(val)
    for guess in (
        Path("/opt/homebrew/share/android-commandlinetools"),
        Path.home() / "Library/Android/sdk",
    ):
        if guess.is_dir():
            return guess
    return None


def _sdk_tool(*relative: str) -> str | None:
    home = android_home()
    if home is None:
        return None
    for rel in relative:
        cand = home / rel
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


def which(name: str, *sdk_relative: str) -> str | None:
    """Find a tool on PATH, falling back to known SDK locations."""
    found = shutil.which(name)
    if found:
        return found
    return _sdk_tool(*sdk_relative)


def adb_path() -> str:
    return which("adb", "platform-tools/adb") or "adb"


def aapt2_path() -> str | None:
    home = android_home()
    if home is not None:
        bt = home / "build-tools"
        if bt.is_dir():
            # Highest version wins.
            for ver in sorted(bt.iterdir(), reverse=True):
                cand = ver / "aapt2"
                if cand.is_file():
                    return str(cand)
    return shutil.which("aapt2")


# ---- adb ----

def adb(*args: str, serial: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> Proc:
    argv = [adb_path()]
    if serial:
        argv += ["-s", serial]
    argv += list(args)
    return run(argv, timeout=timeout)


def adb_shell(command: list[str], serial: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> Proc:
    """Run a shell command on device. `command` is an argv list, not a string."""
    return adb("shell", *command, serial=serial, timeout=timeout)


def devices() -> list[str]:
    """Serials of devices in `device` state (not `offline`/`unauthorized`)."""
    proc = adb("devices", timeout=15)
    out = []
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            out.append(parts[0])
    return out
