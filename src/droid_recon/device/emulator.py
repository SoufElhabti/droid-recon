"""AVD lifecycle: headless boot, readiness wait, root.

Measured on this machine: `webview_lab` (pixel_7 / android-34 / google_apis / arm64)
cold-boots headless in ~23 s and `adb root` succeeds (userdebug image).

Readiness is two conditions, not one. `sys.boot_completed=1` fires before the package
manager will answer, so installing at that moment fails intermittently — we wait for
`pm path android` to resolve as well.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from .. import shell
from ..log import ok, say, warn

BOOT_TIMEOUT = 300
POLL_INTERVAL = 2.0


def emulator_bin() -> str | None:
    return shell.which("emulator", "emulator/emulator")


def list_avds() -> list[str]:
    exe = emulator_bin()
    if not exe:
        return []
    proc = shell.run([exe, "-list-avds"], timeout=30)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def running_serial() -> str | None:
    serials = shell.devices()
    for s in serials:
        if s.startswith("emulator-"):
            return s
    return serials[0] if serials else None


def boot(avd: str, *, headless: bool = True, log_path: Path | None = None,
         wipe: bool = False, http_proxy: str | None = None) -> str | None:
    """Start `avd` and wait until it is genuinely usable. Returns the serial.

    `http_proxy` (e.g. "10.0.2.2:8080") routes traffic through a proxy at the EMULATOR
    level. That matters because `settings put global http_proxy` — the runtime method —
    is honoured by ordinary HTTP stacks but **ignored by Android WebView**, which uses
    Chromium's own network stack. Verified here: with only the runtime setting, a
    WebView loading https://example.com produced zero captured flows while other traffic
    was captured normally. If you need WebView traffic, boot with this.
    """
    existing = running_serial()
    if existing:
        if http_proxy:
            warn(f"device {existing} is already running — the -http-proxy flag only "
                 f"applies at boot. Shut it down first if you need WebView traffic.")
        say("device", f"reusing running device {existing}")
        return existing if wait_ready(existing) else None

    exe = emulator_bin()
    if not exe:
        warn("emulator binary not found (is the Android SDK installed?)")
        return None
    if avd not in list_avds():
        warn(f"AVD '{avd}' not found. Available: {', '.join(list_avds()) or '(none)'}")
        return None

    argv = [exe, "-avd", avd, "-no-audio", "-no-boot-anim",
            "-gpu", "swiftshader_indirect", "-no-snapshot"]
    if http_proxy:
        argv += ["-http-proxy", http_proxy if "://" in http_proxy else f"http://{http_proxy}"]
    if headless:
        argv.append("-no-window")
    if wipe:
        argv.append("-wipe-data")

    say("device", f"booting AVD '{avd}' ({'headless' if headless else 'windowed'})")
    out = open(log_path, "w") if log_path else subprocess.DEVNULL
    subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT,
                     start_new_session=True, env=os.environ.copy())

    deadline = time.time() + BOOT_TIMEOUT
    serial = None
    while time.time() < deadline:
        serial = running_serial()
        if serial:
            break
        time.sleep(POLL_INTERVAL)
    if not serial:
        warn(f"no device appeared within {BOOT_TIMEOUT}s")
        return None

    return serial if wait_ready(serial, deadline=deadline) else None


def wait_ready(serial: str, deadline: float | None = None) -> bool:
    """Wait for boot_completed AND a responsive package manager."""
    deadline = deadline or (time.time() + BOOT_TIMEOUT)
    started = time.time()

    while time.time() < deadline:
        boot_done = shell.adb_shell(["getprop", "sys.boot_completed"], serial=serial, timeout=15)
        if boot_done.stdout.strip() == "1":
            pm = shell.adb_shell(["pm", "path", "android"], serial=serial, timeout=30)
            if "package:" in pm.stdout:
                ok(f"device {serial} ready in {time.time() - started:.0f}s")
                return True
        time.sleep(POLL_INTERVAL)

    warn(f"device {serial} did not become ready within the deadline")
    return False


def become_root(serial: str) -> bool:
    """`adb root`. Fails on production/Play-Store images — that is survivable."""
    proc = shell.adb("root", serial=serial, timeout=30)
    combined = (proc.stdout + proc.stderr).lower()
    if "cannot run as root" in combined or "production builds" in combined:
        warn("adb root refused (production build) — storage inspection will be limited")
        return False
    shell.adb("wait-for-device", serial=serial, timeout=60)
    who = shell.adb_shell(["whoami"], serial=serial, timeout=15)
    if who.stdout.strip() == "root":
        ok("adbd running as root")
        return True
    warn(f"adb root did not take effect (whoami={who.stdout.strip()!r})")
    return False


def device_info(serial: str) -> dict:
    def prop(name: str) -> str:
        return shell.adb_shell(["getprop", name], serial=serial, timeout=15).stdout.strip()

    return {
        "serial": serial,
        "sdk": prop("ro.build.version.sdk"),
        "release": prop("ro.build.version.release"),
        "build_type": prop("ro.build.type"),
        "product": prop("ro.product.model"),
        "abi": prop("ro.product.cpu.abi"),
        "selinux": shell.adb_shell(["getenforce"], serial=serial, timeout=15).stdout.strip(),
        "is_root": shell.adb_shell(["whoami"], serial=serial, timeout=15).stdout.strip() == "root",
    }


def shutdown(serial: str) -> None:
    shell.adb("emu", "kill", serial=serial, timeout=30)
