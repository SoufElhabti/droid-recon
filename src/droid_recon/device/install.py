"""APK installation, including split sets.

`install-multiple` is required for any app distributed as base + config.*.apk; using
plain `install` on the base alone yields an app that crashes on launch with a missing
resource, which then looks like a probe failure and wastes the whole dynamic pass.
"""

from __future__ import annotations

from pathlib import Path

from .. import shell
from ..log import ok, say, warn

INSTALL_TIMEOUT = 300


def is_installed(package: str, serial: str | None = None) -> bool:
    proc = shell.adb_shell(["pm", "path", package], serial=serial, timeout=30)
    return "package:" in proc.stdout


def install(apks: list[Path], serial: str | None = None, *, grant: bool = True,
            reinstall: bool = True) -> tuple[bool, str]:
    """Install one APK or a split set. Returns (ok, message)."""
    if not apks:
        return False, "no APKs given"

    flags = []
    if reinstall:
        flags.append("-r")
    if grant:
        flags.append("-g")

    if len(apks) == 1:
        argv = ["install", *flags, str(apks[0])]
        say("device", f"installing {apks[0].name}")
    else:
        argv = ["install-multiple", *flags, *[str(a) for a in apks]]
        say("device", f"installing split set ({len(apks)} APKs, base={apks[0].name})")

    proc = shell.adb(*argv, serial=serial, timeout=INSTALL_TIMEOUT)
    combined = (proc.stdout + proc.stderr).strip()

    if proc.ok and "Success" in combined:
        ok(f"installed ({len(apks)} apk{'s' if len(apks) > 1 else ''})")
        return True, combined

    # -g fails on apps declaring permissions the platform will not auto-grant.
    if grant and ("Failure" in combined or not proc.ok):
        warn("install with -g failed, retrying without auto-grant")
        return install(apks, serial, grant=False, reinstall=reinstall)

    return False, combined or f"rc={proc.rc}"


def uninstall(package: str, serial: str | None = None) -> bool:
    proc = shell.adb("uninstall", package, serial=serial, timeout=120)
    return "Success" in proc.stdout


def clear_data(package: str, serial: str | None = None) -> bool:
    """Reset app state between probe rounds. Replaces the emulator-snapshot machinery:
    ~2s versus 30-60s for a snapshot save/load cycle, with no `-writable-system` conflict."""
    proc = shell.adb_shell(["pm", "clear", package], serial=serial, timeout=60)
    return "Success" in proc.stdout


def stop(package: str, serial: str | None = None) -> None:
    shell.adb_shell(["am", "force-stop", package], serial=serial, timeout=30)


def pull_installed_apk(package: str, dest_dir: Path, serial: str | None = None) -> list[Path]:
    """Pull an already-installed package's APKs off the device (splits included).

    This is how we obtain real, multi-component targets without downloading anything:
    the emulator's own system apps.
    """
    proc = shell.adb_shell(["pm", "path", package], serial=serial, timeout=30)
    remote = [ln.split("package:", 1)[1].strip()
              for ln in proc.stdout.splitlines() if ln.startswith("package:")]
    if not remote:
        return []

    dest_dir.mkdir(parents=True, exist_ok=True)
    pulled: list[Path] = []
    for rpath in remote:
        local = dest_dir / Path(rpath).name
        res = shell.adb("pull", rpath, str(local), serial=serial, timeout=180)
        if local.exists():
            pulled.append(local)
        else:
            warn(f"pull failed for {rpath}: {res.stderr.strip()[:120]}")

    # base.apk first so install-multiple / manifest parsing pick the right one.
    pulled.sort(key=lambda p: (p.name != "base.apk", p.name))
    return pulled


def list_packages(serial: str | None = None, *, third_party_only: bool = False) -> list[str]:
    args = ["pm", "list", "packages"]
    if third_party_only:
        args.append("-3")
    proc = shell.adb_shell(args, serial=serial, timeout=60)
    return sorted(
        ln.split("package:", 1)[1].strip()
        for ln in proc.stdout.splitlines()
        if ln.startswith("package:")
    )
