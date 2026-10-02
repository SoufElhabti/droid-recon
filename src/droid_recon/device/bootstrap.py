"""Bootstrap operations: the ONLY module that should call shell.adb* directly.

Everything here is a one-time setup or lifecycle operation that runs before or
after the device agent is available. Runtime operations (probes, logcat, screen,
storage, oracle, exploit, explorer) go through device_agent.runtime instead.

The boundary:
  BOOTSTRAP (this module + emulator, install, certs, network, frida/server):
    adb push, adb pull, adb install, adb root, adb forward, adb shell getprop,
    pm install/path/clear, am force-stop, mount/nsenter, settings put/get,
    frida-server lifecycle, emulator boot/shutdown

  RUNTIME (device_agent.runtime → agent HTTP or adb_shell fallback):
    am start/broadcast, content query/call/read, screencap, uiautomator,
    dumpsys, pidof, logcat, input tap/text, find, ls, cp, chmod, sqlite3,
    cat /proc/maps
"""

from __future__ import annotations

from .. import shell


def launch_app(package: str, serial: str | None = None, *, agent=None) -> None:
    """Start the app's launcher activity. Bootstrap: used before probing begins."""
    from ..device_agent.runtime import exec_on_device
    exec_on_device(
        ["monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"],
        agent=agent, serial=serial, timeout=30,
    )


def notify_proxy_change(serial: str | None = None, *, agent=None) -> None:
    """Broadcast PROXY_CHANGE so apps pick up the new proxy setting."""
    from ..device_agent.runtime import exec_on_device
    exec_on_device(
        ["am", "broadcast", "-a", "android.intent.action.PROXY_CHANGE"],
        agent=agent, serial=serial, timeout=20,
    )


def force_stop(package: str, serial: str | None = None) -> None:
    """Stop the app. Pure bootstrap — only called at cleanup boundaries."""
    shell.adb_shell(["am", "force-stop", package], serial=serial, timeout=30)
