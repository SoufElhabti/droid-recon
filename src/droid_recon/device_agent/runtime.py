"""Runtime dispatch: agent if available, else adb shell.

Modules call these instead of `shell.adb_shell()` / `shell.adb_script()` directly,
gaining the device agent's persistent-connection advantage when deployed, with
transparent fallback to ADB otherwise.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .. import shell

if TYPE_CHECKING:
    from .client import DeviceAgentClient


def exec_on_device(
    argv: list[str],
    *,
    agent: DeviceAgentClient | None = None,
    serial: str | None = None,
    timeout: int = 60,
) -> shell.Proc:
    if agent:
        return agent.exec(argv, timeout=timeout)
    return shell.adb_shell(argv, serial=serial, timeout=timeout)


def exec_script(
    script: str,
    *,
    agent: DeviceAgentClient | None = None,
    serial: str | None = None,
    timeout: int = 60,
) -> shell.Proc:
    if agent:
        return agent.exec_script(script, timeout=timeout)
    return shell.adb_script(script, serial=serial, timeout=timeout)
