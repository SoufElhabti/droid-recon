"""Read-only host capability check for the audit pipeline.

The project has no Python runtime dependencies, but its analysis stages need
external Android and reverse-engineering tools.  Report exactly which stages
are available instead of treating a skipped stage as a clean security result.
"""

from __future__ import annotations

import platform
import os
import sys
from collections.abc import Callable
from pathlib import Path, PureWindowsPath

from . import shell


def _ini_values(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    return {key.strip(): value.strip() for line in lines if "=" in line
            for key, _, value in (line.partition("="),)}


def _avd_config(avd_home: Path, user_home: Path, name: str) -> Path | None:
    """Locate config.ini through the standard AVD .ini pointer when present."""
    if not name or name in {".", ".."} or any(char in name for char in "/\\:"):
        return None
    default = avd_home / f"{name}.avd" / "config.ini"
    pointer = _ini_values(avd_home / f"{name}.ini")
    candidates: list[Path] = []
    absolute = Path(pointer.get("path", ""))
    if absolute.is_absolute():
        candidates.append(absolute / "config.ini")
    relative_text = pointer.get("path.rel", "").replace("\\", "/")
    relative = Path(relative_text)
    if (relative_text and not relative.is_absolute()
            and not PureWindowsPath(relative_text).is_absolute()
            and ".." not in relative.parts):
        candidate = (user_home / relative).resolve()
        if candidate.is_relative_to(user_home.resolve()):
            candidates.append(candidate / "config.ini")
    candidates.append(default)
    return next((candidate for candidate in candidates if candidate.is_file()), default)


def inspect(
    *,
    find: Callable[..., str | None] | None = None,
    sdk_home: Callable[[], object | None] | None = None,
    avd_list: Callable[[], list[str]] | None = None,
    device_list: Callable[[], list[str]] | None = None,
) -> dict:
    """Return a capability inventory without launching tools or a device."""
    native_lookup = find is None
    find = find or shell.which
    sdk_home = sdk_home or shell.android_home
    sdk = sdk_home()
    paths = {
        "adb": find("adb", "platform-tools/adb"),
        "emulator": find("emulator", "emulator/emulator"),
        "apkanalyzer": find("apkanalyzer", "cmdline-tools/latest/bin/apkanalyzer"),
        "aapt2": find("aapt2"),
        "jadx": find("jadx"),
        "apktool": find("apktool"),
        "frida": find("frida"),
        "mitmdump": find("mitmdump"),
        "analyzeHeadless": find("analyzeHeadless"),
        "java": find("java"),
        "javac": find("javac"),
    }
    # shell.aapt2_path searches versioned build-tools directories as well.
    if find is shell.which and paths["aapt2"] is None:
        paths["aapt2"] = shell.aapt2_path()

    if avd_list is None:
        if native_lookup and paths["emulator"]:
            from .device import emulator
            avd_list = emulator.list_avds
        else:
            avd_list = lambda: []
    if device_list is None:
        device_list = shell.devices if native_lookup and paths["adb"] else lambda: []
    avds = avd_list()
    attached = device_list()
    platform_jars = (sorted((Path(sdk) / "platforms").glob("android-*/android.jar"))
                     if sdk is not None else [])
    user_home = Path(os.environ.get("ANDROID_USER_HOME") or Path.home() / ".android")
    avd_home = Path(os.environ.get("ANDROID_AVD_HOME") or user_home / "avd")
    host_arch = platform.machine().lower()
    arch_aliases = {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64-v8a",
                    "arm64": "arm64-v8a"}
    normalized_host = arch_aliases.get(host_arch, host_arch)
    avd_details = []
    for name in avds:
        config = _avd_config(avd_home, user_home, name)
        abi = _ini_values(config).get("abi.type") if config is not None else None
        avd_details.append({"name": name, "abi": abi,
                            "host_abi_match": (abi == normalized_host if abi else None)})

    capabilities = {
        "manifest": bool(paths["apkanalyzer"] or paths["aapt2"]),
        "code": bool(paths["jadx"]),
        "resources": bool(paths["apktool"]),
        "device": bool(paths["adb"] and (attached or (paths["emulator"] and avds))),
        "attached_device": bool(attached),
        "companion_build": bool(paths["java"] and paths["javac"] and
                                paths["aapt2"] and platform_jars),
        "frida": bool(paths["adb"] and paths["frida"]),
        "network": bool(paths["adb"] and paths["mitmdump"]),
        "native": bool(paths["analyzeHeadless"]),
    }
    missing = [name for name, available in capabilities.items() if not available]
    return {
        "host": platform.system().lower(),
        "python": platform.python_version(),
        "python_supported": sys.version_info >= (3, 11),
        "android_sdk": str(sdk) if sdk is not None else None,
        "host_arch": host_arch,
        "avds": avd_details,
        "attached_devices": attached,
        "android_platforms": [path.parent.name for path in platform_jars],
        "tools": paths,
        "capabilities": capabilities,
        "missing_capabilities": missing,
        "note": ("This inventories local tools, AVD configuration, and attached serials; "
                 "it does not prove device readiness or APK compatibility."),
    }
