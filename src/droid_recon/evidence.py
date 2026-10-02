"""Reproducible, secret-free metadata for an APK audit session."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import shell
from .models import AttackSurface, utcnow


_CERT_SHA256 = re.compile(r"certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", re.I)
_CONFIG_KEYS = (
    "type", "limit", "screenshots", "traversal", "include_shell_only",
    "provider_fallbacks", "no_install", "reinstall", "no_logcat", "no_storage",
    "skip_code", "max_payloads", "avd", "serial", "no_agent",
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _apksigner_path() -> str | None:
    found = shell.which("apksigner")
    if found:
        return found
    sdk = shell.android_home()
    if sdk is None:
        return None
    build_tools = sdk / "build-tools"
    if not build_tools.is_dir():
        return None
    for version in sorted(build_tools.iterdir(), reverse=True):
        for candidate in shell._executable_candidates(version / "apksigner"):
            if candidate.is_file():
                return str(candidate)
    return None


def signing_fingerprint(apk: Path, *, signer: str | None = None) -> dict:
    """Read the APK signing certificate fingerprint when apksigner is installed."""
    signer = signer or _apksigner_path()
    if not signer:
        return {"sha256": None, "reason": "apksigner unavailable"}
    result = shell.run([signer, "verify", "--print-certs", str(apk)], timeout=45)
    if not result.ok:
        return {"sha256": None, "reason": "apksigner verification failed",
                "exit_code": result.rc}
    fingerprints = [match.replace(":", "").lower()
                    for match in _CERT_SHA256.findall(result.stdout + result.stderr)]
    if not fingerprints:
        return {"sha256": None, "reason": "certificate digest absent from apksigner output"}
    return {"sha256": sorted(set(fingerprints))}


def _device_metadata(serial: str) -> dict:
    from .device import emulator

    info = emulator.device_info(serial)
    webview = shell.adb_shell(
        ["cmd", "webviewupdate", "getCurrentWebViewPackage"], serial=serial, timeout=20
    )
    info["webview_package"] = webview.stdout.strip()[:300] if webview.ok else None
    return info


def record(
    session_dir: Path,
    surface: AttackSurface,
    *,
    args: object | None = None,
    serial: str | None = None,
    execution_context: str = "static_only",
    device_info: dict | None = None,
) -> dict:
    """Write an evidence manifest; update device context after a static-only pass.

    Only an allowlist of option names is saved, so passwords and API keys cannot be
    copied from CLI arguments into the artifact.
    """
    path = session_dir / "evidence_manifest.json"
    previous: dict = {}
    if path.exists():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous = {}

    apks = []
    for raw in surface.apk_paths:
        apk = Path(raw)
        entry = {"path": str(apk)}
        if apk.is_file():
            entry["sha256"] = _sha256(apk)
            entry["signing_certificate"] = signing_fingerprint(apk)
        else:
            entry["sha256"] = None
            entry["signing_certificate"] = {"sha256": None, "reason": "APK unavailable"}
        apks.append(entry)

    options = {key: getattr(args, key) for key in _CONFIG_KEYS
               if args is not None and hasattr(args, key)}
    contexts = list(previous.get("execution_contexts", []))
    if execution_context not in contexts:
        contexts.append(execution_context)
    device = device_info if device_info is not None else (
        _device_metadata(serial) if serial else previous.get("device")
    )
    doc = {
        "schema_version": 1,
        "generated_at": utcnow(),
        "package": surface.package,
        "app_version": {"name": surface.version_name, "code": surface.version_code},
        "sdk": {"min": surface.min_sdk, "target": surface.target_sdk,
                "device": device.get("sdk") if device else None},
        "apks": apks,
        "device": device,
        "execution_contexts": contexts,
        "configuration": options or previous.get("configuration", {}),
    }
    session_dir.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)
    return doc
