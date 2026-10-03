"""Preserve old audit runs and validate resumptions against their inputs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

from .models import AttackSurface, utcnow
from .session import Session

_OPTIONS = (
    "type", "limit", "screenshots", "traversal", "include_shell_only",
    "provider_fallbacks", "no_install", "reinstall", "no_logcat", "no_storage",
    "skip_code", "no_resources", "max_payloads", "max_screens", "max_depth",
    "avd", "serial", "no_agent", "deep", "explore", "reset_app_data",
    "force", "timeout", "top", "provider_method",
)


def configuration(args: object) -> dict:
    """Only reproducibility settings, never passwords or API keys."""
    config = {key: getattr(args, key) for key in _OPTIONS if hasattr(args, key)}
    config["test_account_requested"] = bool(
        getattr(args, "credentials", None) or
        (getattr(args, "username", None) and getattr(args, "password", None))
    )
    companion = getattr(args, "companion_apk", None)
    if companion:
        path = Path(companion).expanduser()
        digest = hashlib.sha256()
        if path.is_file():
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1 << 20), b""):
                    digest.update(chunk)
            config["companion_apk"] = {"name": path.name, "sha256": digest.hexdigest()}
        else:
            config["companion_apk"] = {"name": path.name, "status": "missing"}
    return config


def _signature(surface: AttackSurface, config: dict) -> str:
    payload = {"apk_sha256s": surface.apk_sha256s or {"base": surface.apk_sha256},
               "configuration": config}
    data = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def prepare(session: Session, surface: AttackSurface, args: object, *, resume: bool) -> dict:
    """Start a run or resume the active one; archive rather than erase old artifacts."""
    path = session.dir / "run_manifest.json"
    config = configuration(args)
    signature = _signature(surface, config)
    if resume:
        if not path.is_file():
            raise ValueError("no active run to resume")
        current = json.loads(path.read_text(encoding="utf-8"))
        if current.get("signature") != signature:
            raise ValueError("APK set or audit options differ from the active run")
        return current

    existing = [child for child in session.dir.iterdir() if child.name != "runs"]
    # Session() creates these directories even when no previous run exists.
    meaningful = [child for child in existing
                  if child.is_file() or (child.is_dir() and any(child.iterdir()))]
    if meaningful:
        archive = session.dir / "runs" / uuid4().hex
        archive.mkdir(parents=True)
        root = session.dir.resolve()
        if archive.resolve().parent != (root / "runs").resolve():
            raise ValueError("archive path escaped the session directory")
        for child in existing:
            if child.exists():
                child.rename(archive / child.name)
        (session.dir / "screenshots").mkdir(exist_ok=True)
        (session.dir / "storage").mkdir(exist_ok=True)

    doc = {
        "schema_version": 1,
        "run_id": uuid4().hex,
        "started_at": utcnow(),
        "package": surface.package,
        "apk_sha256s": surface.apk_sha256s or {"base": surface.apk_sha256},
        "configuration": config,
        "signature": signature,
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return doc


def bind_device(session: Session, serial: str) -> None:
    """Resume only on the same device once runtime probing has started."""
    path = session.dir / "run_manifest.json"
    run = json.loads(path.read_text(encoding="utf-8"))
    saved = run.get("device_serial")
    if saved and saved != serial:
        raise ValueError(f"active run used device {saved}, current device is {serial}")
    if not saved:
        run["device_serial"] = serial
        path.write_text(json.dumps(run, indent=2), encoding="utf-8")
