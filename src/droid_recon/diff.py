"""Compare the externally reachable surface of two APK releases."""

from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path

from .models import AttackSurface, Component


def _component_key(component: Component) -> str:
    return f"{component.type}:{component.name}"


def _component_view(component: Component) -> dict:
    return {
        "type": component.type,
        "name": component.name,
        "exported": component.exported,
        "enabled": component.enabled,
        "reachable_from": component.reachable_from,
        "publicly_reachable": component.publicly_reachable,
        "provider_reach": ({operation: component.provider_reach(operation)
                            for operation in ("read", "write", "call")}
                           if component.type == "provider" else None),
        "permission": component.permission,
        "read_permission": component.read_permission,
        "write_permission": component.write_permission,
        "authorities": sorted(component.authorities),
        "deeplinks": sorted(component.deeplinks()),
        "actions": sorted({a for f in component.intent_filters for a in f.actions}),
    }


def _packaged_artifacts(surface: AttackSurface) -> dict[str, str]:
    """Hash shipped code and native assets without claiming dependency identity."""
    found: dict[str, str] = {}
    for raw in surface.apk_paths:
        apk = Path(raw)
        if not apk.is_file() or not zipfile.is_zipfile(apk):
            continue
        with zipfile.ZipFile(apk) as archive:
            for member in archive.infolist():
                name = member.filename
                selected = (bool(re.fullmatch(r"classes\d*\.dex", name)) or
                            (name.startswith("lib/") and name.endswith(".so")) or
                            name.endswith(".bundle") or name.endswith(".jar"))
                if not selected or member.is_dir():
                    continue
                digest = hashlib.sha256()
                with archive.open(member) as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(block)
                found[f"{apk.name}:{name}"] = digest.hexdigest()
    return found


def compare(before: AttackSurface, after: AttackSurface) -> dict:
    """Return deterministic changes; this is a difference, not a vulnerability verdict."""
    if before.package != after.package:
        raise ValueError(
            f"cannot compare different packages: {before.package} != {after.package}"
        )
    old = {_component_key(c): _component_view(c) for c in before.components}
    new = {_component_key(c): _component_view(c) for c in after.components}
    added = {key: new[key] for key in sorted(new.keys() - old.keys())}
    removed = {key: old[key] for key in sorted(old.keys() - new.keys())}
    changed = {}
    for key in sorted(old.keys() & new.keys()):
        differences = {
            field: {"before": old[key][field], "after": new[key][field]}
            for field in old[key]
            if old[key][field] != new[key][field]
        }
        if differences:
            changed[key] = differences

    newly_reachable = [
        key for key in sorted(new) if new[key]["publicly_reachable"]
        and not old.get(key, {}).get("publicly_reachable", False)
    ]
    third_party = {"third_party_app", "browser"}
    newly_reachable_operations = [
        f"{key}:{operation}"
        for key in sorted(new)
        if new[key]["type"] == "provider"
        for operation, reach in new[key]["provider_reach"].items()
        if reach in third_party and
        (old.get(key, {}).get("provider_reach") or {}).get(operation) not in third_party
    ]
    app_fields = ("target_sdk", "min_sdk", "debuggable", "allow_backup",
                  "uses_cleartext_traffic", "network_security_config",
                  "uses_permissions", "native_libs")
    app_changes = {
        field: {"before": getattr(before, field), "after": getattr(after, field)}
        for field in app_fields
        if getattr(before, field) != getattr(after, field)
    }
    old_artifacts = _packaged_artifacts(before)
    new_artifacts = _packaged_artifacts(after)
    shipped_changes = {
        "added": sorted(new_artifacts.keys() - old_artifacts.keys()),
        "removed": sorted(old_artifacts.keys() - new_artifacts.keys()),
        "changed": sorted(key for key in old_artifacts.keys() & new_artifacts.keys()
                          if old_artifacts[key] != new_artifacts[key]),
    }
    return {
        "package": before.package,
        "before": {"version_name": before.version_name,
                   "version_code": before.version_code, "apk_sha256": before.apk_sha256},
        "after": {"version_name": after.version_name,
                  "version_code": after.version_code, "apk_sha256": after.apk_sha256},
        "added_components": added,
        "removed_components": removed,
        "changed_components": changed,
        "newly_reachable": sorted(newly_reachable),
        "newly_reachable_operations": newly_reachable_operations,
        "application_changes": app_changes,
        "shipped_code_and_library_changes": shipped_changes,
        "dependency_note": "Binary changes do not identify the dependency or its version.",
    }
