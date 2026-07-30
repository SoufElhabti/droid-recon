"""AndroidManifest.xml -> AttackSurface.

Uses `apkanalyzer manifest print` (0.7s on an 18 MB APK) with an `aapt2 dump xmltree`
fallback. Deliberately does NOT need jadx — the whole attack surface is available in
under a second, so `droid-recon static` stays interactive.

Ported from android-privesc-hunt/scripts/pre-analyze.sh:55-180.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from .. import shell
from ..log import say, warn
from ..models import (
    AttackSurface,
    Component,
    ComponentType,
    DeclaredPermission,
    IntentFilter,
    classify_reach,
)

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

_COMPONENT_TAGS: dict[str, ComponentType] = {
    "activity": "activity",
    "activity-alias": "activity-alias",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}

# Protection levels every third-party app can hold.
_WEAK_PROTECTIONS = ("normal", "dangerous")


def _attr(el: ET.Element, name: str) -> str | None:
    return el.attrib.get(ANDROID_NS + name) or el.attrib.get(name)


def _bool_attr(el: ET.Element, name: str, default: bool | None = None) -> bool | None:
    raw = _attr(el, name)
    if raw is None:
        return default
    return raw.strip().lower() in ("true", "1", "0xffffffff", "-1")


def _int_attr(el: ET.Element, name: str) -> int | None:
    raw = _attr(el, name)
    if raw is None:
        return None
    raw = raw.strip()
    try:
        return int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    except ValueError:
        return None


# ---- APK input resolution ----

def resolve_apks(target: str | Path) -> list[Path]:
    """Accept a single APK, or a directory containing a base + `config.*.apk` split set.

    Returns base-first so `install-multiple` gets a sane order. Raises ValueError with a
    readable message rather than a traceback — extracted-APK *directories* are a real
    thing on this machine and must not crash the tool.
    """
    p = Path(target).expanduser()
    if not p.exists():
        raise ValueError(f"no such path: {p}")

    if p.is_file():
        if not zipfile.is_zipfile(p):
            raise ValueError(f"not a valid APK (not a zip archive): {p}")
        return [p]

    if p.is_dir():
        apks = sorted(x for x in p.glob("*.apk") if zipfile.is_zipfile(x))
        if not apks:
            raise ValueError(
                f"directory contains no valid APK files: {p}\n"
                f"    (an *extracted* APK directory is not an APK — point at the .apk file)"
            )
        base = [a for a in apks if not a.name.startswith("config.")]
        splits = [a for a in apks if a.name.startswith("config.")]
        # Prefer a file literally named base.apk, else the largest non-config apk.
        base.sort(key=lambda a: (a.name != "base.apk", -a.stat().st_size))
        return base + splits

    raise ValueError(f"unsupported path type: {p}")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---- manifest extraction ----

def dump_manifest_xml(apk: Path, timeout: int = 120) -> str:
    """Decoded AndroidManifest.xml text. apkanalyzer first, aapt2 fallback."""
    apkanalyzer = shell.which("apkanalyzer", "cmdline-tools/latest/bin/apkanalyzer")
    if apkanalyzer:
        proc = shell.run([apkanalyzer, "manifest", "print", str(apk)], timeout=timeout)
        if proc.ok and proc.stdout.lstrip().startswith("<"):
            return proc.stdout
        warn(f"apkanalyzer failed on {apk.name} (rc={proc.rc}), trying aapt2")

    aapt2 = shell.aapt2_path()
    if aapt2:
        proc = shell.run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)],
                         timeout=timeout)
        if proc.ok:
            return _xmltree_to_xml(proc.stdout)

    raise ValueError(f"could not decode AndroidManifest.xml from {apk} (no apkanalyzer/aapt2)")


_XMLTREE_EL = re.compile(r"^(\s*)E: ([\w:.-]+)")
_XMLTREE_AT = re.compile(r'^\s*A: (?:http://schemas.android.com/apk/res/android:)?([\w:.-]+)'
                         r'(?:\(0x[0-9a-f]+\))?=(?:\(type [^)]+\))?"?([^"\n]*)"?')


def _xmltree_to_xml(dump: str) -> str:
    """Minimal `aapt2 dump xmltree` -> XML. Fallback path only."""
    out = ['<?xml version="1.0" encoding="utf-8"?>']
    stack: list[tuple[int, str]] = []
    pending: list[str] | None = None
    ns = ' xmlns:android="http://schemas.android.com/apk/res/android"'
    first = True

    def close_to(indent: int) -> None:
        while stack and stack[-1][0] >= indent:
            _, tag = stack.pop()
            out.append(f"</{tag}>")

    for line in dump.splitlines():
        m = _XMLTREE_EL.match(line)
        if m:
            if pending is not None:
                out.append("".join(pending) + ">")
                pending = None
            indent, tag = len(m.group(1)), m.group(2)
            close_to(indent)
            stack.append((indent, tag))
            pending = [f"<{tag}{ns if first else ''}"]
            first = False
            continue
        a = _XMLTREE_AT.match(line)
        if a and pending is not None:
            name, val = a.group(1), a.group(2).strip()
            prefix = "" if ":" in name else "android:"
            val = val.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
            pending.append(f' {prefix}{name}="{val}"')
    if pending is not None:
        out.append("".join(pending) + ">")
    close_to(-1)
    return "\n".join(out)


# ---- parsing ----

def _parse_intent_filters(el: ET.Element) -> list[IntentFilter]:
    filters = []
    for f in el.findall("intent-filter"):
        actions = [n for a in f.findall("action") if (n := _attr(a, "name"))]
        cats = [n for c in f.findall("category") if (n := _attr(c, "name"))]
        data = []
        for d in f.findall("data"):
            entry = {
                k: v
                for k in ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType")
                if (v := _attr(d, k))
            }
            if entry:
                data.append(entry)
        filters.append(IntentFilter(actions=actions, categories=cats, data=data))
    return filters


def _protection_of(name: str | None, declared: dict[str, str]) -> str | None:
    """Resolve a permission name to its protectionLevel.

    Own declarations first, then the platform table. An unresolvable custom permission
    returns None, which classify_reach treats as *not* signature-gated — the
    defender-pessimistic default.
    """
    if not name:
        return None
    if name in declared:
        return declared[name]
    if name.startswith("android.permission."):
        return _PLATFORM_PROTECTION.get(name, "signature")
    return None


# Coarse platform permission table: only the distinction "any app can hold it" vs not.
_PLATFORM_PROTECTION: dict[str, str] = {
    "android.permission.INTERNET": "normal",
    "android.permission.ACCESS_NETWORK_STATE": "normal",
    "android.permission.VIBRATE": "normal",
    "android.permission.WAKE_LOCK": "normal",
    "android.permission.FOREGROUND_SERVICE": "normal",
    "android.permission.RECEIVE_BOOT_COMPLETED": "normal",
    "android.permission.READ_EXTERNAL_STORAGE": "dangerous",
    "android.permission.WRITE_EXTERNAL_STORAGE": "dangerous",
    "android.permission.CAMERA": "dangerous",
    "android.permission.RECORD_AUDIO": "dangerous",
    "android.permission.ACCESS_FINE_LOCATION": "dangerous",
    "android.permission.ACCESS_COARSE_LOCATION": "dangerous",
    "android.permission.READ_CONTACTS": "dangerous",
    "android.permission.READ_PHONE_STATE": "dangerous",
    "android.permission.POST_NOTIFICATIONS": "dangerous",
    "android.permission.QUERY_ALL_PACKAGES": "normal",
    "android.permission.REQUEST_INSTALL_PACKAGES": "signature",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "signature",
}


def _component_issues(c: Component, surface_pkg: str) -> list[str]:
    """Manifest-level red flags. Ported from pre-analyze.sh component issue rules."""
    issues: list[str] = []
    if not c.exported:
        return issues

    if c.type == "provider":
        if not c.read_permission and not c.write_permission and not c.permission:
            issues.append("exported provider with NO permission (readable+writable by any app)")
        elif c.read_permission and not c.write_permission and not c.permission:
            issues.append("exported provider guarded on read only — writes are unprotected")
        elif c.write_permission and not c.read_permission and not c.permission:
            issues.append("exported provider guarded on write only — reads are unprotected")
        if c.grant_uri_permissions:
            issues.append("grantUriPermissions=true — URI grants can escape the provider's guard")
    elif not c.permission:
        issues.append(f"exported {c.type} with no permission guard")

    if c.browsable:
        issues.append("BROWSABLE — reachable from a web page via an <a href> / iframe")
    if c.send_target:
        issues.append("accepts ACTION_SEND — Dirty Stream / cross-app content injection surface")
    if c.type == "activity-alias" and c.target_activity:
        issues.append(f"activity-alias exposing {c.target_activity}")
    return issues


def parse_manifest(xml_text: str, apk_paths: list[Path] | None = None) -> AttackSurface:
    root = ET.fromstring(xml_text)
    pkg = root.attrib.get("package", "")

    surface = AttackSurface(
        package=pkg,
        apk_paths=[str(p) for p in (apk_paths or [])],
        version_name=_attr(root, "versionName"),
        version_code=_int_attr(root, "versionCode"),
        shared_user_id=_attr(root, "sharedUserId"),
    )

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        surface.min_sdk = _int_attr(uses_sdk, "minSdkVersion")
        surface.target_sdk = _int_attr(uses_sdk, "targetSdkVersion")
    surface.min_sdk = surface.min_sdk or _int_attr(root, "minSdkVersion")
    surface.target_sdk = surface.target_sdk or _int_attr(root, "targetSdkVersion")

    surface.uses_permissions = sorted(
        {n for u in root.findall("uses-permission") if (n := _attr(u, "name"))}
    )

    declared: dict[str, str] = {}
    for perm in root.findall("permission"):
        name = _attr(perm, "name")
        if not name:
            continue
        level = (_attr(perm, "protectionLevel") or "normal").lower()
        # aapt2/apkanalyzer sometimes emit the raw flag int.
        if level.startswith("0x") or level.isdigit():
            level = _decode_protection_flags(level)
        declared[name] = level
        surface.declared_permissions.append(DeclaredPermission(name=name, protection_level=level))
        if any(w in level for w in _WEAK_PROTECTIONS) and "signature" not in level:
            surface.permission_misconfigs.append(
                {
                    "permission": name,
                    "protectionLevel": level,
                    "why": "custom permission any third-party app can request and be granted",
                }
            )

    app = root.find("application")
    if app is None:
        return surface

    surface.debuggable = bool(_bool_attr(app, "debuggable", False))
    surface.allow_backup = bool(_bool_attr(app, "allowBackup", True))
    surface.uses_cleartext_traffic = _bool_attr(app, "usesCleartextTraffic", None)
    surface.network_security_config = _attr(app, "networkSecurityConfig")

    if surface.debuggable:
        surface.app_issues.append("android:debuggable=true — any local process can attach a debugger")
    if surface.allow_backup:
        surface.app_issues.append("android:allowBackup=true — app data extractable via `adb backup`")
    if surface.uses_cleartext_traffic:
        surface.app_issues.append("usesCleartextTraffic=true — plaintext HTTP permitted")
    if surface.shared_user_id:
        surface.app_issues.append(
            f"sharedUserId={surface.shared_user_id} — shares a UID/data sandbox with sibling apps"
        )

    for tag, ctype in _COMPONENT_TAGS.items():
        for el in app.findall(tag):
            name = _attr(el, "name")
            if not name:
                continue
            if name.startswith("."):
                name = pkg + name
            elif "." not in name:
                name = f"{pkg}.{name}"

            filters = _parse_intent_filters(el)
            explicit = _bool_attr(el, "exported", None)
            if explicit is None:
                # Providers default exported=true only below targetSdk 17; every modern
                # APK is above that, so absence means false for providers. For the other
                # component types, an intent-filter implies exported.
                if ctype == "provider":
                    inferred = (surface.target_sdk or 0) < 17
                    source = "default-by-targetsdk"
                else:
                    inferred = bool(filters)
                    source = "inferred-from-intent-filter" if filters else "default"
            else:
                inferred, source = explicit, "explicit"

            perm = _attr(el, "permission")
            read_perm = _attr(el, "readPermission")
            write_perm = _attr(el, "writePermission")

            comp = Component(
                name=name,
                type=ctype,
                exported=bool(inferred),
                exported_source=source,
                permission=perm,
                read_permission=read_perm,
                write_permission=write_perm,
                authorities=[a for a in (_attr(el, "authorities") or "").split(";") if a],
                grant_uri_permissions=bool(_bool_attr(el, "grantUriPermissions", False)),
                enabled=bool(_bool_attr(el, "enabled", True)),
                intent_filters=filters,
                target_activity=_attr(el, "targetActivity"),
            )

            # For providers, the effective read guard is readPermission or permission.
            guard = read_perm or perm if ctype == "provider" else perm
            comp.reachable_from = classify_reach(
                exported=comp.exported,
                permission=guard,
                permission_protection=_protection_of(guard, declared),
                browsable=comp.browsable,
            )
            comp.issues = _component_issues(comp, pkg)
            surface.components.append(comp)

    return surface


_PROTECTION_BITS = {
    0x0: "normal",
    0x1: "dangerous",
    0x2: "signature",
    0x3: "signatureOrSystem",
}


def _decode_protection_flags(raw: str) -> str:
    try:
        val = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    except ValueError:
        return raw
    base = _PROTECTION_BITS.get(val & 0xF, "normal")
    extras = []
    if val & 0x10:
        extras.append("privileged")
    if val & 0x40:
        extras.append("development")
    if val & 0x400:
        extras.append("instant")
    if val & 0x10000:
        extras.append("internal")
    return "|".join([base, *extras])


def analyze(target: str | Path) -> AttackSurface:
    """Full static manifest pass over an APK path or split-set directory."""
    apks = resolve_apks(target)
    base = apks[0]
    say("static", f"manifest <- {base.name}" + (f" (+{len(apks) - 1} splits)" if len(apks) > 1 else ""))
    xml_text = dump_manifest_xml(base)
    surface = parse_manifest(xml_text, apk_paths=apks)
    surface.apk_sha256 = sha256_of(base)
    surface.native_libs = _native_libs(apks)
    return surface


def _native_libs(apks: list[Path]) -> list[str]:
    libs: set[str] = set()
    for apk in apks:
        try:
            with zipfile.ZipFile(apk) as zf:
                for n in zf.namelist():
                    if n.startswith("lib/") and n.endswith(".so"):
                        libs.add(n.split("/")[-1])
        except (zipfile.BadZipFile, OSError):
            continue
    return sorted(libs)
