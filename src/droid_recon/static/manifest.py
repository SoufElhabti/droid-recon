"""AndroidManifest.xml -> AttackSurface.

Uses `apkanalyzer manifest print` (0.7s on an 18 MB APK) with an `aapt2 dump xmltree`
fallback. Deliberately does NOT need jadx — the whole attack surface is available in
under a second, so `droid-recon static` stays interactive.

Ported from android-privesc-hunt/scripts/pre-analyze.sh:55-180.
"""

from __future__ import annotations

import copy
import hashlib
import re
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Sequence
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

def resolve_apks(target: str | Path | Sequence[str | Path]) -> list[Path]:
    """Accept an APK, a split-set directory, or an explicit list of APK paths.

    Returns the likely base first for `install-multiple`; `analyze` verifies the actual
    base using each manifest's `split` attribute. An explicit list is useful when APKs
    come from different directories. No file is silently dropped from a supplied list.
    """
    if isinstance(target, Sequence) and not isinstance(target, (str, bytes, Path)):
        if not target:
            raise ValueError("no APK paths supplied")
        apks: list[Path] = []
        for item in target:
            p = Path(item).expanduser()
            if not p.is_file():
                raise ValueError(f"not an APK file: {p}")
            if not zipfile.is_zipfile(p):
                raise ValueError(f"not a valid APK (not a zip archive): {p}")
            apks.append(p)
        if len({p.resolve() for p in apks}) != len(apks):
            raise ValueError("duplicate APK paths supplied")
        return _base_first(apks)

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
        invalid = sorted(x for x in p.glob("*.apk") if x not in apks)
        if invalid:
            raise ValueError(f"directory contains an invalid APK file: {invalid[0]}")
        return _base_first(apks)

    raise ValueError(f"unsupported path type: {p}")


def _base_first(apks: list[Path]) -> list[Path]:
    """Filename heuristic only; manifest identity is checked in `analyze`."""
    return sorted(apks, key=lambda a: (
        a.name != "base.apk",
        a.name.startswith(("config.", "split_config.", "split_")),
        -a.stat().st_size,
        a.name,
    ))


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
        if proc.ok:
            try:
                if ET.fromstring(proc.stdout).tag == "manifest":
                    return proc.stdout
            except ET.ParseError:
                pass
        warn(f"apkanalyzer did not return a valid manifest for {apk.name} "
             f"(rc={proc.rc}), trying aapt2")

    aapt2 = shell.aapt2_path()
    if aapt2:
        proc = shell.run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)],
                         timeout=timeout)
        if proc.ok:
            xml = _xmltree_to_xml(proc.stdout)
            try:
                if ET.fromstring(xml).tag == "manifest":
                    return xml
            except ET.ParseError:
                pass

    raise ValueError(f"could not decode a valid AndroidManifest.xml from {apk} "
                     "(apkanalyzer/aapt2 unavailable or returned invalid output)")


_XMLTREE_EL = re.compile(r"^(\s*)E: ([\w:.-]+)")
_XMLTREE_AT = re.compile(
    r'^\s*A: (?:http://schemas.android.com/apk/res/android:)?(?P<name>[\w:.-]+)?'
    r'(?:\((?P<id>0x[0-9a-fA-F]+)\))?=(?:\(type [^)]+\))?'
    r'(?:(?:"(?P<quoted>(?:\\.|[^"\\])*)")|(?P<bare>\S+))'
)

# Recent SDK tools sometimes omit framework attribute names in decoded manifests.
# These public Android resource IDs cover every attribute consumed by parse_manifest.
# Resource IDs are stable across Android releases; unknown IDs are ignored rather
# than emitted as malformed/fictional XML attributes.
_ANDROID_ATTR_IDS = {
    "0x01010003": "name", "0x01010006": "permission",
    "0x01010007": "readPermission", "0x01010008": "writePermission",
    "0x01010009": "protectionLevel", "0x0101000b": "sharedUserId",
    "0x0101000e": "enabled", "0x0101000f": "debuggable",
    "0x01010010": "exported", "0x01010018": "authorities",
    "0x0101001b": "grantUriPermissions", "0x01010026": "mimeType",
    "0x01010027": "scheme", "0x01010028": "host",
    "0x01010029": "port", "0x0101002a": "path",
    "0x0101002b": "pathPrefix", "0x0101002c": "pathPattern",
    "0x01010202": "targetActivity", "0x0101020c": "minSdkVersion",
    "0x0101021b": "versionCode", "0x0101021c": "versionName",
    "0x01010270": "targetSdkVersion", "0x01010280": "allowBackup",
    "0x010104ec": "usesCleartextTraffic",
    "0x01010527": "networkSecurityConfig",
}


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
            name = a.group("name") or _ANDROID_ATTR_IDS.get((a.group("id") or "").lower())
            if not name:
                continue
            val = (a.group("quoted") if a.group("quoted") is not None
                   else a.group("bare")).strip()
            # `package` and `split` are unnamespaced manifest-root attributes.
            # Namespacing them hides the package and split identity from the parser.
            root_attr = stack and stack[-1][1] == "manifest" and name in {
                "package", "split", "platformBuildVersionCode", "platformBuildVersionName",
            }
            prefix = "" if ":" in name or root_attr else "android:"
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


def _qualified_component_name(name: str, package: str) -> str:
    if name.startswith("."):
        return package + name
    if "." not in name:
        return f"{package}.{name}"
    return name


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
    if not c.exported or not c.enabled:
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
        {n for tag in ("uses-permission", "uses-permission-sdk-23")
         for u in root.findall(tag) if (n := _attr(u, "name"))}
    )

    declared: dict[str, str] = {}
    for permission_el in root.findall("permission"):
        name = _attr(permission_el, "name")
        if not name:
            continue
        level = (_attr(permission_el, "protectionLevel") or "normal").lower()
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
    app_enabled = bool(_bool_attr(app, "enabled", True))
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
            name = _qualified_component_name(name, pkg)

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

            component_permission = _attr(el, "permission") or _attr(app, "permission")
            read_perm = _attr(el, "readPermission")
            write_perm = _attr(el, "writePermission")
            target_name = _attr(el, "targetActivity")

            comp = Component(
                name=name,
                type=ctype,
                exported=bool(inferred),
                exported_source=source,
                permission=component_permission,
                read_permission=read_perm,
                write_permission=write_perm,
                authorities=[a for a in (_attr(el, "authorities") or "").split(";") if a],
                grant_uri_permissions=bool(_bool_attr(el, "grantUriPermissions", False)),
                enabled=app_enabled and bool(_bool_attr(el, "enabled", True)),
                intent_filters=filters,
                target_activity=(_qualified_component_name(target_name, pkg)
                                 if target_name else None),
            )

            if ctype == "provider":
                # A provider has separate read and write gates. Path-specific guards
                # and temporary URI grants can change reach for individual URIs, so
                # these are conservative provider-wide candidates, not proof of access.
                read_guard = read_perm or component_permission
                write_guard = write_perm or component_permission
                comp.read_reachable_from = classify_reach(
                    exported=comp.exported, enabled=comp.enabled,
                    permission=read_guard,
                    permission_protection=_protection_of(read_guard, declared),
                )
                comp.write_reachable_from = classify_reach(
                    exported=comp.exported, enabled=comp.enabled,
                    permission=write_guard,
                    permission_protection=_protection_of(write_guard, declared),
                )
                # ContentProvider.call() has no framework read/write permission
                # check; its method must enforce access itself. Treat an exported
                # provider as a candidate until an ordinary-app test verifies it.
                comp.call_reachable_from = classify_reach(
                    exported=comp.exported, enabled=comp.enabled,
                    permission=None, permission_protection=None,
                )
                comp.reachable_from = comp.read_reachable_from
            else:
                comp.reachable_from = classify_reach(
                    exported=comp.exported, enabled=comp.enabled,
                    permission=component_permission,
                    permission_protection=_protection_of(component_permission, declared),
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


def _manifest_roots(apks: list[Path]) -> list[tuple[Path, ET.Element, str | None]]:
    roots: list[tuple[Path, ET.Element, str | None]] = []
    for apk in apks:
        try:
            root = ET.fromstring(dump_manifest_xml(apk))
        except ET.ParseError as exc:
            raise ValueError(f"invalid decoded manifest in {apk}: {exc}") from exc
        if root.tag != "manifest":
            raise ValueError(f"decoded manifest in {apk} has unexpected root {root.tag!r}")
        split = root.attrib.get("split") or _attr(root, "split") or None
        roots.append((apk, root, split))
    return roots


def _merged_manifest(
    roots: list[tuple[Path, ET.Element, str | None]],
) -> tuple[str, list[Path], dict[tuple[str, str], tuple[str, str | None]]]:
    """Combine base and feature declarations while retaining component provenance.

    Split manifests are *additive*: app-wide flags and SDK defaults come from the base,
    while declarations of permissions and components may arrive in any split. Parsing
    the combined XML once makes permission reachability consistent across splits.
    """
    bases = [entry for entry in roots if not entry[2]]
    if len(bases) != 1:
        raise ValueError(
            f"expected exactly one base APK manifest (without a split name), found {len(bases)}"
        )
    base_path, base_root, _ = bases[0]
    package = base_root.attrib.get("package", "")
    if not package:
        raise ValueError(f"base manifest has no package: {base_path}")
    ordered = [bases[0], *(entry for entry in roots if entry[2])]
    base_version = _int_attr(base_root, "versionCode")
    seen_splits: set[str] = set()
    origins: dict[tuple[str, str], tuple[str, str | None]] = {}
    merged = copy.deepcopy(base_root)
    merged_app = merged.find("application")

    # Names are unique within the installed package. A duplicate declaration makes
    # our effective exposure ambiguous, so fail instead of reporting either one.
    for apk, root, split in ordered:
        if root.attrib.get("package") != package:
            raise ValueError(
                f"APK package mismatch: {apk} declares {root.attrib.get('package')!r}; "
                f"base declares {package!r}"
            )
        version = _int_attr(root, "versionCode")
        if apk != base_path and version is not None and base_version is not None \
                and version != base_version:
            raise ValueError(
                f"APK versionCode mismatch: {apk} declares {version}; "
                f"base declares {base_version}"
            )
        if split:
            if split in seen_splits:
                raise ValueError(f"duplicate split name {split!r} in APK set")
            seen_splits.add(split)

        app = root.find("application")
        if app is None:
            continue
        for tag in _COMPONENT_TAGS:
            for component in app.findall(tag):
                raw_name = _attr(component, "name")
                if not raw_name:
                    continue
                name = _qualified_component_name(raw_name, package)
                key = (tag, name)
                if key in origins:
                    prev_apk, _ = origins[key]
                    raise ValueError(
                        f"duplicate {tag} {name} declared in {prev_apk} and {apk}"
                    )
                origins[key] = (str(apk), split)
                if apk == base_path:
                    continue
                if merged_app is None:
                    merged_app = ET.SubElement(merged, "application")
                added = copy.deepcopy(component)
                # A split's application permission is the default for its own
                # components if explicitly supplied there.
                split_permission = _attr(app, "permission")
                if split_permission and not _attr(added, "permission"):
                    added.set(ANDROID_NS + "permission", split_permission)
                merged_app.append(added)

    permission_defs: dict[str, str] = {}
    for permission_el in merged.findall("permission"):
        permission_name = _attr(permission_el, "name")
        if permission_name:
            permission_defs[permission_name] = (
                _attr(permission_el, "protectionLevel") or "normal"
            )
    for apk, root, split in ordered[1:]:
        for tag in ("uses-permission", "uses-permission-sdk-23"):
            for el in root.findall(tag):
                merged.append(copy.deepcopy(el))
        for el in root.findall("permission"):
            permission_name = _attr(el, "name")
            if not permission_name:
                continue
            level = _attr(el, "protectionLevel") or "normal"
            previous = permission_defs.get(permission_name)
            if previous is not None:
                def normalized(value: str) -> str:
                    return _decode_protection_flags(value) if value.startswith("0x") or value.isdigit() else value.lower()
                if normalized(previous) != normalized(level):
                    raise ValueError(
                        f"conflicting protectionLevel for {permission_name} in {apk}: "
                        f"{previous!r} vs {level!r}"
                    )
                continue
            permission_defs[permission_name] = level
            merged.append(copy.deepcopy(el))

    paths = [entry[0] for entry in ordered]
    return ET.tostring(merged, encoding="unicode"), paths, origins


def analyze(target: str | Path | Sequence[str | Path]) -> AttackSurface:
    """Analyze every manifest in a base APK and its supplied split APKs."""
    roots = _manifest_roots(resolve_apks(target))
    xml_text, apks, origins = _merged_manifest(roots)
    base = apks[0]
    say("static", f"manifest <- {base.name}" + (f" (+{len(apks) - 1} splits)" if len(apks) > 1 else ""))
    surface = parse_manifest(xml_text, apk_paths=apks)
    surface.apk_sha256s = {str(apk): sha256_of(apk) for apk in apks}
    surface.apk_sha256 = surface.apk_sha256s[str(base)]
    for component in surface.components:
        component.source_apk, component.source_split = origins[(component.type, component.name)]
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
