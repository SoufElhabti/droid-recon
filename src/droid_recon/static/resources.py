"""FileProvider path configs and network security config.

Ported from android-privesc-hunt/scripts/pre-analyze.sh:181-195.

A FileProvider whose <root-path path="/"/> is declared is a classic arbitrary-file-read
primitive, and the declaration lives in a res/xml/ file, not the manifest — so this needs
the resource tree (apktool) rather than just the decoded manifest.
"""

from __future__ import annotations

import hashlib
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

from .. import shell
from ..log import say, warn

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Tags in a FileProvider paths XML, mapped to the real directory they expose.
_PATH_TAGS = {
    "root-path": "/  (device filesystem root)",
    "files-path": "<app>/files",
    "cache-path": "<app>/cache",
    "external-path": "external storage root",
    "external-files-path": "external <app>/files",
    "external-cache-path": "external <app>/cache",
    "external-media-path": "external media",
}

# Declarations that expose more than the app's own sandbox.
_DANGEROUS = {"root-path", "external-path", "external-media-path"}

APKTOOL_TIMEOUT = 600


def extract_resources(apk: Path, dest: Path, *, force: bool = False) -> Path | None:
    """Decode resources with apktool (`-s` skips dex, so it is fast)."""
    marker = dest / ".droid-recon-res"
    if marker.exists() and not force:
        return dest

    apktool = shell.which("apktool")
    if not apktool:
        warn("apktool not found — skipping FileProvider path analysis")
        return None

    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    say("static", f"apktool decoding resources from {apk.name}")
    proc = shell.run(
        [apktool, "d", "-q", "-f", "-s", "-o", str(dest), str(apk)], timeout=APKTOOL_TIMEOUT
    )
    if not dest.is_dir():
        warn(f"apktool failed (rc={proc.rc}) — skipping resource analysis")
        return None
    marker.write_text(str(apk), encoding="utf-8")
    return dest


def find_fileprovider_paths(res_root: Path) -> list[dict]:
    """Parse every res/xml/*.xml that looks like a FileProvider paths declaration."""
    out: list[dict] = []
    xml_dir = res_root / "res" / "xml"
    if not xml_dir.is_dir():
        return out

    for xml_file in sorted(xml_dir.glob("*.xml")):
        try:
            root = ET.parse(xml_file).getroot()
        except (ET.ParseError, OSError):
            continue
        if root.tag != "paths":
            continue
        for child in root:
            if child.tag not in _PATH_TAGS:
                continue
            name = child.attrib.get(ANDROID_NS + "name") or child.attrib.get("name") or ""
            path = child.attrib.get(ANDROID_NS + "path") or child.attrib.get("path") or ""
            entry = {
                "file": str(xml_file.relative_to(res_root)),
                "type": child.tag,
                "name": name,
                "path": path,
                "exposes": _PATH_TAGS[child.tag],
                "dangerous": child.tag in _DANGEROUS or path.strip() in ("/", "."),
            }
            if entry["dangerous"]:
                entry["why"] = (
                    f"<{child.tag} path=\"{path}\"/> exposes storage outside the app sandbox; "
                    f"combined with an exported provider this is an arbitrary-file-read primitive"
                )
            out.append(entry)
    return out


def find_network_security_config(res_root: Path) -> dict | None:
    """Look for cleartext / user-CA trust in the network security config."""
    xml_dir = res_root / "res" / "xml"
    if not xml_dir.is_dir():
        return None
    for xml_file in sorted(xml_dir.glob("*.xml")):
        try:
            root = ET.parse(xml_file).getroot()
        except (ET.ParseError, OSError):
            continue
        if root.tag != "network-security-config":
            continue
        issues = []
        text = xml_file.read_text(encoding="utf-8", errors="ignore")
        if 'cleartextTrafficPermitted="true"' in text:
            issues.append("cleartextTrafficPermitted=true — plaintext HTTP allowed")
        if 'src="user"' in text:
            issues.append('trust-anchors src="user" — trusts user-installed CAs (MITM-friendly)')
        if "<debug-overrides" in text:
            issues.append("<debug-overrides> present")
        return {"file": str(xml_file.relative_to(res_root)), "issues": issues}
    return None


def analyze_all(apks: list[Path], cache_root: Path, *, force: bool = False) -> dict:
    """Decode every split and retain the APK provenance of resource findings."""
    paths: list[dict] = []
    network_configs: list[dict] = []
    status: list[dict] = []
    for apk in apks:
        hasher = hashlib.sha256()
        with apk.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                hasher.update(block)
        digest = hasher.hexdigest()[:16]
        root = extract_resources(apk, cache_root / digest, force=force)
        if root is None:
            status.append({"apk": str(apk), "status": "unsupported",
                           "reason": "apktool unavailable or resource decode failed"})
            continue
        status.append({"apk": str(apk), "status": "tested"})
        for entry in find_fileprovider_paths(root):
            paths.append({**entry, "source_apk": str(apk)})
        network = find_network_security_config(root)
        if network:
            network_configs.append({**network, "source_apk": str(apk)})
    return {"fileprovider_paths": paths, "network_configs": network_configs,
            "status": status}
