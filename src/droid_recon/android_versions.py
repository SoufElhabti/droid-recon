"""Android-version caveats for interpreting a static attack-surface inventory.

These are conditional platform rules, not vulnerability findings. In particular,
the manifest cannot tell us a device's App Links verification/user-selection state,
and a device's API level is not interchangeable with an app's targetSdkVersion.
Sources are official Android developer documentation, linked in each caveat.
"""

from __future__ import annotations

from typing import Any

from .models import AttackSurface

ANDROID_12_ALL = "https://developer.android.com/about/versions/12/behavior-changes-all"
ANDROID_12_TARGET = "https://developer.android.com/about/versions/12/behavior-changes-12"
APP_LINKS = "https://developer.android.com/training/app-links/verify-applinks"
ANDROID_16_ALL = "https://developer.android.com/about/versions/16/behavior-changes-all"
ANDROID_16_TARGET = "https://developer.android.com/about/versions/16/behavior-changes-16"
USES_SDK = "https://developer.android.com/guide/topics/manifest/uses-sdk-element"


def _positive_api(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (ValueError, TypeError):
        return None
    return parsed if parsed > 0 else None


def device_api_level(device_info: dict | None = None, *, device_api: int | str | None = None
                     ) -> int | None:
    """Read a device API from `emulator.device_info` or an evidence SDK block."""
    if device_api is not None:
        return _positive_api(device_api)
    if not isinstance(device_info, dict):
        return None
    for key in ("api_level", "device_api", "device", "sdk", "api"):
        value = device_info.get(key)
        if isinstance(value, dict):
            value = value.get("device")
        parsed = _positive_api(value)
        if parsed is not None:
            return parsed
    return None


def _web_link_hosts(surface: AttackSurface) -> tuple[list[str], list[str]]:
    hosts: set[str] = set()
    components: set[str] = set()
    for comp in surface.components:
        if not comp.browsable:
            continue
        for intent_filter in comp.intent_filters:
            if not intent_filter.browsable:
                continue
            for data in intent_filter.data:
                if data.get("scheme", "").lower() in ("http", "https"):
                    components.add(comp.name)
                    if data.get("host"):
                        hosts.add(data["host"].lower())
    return sorted(hosts), sorted(components)


def version_caveats(surface: AttackSurface, device_info: dict | None = None, *,
                    device_api: int | str | None = None) -> list[dict]:
    """Return concise, sourced caveats for this app/device combination.

    `device_info` may be the `emulator.device_info()` result (`sdk` is a string),
    or an evidence SDK block. Unknown device or target versions stay unknown; this
    function never upgrades a candidate surface to a confirmed exploit.
    """
    api = device_api_level(device_info, device_api=device_api)
    target = _positive_api(surface.target_sdk)
    caveats: list[dict] = []

    def add(caveat_id: str, message: str, source: str, *,
            components: list[str] | None = None) -> None:
        item: dict = {"id": caveat_id, "message": message, "source": source}
        if components:
            item["components"] = components[:12]
        caveats.append(item)

    if api is None:
        add("device_api_unknown",
            "Device API level is unknown; runtime rules cannot be selected for this audit.",
            USES_SDK)
    if target is None:
        add("target_sdk_unknown",
            "The app targetSdkVersion is unknown; target-dependent platform rules remain unverified.",
            ANDROID_12_TARGET)
    if api is not None and surface.min_sdk is not None and api < surface.min_sdk:
        add("device_below_min_sdk",
            f"Device API {api} is below minSdkVersion {surface.min_sdk}; a normal install "
            "should be rejected, so runtime results on this device need investigation.",
            USES_SDK)

    implicit_exports = sorted(c.name for c in surface.components
                              if c.type in ("activity", "activity-alias", "service", "receiver")
                              and c.intent_filters
                              and c.exported_source == "inferred-from-intent-filter")
    if target is not None and target >= 31 and implicit_exports:
        add("android12_explicit_export_required",
            "This app targets API 31+ but these filtered components do not explicitly "
            "declare android:exported. Android 12+ normally rejects installation; "
            "their inferred reachability needs an install check.",
            ANDROID_12_TARGET, components=implicit_exports)

    hosts, web_components = _web_link_hosts(surface)
    if web_components:
        sample = ", ".join(hosts[:5]) if hosts else "an unspecified host"
        if api is None:
            detail = ("The device API is unknown. On Android 12+, generic HTTP(S) "
                      "links open this app only for domains approved by verification "
                      "or user selection.")
        elif api >= 31:
            detail = ("On this Android 12+ device, generic HTTP(S) links open this app "
                      "only for domains approved by verification or user selection.")
        else:
            detail = ("This device predates Android 12. Retest generic HTTP(S) link "
                      "routing on API 31+ because domain-approval rules differ.")
        add("web_app_links_approval_unknown",
            f"{detail} Manifest filters mention {sample}; approval state was not supplied. "
            "Check the device's App Links state before claiming browser delivery.",
            ANDROID_12_ALL, components=web_components)

    if surface.allow_backup and target is not None and target >= 31 and (api is None or api >= 31):
        add("android12_adb_backup_restricted",
            "android:allowBackup alone does not prove adb backup can extract app data. "
            "For apps targeting API 31+ on Android 12+, app data is excluded by default "
            "unless a documented exception applies; extraction was not verified here.",
            ANDROID_12_TARGET)

    ipc_candidates = any(c.enabled and c.publicly_reachable
                         and c.type in ("activity", "activity-alias", "receiver", "service")
                         for c in surface.components)
    if api is not None and api >= 36 and ipc_candidates:
        add("android16_intent_redirection_hardening",
            "Android 16 applies default protection to some nested Intent redirection "
            "paths. A blocked probe on this device does not establish how the same app "
            "behaves on older Android versions or whether app code opts out.",
            ANDROID_16_ALL)
    if api is not None and api >= 36 and target is not None and target >= 36 and ipc_candidates:
        add("android16_strict_intent_matching_unknown",
            "Android 16 offers opt-in strict matching for cross-app Intents. This inventory "
            "does not record intentMatchingFlags, so whether the app enabled it is unknown.",
            ANDROID_16_TARGET)

    return caveats
