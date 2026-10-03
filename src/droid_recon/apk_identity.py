"""Compare cached analysis inputs without accepting stale split APK reports."""

from __future__ import annotations

from .models import AttackSurface


def same_surface(saved: AttackSurface, current: AttackSurface) -> bool:
    if saved.apk_sha256s and current.apk_sha256s:
        return saved.apk_sha256s == current.apk_sha256s
    return saved.apk_sha256 == current.apk_sha256 and not (
        len(saved.apk_sha256s) > 1 or len(current.apk_sha256s) > 1
    )


def report_matches_apks(report: dict, surface: AttackSurface) -> bool:
    hashes = report.get("apk_sha256s")
    if hashes and surface.apk_sha256s:
        return hashes == surface.apk_sha256s
    # Legacy single-APK reports remain usable. A base-only hash cannot prove that
    # feature APKs are unchanged, so never use it for a split set.
    return (len(surface.apk_sha256s) <= 1 and
            report.get("apk_sha256") == surface.apk_sha256)
