"""Version caveats qualify findings without treating a manifest entry as proof."""

from __future__ import annotations

from droid_recon.android_versions import device_api_level, version_caveats
from droid_recon.models import AttackSurface, Component, IntentFilter


def web_surface(*, scheme: str = "https", target: int | None = 34) -> AttackSurface:
    return AttackSurface(
        package="com.example.app", target_sdk=target, min_sdk=24,
        components=[Component(
            name="com.example.app.LinkActivity", type="activity", exported=True,
            reachable_from="browser", intent_filters=[IntentFilter(
                actions=["android.intent.action.VIEW"],
                categories=["android.intent.category.BROWSABLE"],
                data=[{"scheme": scheme, "host": "Example.Test"}],
            )],
        )],
    )


def by_id(caveats: list[dict]) -> dict[str, dict]:
    return {c["id"]: c for c in caveats}


def test_device_api_accepts_emulator_and_evidence_shapes():
    assert device_api_level({"sdk": "34"}) == 34
    assert device_api_level({"sdk": {"device": "36"}}) == 36
    assert device_api_level({"device": "34", "target": "35"}) == 34
    assert device_api_level({"api_level": 31}) == 31
    assert device_api_level({"sdk": "unknown"}) is None
    assert device_api_level({"sdk": "34"}, device_api="30") == 30
    assert device_api_level({"sdk": "34"}, device_api=True) is None


def test_evidence_sdk_block_selects_device_specific_caveats():
    caveats = by_id(version_caveats(web_surface(), {"device": "34", "target": "35"}))
    assert "device_api_unknown" not in caveats
    assert "web_app_links_approval_unknown" in caveats
    assert "On this Android 12+ device" in caveats["web_app_links_approval_unknown"]["message"]


def test_android12_web_links_are_conditional_on_domain_approval():
    caveats = by_id(version_caveats(web_surface(), {"sdk": "34"}))
    link = caveats["web_app_links_approval_unknown"]
    assert "Android 12+" in link["message"]
    assert "verification or user selection" in link["message"]
    assert "example.test" in link["message"]
    assert "not supplied" in link["message"]
    assert link["components"] == ["com.example.app.LinkActivity"]
    assert link["source"].startswith("https://developer.android.com/")
    assert "confirmed" not in link["message"].lower()


def test_older_and_unknown_devices_do_not_claim_android12_rule_is_active():
    old = by_id(version_caveats(web_surface(), device_api=30))
    assert "predates Android 12" in old["web_app_links_approval_unknown"]["message"]
    assert "android16_intent_redirection_hardening" not in old
    unknown = by_id(version_caveats(web_surface()))
    assert "device_api_unknown" in unknown
    assert "device API is unknown" in unknown["web_app_links_approval_unknown"]["message"]


def test_custom_scheme_does_not_get_http_app_links_caveat():
    caveats = by_id(version_caveats(web_surface(scheme="myapp"), device_api=34))
    assert "web_app_links_approval_unknown" not in caveats


def test_target31_implicit_export_and_backup_are_qualified():
    surface = web_surface(target=31)
    surface.components[0].exported_source = "inferred-from-intent-filter"
    surface.allow_backup = True
    caveats = by_id(version_caveats(surface, {"sdk": "31"}))
    assert "android12_explicit_export_required" in caveats
    assert caveats["android12_explicit_export_required"]["components"] == [
        "com.example.app.LinkActivity"]
    assert "install" in caveats["android12_explicit_export_required"]["message"]
    assert "android12_adb_backup_restricted" in caveats
    assert "does not prove" in caveats["android12_adb_backup_restricted"]["message"]


def test_android16_caveats_avoid_claiming_opt_in_or_exploit():
    caveats = by_id(version_caveats(web_surface(target=36), device_api=36))
    assert "android16_intent_redirection_hardening" in caveats
    assert "android16_strict_intent_matching_unknown" in caveats
    assert "unknown" in caveats["android16_strict_intent_matching_unknown"]["message"]
    older_target = by_id(version_caveats(web_surface(target=35), device_api=36))
    assert "android16_intent_redirection_hardening" in older_target
    assert "android16_strict_intent_matching_unknown" not in older_target


def test_unknown_target_and_incompatible_min_sdk_are_reported():
    surface = web_surface(target=None)
    surface.min_sdk = 35
    caveats = by_id(version_caveats(surface, device_api=34))
    assert "target_sdk_unknown" in caveats
    assert "device_below_min_sdk" in caveats
    assert "normally" not in caveats["device_below_min_sdk"]["message"]  # precise wording
    assert "should be rejected" in caveats["device_below_min_sdk"]["message"]
