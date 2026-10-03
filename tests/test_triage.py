"""The false-positive gate.

The single most important test in this file is
`test_shell_only_observation_is_always_rejected` — it encodes the rule that stops this
tool producing the spec's own bogus example finding ("unexported activity accessible via
root am start"), which is true on every Android device and is not a bug.
"""

from __future__ import annotations

import pytest

from droid_recon.models import Observation
from droid_recon.static.manifest import parse_manifest
from droid_recon.triage import triage

from .fixtures import KNOWN_ANSWERS_MANIFEST


@pytest.fixture(scope="module")
def surface():
    return parse_manifest(KNOWN_ANSWERS_MANIFEST)


def obs(**kw) -> Observation:
    base = dict(
        id="O0001-test",
        kind="query_provider",
        package="com.example.target",
        component="com.example.target.OpenProvider",
        reachable_from="third_party_app",
        command=["adb", "shell", "content", "query", "--uri", "content://x/notes"],
        rc=0,
        stdout_excerpt="Row: 0 _id=1, body=secret",
        signal="rows_returned",
    )
    base.update(kw)
    return Observation(**base)


def test_open_provider_rows_becomes_a_finding(surface):
    result = triage(surface, [obs()])
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == "high"
    assert f.reachable_from == "third_party_app"
    assert len(f.chain) >= 3
    assert f.source and f.sink
    assert "CWE-926" in f.cwe


@pytest.mark.parametrize("reach", ["shell", "none"])
def test_shell_only_observation_is_always_rejected(surface, reach):
    """adb shell holds START_ANY_ACTIVITY. Success from shell proves nothing."""
    result = triage(surface, [obs(reachable_from=reach, component="com.example.target.PrivateActivity",
                                  kind="launch_activity", signal="ok")])
    assert result.findings == []
    assert len(result.rejected) == 1
    assert "shell" in result.rejected[0]["why"].lower() or "not a finding" in result.rejected[0]["why"]


def test_launching_an_unexported_activity_is_not_a_finding(surface):
    """The spec's flagship example (prompt.md:248) must produce zero findings."""
    private = next(c for c in surface.components if c.name.endswith("PrivateActivity"))
    assert private.reachable_from == "shell"
    result = triage(surface, [obs(
        kind="launch_activity",
        component=private.name,
        reachable_from=private.reachable_from,
        signal="ok",
        stdout_excerpt="Status: ok\nActivity: com.example.target/.PrivateActivity",
    )])
    assert result.findings == [], "launching an unexported activity from adb is never a finding"


def test_signature_guarded_component_is_rejected(surface):
    guarded = next(c for c in surface.components if c.name.endswith("SignatureGuardedActivity"))
    result = triage(surface, [obs(component=guarded.name,
                                  reachable_from=guarded.reachable_from,
                                  kind="launch_activity", signal="ok")])
    assert result.findings == []


def test_no_effect_is_rejected(surface):
    """Reachable but nothing happened -> not a finding."""
    result = triage(surface, [obs(signal="provider_error", stdout_excerpt="Error while accessing provider")])
    assert result.findings == []
    assert "no observable effect" in result.rejected[0]["why"]


def test_empty_result_is_rejected(surface):
    result = triage(surface, [obs(signal="empty_result", stdout_excerpt="No result found.")])
    assert result.findings == []


def test_logged_credentials_become_a_finding(surface):
    result = triage(surface, [obs(
        kind="broadcast",
        component="com.example.target.OpenReceiver",
        signal="ok",
        detail={"logcat_sensitive_tokens": ["token", "authorization:"]},
        logcat_excerpt="D/Net: authorization: Bearer eyJhbGciOi...",
    )])
    assert len(result.findings) == 1
    assert "CWE-532" in result.findings[0].cwe


def test_crash_on_exported_component_is_low_severity(surface):
    result = triage(surface, [obs(
        kind="launch_activity",
        component="com.example.target.ExportedNoGuardActivity",
        signal="crash",
        logcat_excerpt=("FATAL EXCEPTION: main\njava.lang.NullPointerException\n"
                        "at com.example.target.ExportedNoGuardActivity.onCreate(A.java:42)"),
    )])
    assert len(result.findings) == 1
    assert result.findings[0].severity == "low"
    assert "CWE-20" in result.findings[0].cwe


def test_browser_reach_raises_exploitability(surface):
    result = triage(surface, [obs(reachable_from="browser")])
    assert result.findings[0].exploitability == "remote-one-click"


def test_finding_ids_continue_from_offset(surface):
    """Two distinct components -> two findings, numbered on from the offset."""
    result = triage(surface, [
        obs(),
        obs(id="O0002-test", component="com.example.target.GrantingProvider",
            detail={"uri": "content://com.example.target.grant/x"}),
    ], start_index=5)
    assert [f.id for f in result.findings] == ["F006", "F007"]


def test_same_component_many_paths_is_one_finding(surface):
    """One misconfigured provider queried across six paths is ONE finding, six PoCs."""
    uris = [f"content://com.example.target.open/{p}"
            for p in ("notes", "secrets", "users", "items", "data", "cache")]
    result = triage(surface, [
        obs(id=f"O{i:04d}", detail={"uri": u, "row_count": 3})
        for i, u in enumerate(uris)
    ])
    assert len(result.findings) == 1, "must not emit one finding per URI"
    f = result.findings[0]
    assert len(f.observations) == 6
    assert len(f.evidence["additional_uris"]) == 5  # the first is the primary PoC
    assert f.evidence["total_rows"] == 15  # 5 merged x 3 rows


def test_platform_component_is_downgraded_and_caveated():
    """content://settings/* is world-readable BY DESIGN. Report it, but do not overclaim."""
    from droid_recon.static.manifest import parse_manifest

    platform = parse_manifest(
        '<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.android.providers.settings" android:sharedUserId="android.uid.system">'
        '<application><provider android:name=".SettingsProvider" android:exported="true"'
        ' android:authorities="settings"/></application></manifest>'
    )
    result = triage(platform, [obs(
        component="com.android.providers.settings.SettingsProvider",
        detail={"uri": "content://settings/system", "row_count": 36},
    )])
    f = result.findings[0]
    assert f.severity == "medium", "platform findings drop one severity notch"
    assert f.confidence == "50%"
    assert f.evidence["platform_by_design_caveat"] is True
    assert "documented API" in f.notes


def test_non_platform_component_is_not_downgraded(surface):
    """A normal third-party app keeps full severity and confidence."""
    f = triage(surface, [obs()]).findings[0]
    assert f.severity == "high"
    assert f.confidence == "80%"
    assert "platform_by_design_caveat" not in f.evidence


def test_guarded_provider_rows_is_medium_not_high(surface):
    """Rows from a provider that at least has a guard is less severe than one with none."""
    guarded = next(c for c in surface.components if c.name.endswith("ReadGuardedProvider"))
    # Force reach so we exercise the severity branch, not the reach gate.
    result = triage(surface, [obs(component=guarded.name, reachable_from="third_party_app")])
    assert result.findings[0].severity == "medium"


def test_every_finding_has_a_chain(surface):
    """Schema invariant: source + sink + chain are what make a finding reportable."""
    result = triage(surface, [
        obs(),
        obs(id="O2", kind="broadcast", component="com.example.target.OpenReceiver",
            signal="ok", detail={"logcat_sensitive_tokens": ["password"]}),
    ])
    assert len(result.findings) == 2
    for f in result.findings:
        assert f.chain and len(f.chain) >= 3
        assert f.source.get("code_location")
        assert f.sink.get("code_location")
        assert f.poc
        assert f.impact
