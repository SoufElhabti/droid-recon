"""Correctness gate for manifest parsing and reachability classification.

If `reachable_from` is wrong, every downstream artifact is wrong: triage would either
suppress real bugs or emit the classic non-finding ("unexported activity launched via
adb"). These assertions are exact, not smoke tests.
"""

from __future__ import annotations

import pytest

from droid_recon.models import classify_reach
from droid_recon.static.manifest import parse_manifest

from .fixtures import EXPECTED, KNOWN_ANSWERS_MANIFEST


@pytest.fixture(scope="module")
def surface():
    return parse_manifest(KNOWN_ANSWERS_MANIFEST)


def test_package_and_metadata(surface):
    assert surface.package == "com.example.target"
    assert surface.version_code == 7
    assert surface.version_name == "1.2.3"
    assert surface.min_sdk == 24
    assert surface.target_sdk == 34
    assert surface.debuggable is True
    assert surface.allow_backup is True


def test_all_components_parsed(surface):
    names = {c.name for c in surface.components}
    assert names == set(EXPECTED), f"missing={set(EXPECTED) - names} extra={names - set(EXPECTED)}"


@pytest.mark.parametrize("name,expected", sorted(EXPECTED.items()))
def test_exported_and_reachability(surface, name, expected):
    """The load-bearing assertion of the whole project."""
    exp_exported, exp_reach = expected
    comp = next(c for c in surface.components if c.name == name)
    assert comp.exported is exp_exported, f"{name}: exported"
    assert comp.reachable_from == exp_reach, f"{name}: reachable_from"


def test_exported_inference_is_labelled(surface):
    """An inferred export must say so — the operator needs to know it wasn't explicit."""
    inferred = next(c for c in surface.components
                    if c.name.endswith("InferredExportedActivity"))
    assert inferred.exported_source == "inferred-from-intent-filter"

    explicit = next(c for c in surface.components if c.name.endswith("ExportedNoGuardActivity"))
    assert explicit.exported_source == "explicit"


def test_provider_defaults_to_not_exported_on_modern_targetsdk(surface):
    """Providers are exported-by-default only below targetSdk 17. This app targets 34."""
    p = next(c for c in surface.components if c.name.endswith("DefaultProvider"))
    assert p.exported is False
    assert p.exported_source == "default-by-targetsdk"


def test_weak_custom_permission_does_not_protect(surface):
    """protectionLevel=normal is grantable to any app, so it is not a real guard."""
    c = next(c for c in surface.components if c.name.endswith("WeaklyGuardedActivity"))
    assert c.reachable_from == "third_party_app"
    assert any("WEAK" in m["permission"] for m in surface.permission_misconfigs)


def test_signature_permission_does_protect(surface):
    c = next(c for c in surface.components if c.name.endswith("SignatureGuardedActivity"))
    assert c.reachable_from == "none"


def test_provider_read_permission_is_the_read_guard(surface):
    """For providers the effective read guard is readPermission, not permission."""
    c = next(c for c in surface.components if c.name.endswith("ReadGuardedProvider"))
    assert c.read_permission == "com.example.target.permission.STRONG"
    assert c.reachable_from == "none"
    assert any("write" in i.lower() for i in c.issues), c.issues


def test_open_provider_is_flagged(surface):
    c = next(c for c in surface.components if c.name.endswith("OpenProvider"))
    assert c.authorities == ["com.example.target.open"]
    assert any("NO permission" in i for i in c.issues), c.issues


def test_grant_uri_permissions_flagged(surface):
    c = next(c for c in surface.components if c.name.endswith("GrantingProvider"))
    assert c.grant_uri_permissions is True
    assert any("grantUriPermissions" in i for i in c.issues)


def test_browsable_and_deeplinks(surface):
    c = next(c for c in surface.components if c.name.endswith("BrowsableActivity"))
    assert c.browsable is True
    assert "myapp://open/deep" in c.deeplinks()
    assert any("BROWSABLE" in i for i in c.issues)


def test_send_target_detected(surface):
    c = next(c for c in surface.components if c.name.endswith("ShareActivity"))
    assert c.send_target is True
    assert any("SEND" in i for i in c.issues)


def test_app_level_issues(surface):
    joined = " ".join(surface.app_issues)
    assert "debuggable" in joined
    assert "allowBackup" in joined


def test_summary_counts(surface):
    s = surface.summary()
    assert s["total_components"] == len(EXPECTED)
    assert s["exported_components"] == sum(1 for e in EXPECTED.values() if e[0])
    assert s["reachable_third_party"] == sum(
        1 for e in EXPECTED.values() if e[1] in ("third_party_app", "browser")
    )


def test_roundtrip_serialisation(surface):
    from droid_recon.models import AttackSurface

    restored = AttackSurface.from_dict(surface.to_dict())
    assert restored.package == surface.package
    assert len(restored.components) == len(surface.components)
    assert [c.reachable_from for c in restored.components] == \
           [c.reachable_from for c in surface.components]


# ---- classify_reach unit table ----

@pytest.mark.parametrize("kwargs,expected", [
    (dict(exported=False, permission=None, permission_protection=None), "shell"),
    (dict(exported=False, permission="x", permission_protection="signature"), "shell"),
    (dict(exported=True, permission=None, permission_protection=None), "third_party_app"),
    (dict(exported=True, permission=None, permission_protection=None, browsable=True), "browser"),
    (dict(exported=True, permission="p", permission_protection="normal"), "third_party_app"),
    (dict(exported=True, permission="p", permission_protection="dangerous"), "third_party_app"),
    (dict(exported=True, permission="p", permission_protection="signature"), "none"),
    (dict(exported=True, permission="p", permission_protection="signatureOrSystem"), "none"),
    (dict(exported=True, permission="p", permission_protection="signature|privileged"), "none"),
    # Unresolvable custom permission: assume it might be weak (defender-pessimistic).
    (dict(exported=True, permission="com.x.CUSTOM", permission_protection=None), "third_party_app"),
])
def test_classify_reach_table(kwargs, expected):
    assert classify_reach(**kwargs) == expected


def test_unexported_is_never_third_party_reachable():
    """Property: no combination of guards can make an unexported component attacker-reachable."""
    for perm in (None, "p"):
        for prot in (None, "normal", "dangerous", "signature"):
            for browsable in (True, False):
                assert classify_reach(
                    exported=False, permission=perm,
                    permission_protection=prot, browsable=browsable
                ) == "shell"
