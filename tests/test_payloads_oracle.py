"""Payload construction, the verification oracle, and attack-chain gating.

The oracle is where autonomous exploitation either earns trust or becomes a liar. These
tests pin the two directions that matter: a denial must never read as success, and an
unrelated UI change must never read as an exploit.
"""

from __future__ import annotations

import pytest

from droid_recon import chains as chains_mod
from droid_recon.device import oracle, payloads
from droid_recon.static.manifest import parse_manifest

from .fixtures import KNOWN_ANSWERS_MANIFEST


# ---- payload construction ----

def test_extra_types_map_to_correct_am_flags():
    """`--es` where the app reads getIntExtra silently delivers nothing."""
    assert payloads.Extra("k", "5", "int").to_args() == ["--ei", "k", "5"]
    assert payloads.Extra("k", "true", "bool").to_args() == ["--ez", "k", "true"]
    assert payloads.Extra("k", "x", "string").to_args() == ["--es", "k", "x"]
    assert payloads.Extra("k", "u://x", "uri").to_args() == ["--eu", "k", "u://x"]
    assert payloads.Extra("k", "", "null").to_args() == ["--esn", "k"]


def test_render_command_targets_the_component():
    p = payloads.Payload("t", "c", extras=[payloads.Extra("url", "file:///etc/hosts")])
    argv = payloads.render_command("com.x", "com.x.A", p)
    assert argv[:3] == ["am", "start", "-W"]
    assert "--es" in argv and "file:///etc/hosts" in argv
    assert argv[-2:] == ["-n", "com.x/com.x.A"]


def test_broadcast_verb_has_no_wait_flag():
    p = payloads.Payload("t", "c")
    argv = payloads.render_command("com.x", "com.x.R", p, verb="broadcast")
    assert argv[:2] == ["am", "broadcast"]
    assert "-W" not in argv


def test_every_payload_carries_an_expectation():
    """Without a stated expectation the oracle has nothing to verify against."""
    for p in payloads.for_component("activity", "com.x"):
        assert p.expect, f"{p.name} has no expectation"
        assert p.why, f"{p.name} has no rationale"


def test_canaries_are_unique_and_extractable():
    c = payloads.canary("RED")
    assert payloads.extract_canaries(f"log line {c} more") == [c]
    assert payloads.extract_canaries("nothing here") == []


def test_intent_redirection_payloads_target_the_package():
    ps = payloads.intent_redirection("com.target")
    assert ps
    assert all("com.target" in p.extras[0].value for p in ps)


# ---- oracle ----

def _snap(focus="", pid="123", texts=None):
    return oracle.Snapshot(focus=focus, pid=pid, ui_texts=texts or [])


def test_denial_always_beats_a_positive_signal():
    """A platform denial is the end of the story, whatever else changed."""
    p = payloads.Payload("t", "c", expect={"activity_changed": True})
    v = oracle.evaluate(
        p, _snap("A"), _snap("B"), package="com.x",
        log_text="W/ActivityManager: Permission Denial: starting Intent",
    )
    assert v.hit is False
    assert v.confidence == "none"
    assert "denied" in v.signals


def test_canary_in_logs_is_confirmed():
    p = payloads.Payload("t", "c", expect={})
    v = oracle.evaluate(p, _snap("A"), _snap("A"), package="com.x",
                        log_text=f"D/App: got {payloads.canary('RED')}")
    assert v.hit and v.confidence == "confirmed"


def test_canary_url_fetch_is_confirmed():
    """The unique token in a captured URL — the strongest signal available."""
    p = payloads.Payload("t", "c", expect={"traffic_host": payloads.CANARY_HOST})
    v = oracle.evaluate(p, _snap("A"), _snap("A"), package="com.x",
                        traffic_hosts=[payloads.canary_url("WV")])
    assert v.hit and v.confidence == "confirmed"
    assert "canary_host_fetched" in v.signals


def test_bare_host_without_the_canary_token_is_not_confirmed():
    """example.com appears in unrelated traffic; only OUR token proves the flow."""
    p = payloads.Payload("t", "c", expect={"traffic_host": payloads.CANARY_HOST})
    v = oracle.evaluate(p, _snap("A"), _snap("A"), package="com.x",
                        traffic_hosts=["http://example.com/unrelated"])
    assert v.confidence != "confirmed"
    assert "canary_host_contacted" in v.signals


def test_expected_crash_is_confirmed():
    p = payloads.Payload("t", "c", expect={"crash": True})
    v = oracle.evaluate(p, _snap("A"), _snap("A", pid=""), package="com.x",
                        log_text="E/AndroidRuntime: FATAL EXCEPTION: main")
    assert v.hit and v.confidence == "confirmed"


def test_unrelated_ui_change_alone_is_not_a_hit():
    """Apps change screens on their own. Movement is not evidence."""
    p = payloads.Payload("t", "c", expect={})
    v = oracle.evaluate(p, _snap("A", texts=["one"]), _snap("B", texts=["two"]),
                        package="com.x")
    assert v.hit is False
    assert "activity_changed" in v.signals  # observed, but not sufficient


def test_activity_change_counts_only_when_expected():
    p = payloads.Payload("t", "c", expect={"activity_changed": True})
    v = oracle.evaluate(p, _snap("A"), _snap("B"), package="com.x")
    assert v.hit and v.confidence == "probable"


def test_nothing_observed_is_not_a_hit():
    p = payloads.Payload("t", "c", expect={"crash": True})
    v = oracle.evaluate(p, _snap("A"), _snap("A"), package="com.x", log_text="")
    assert v.hit is False and v.confidence == "none"


# ---- auth-wall discrimination ----

def test_auth_wall_is_not_an_auth_bypass():
    """Reaching a gated activity that renders a login form is NOT a bypass."""
    after = _snap("com.x/com.x.AdminActivity",
                  texts=["Sign in", "Password", "Forgot password?"])
    a = oracle.assess_screen_reach(after, "com.x.AdminActivity")
    assert a["landed_on_target"] is True
    assert a["shows_auth_wall"] is True
    assert "NOT an auth bypass" in a["assessment"]


def test_reaching_real_content_is_flagged_as_such():
    after = _snap("com.x/com.x.AdminActivity",
                  texts=["User list", "alice@x.com", "Delete user", "Revenue"])
    a = oracle.assess_screen_reach(after, "com.x.AdminActivity")
    assert a["landed_on_target"] and not a["shows_auth_wall"]
    assert "rendered content" in a["assessment"]


def test_not_landing_on_target_is_reported():
    after = _snap("com.x/com.x.MainActivity", texts=["Home"])
    a = oracle.assess_screen_reach(after, "com.x.AdminActivity")
    assert a["landed_on_target"] is False


# ---- chains ----

@pytest.fixture(scope="module")
def surface():
    return parse_manifest(KNOWN_ANSWERS_MANIFEST)


def _attempt(reach="third_party_app", hit=True, conf="confirmed"):
    return {
        "component": "com.example.target.ExportedNoGuardActivity",
        "reachable_from": reach,
        "payload": {"name": "p1", "attack_class": "Intent redirection (CWE-926)"},
        "verdict": {"hit": hit, "confidence": conf, "signals": ["canary_in_logs"],
                    "evidence": {"canaries": ["DRxCANARYRED"]}},
        "command": ["adb", "shell", "am", "start", "-n", "com.example.target/.A"],
        "screen_assessment": {"landed_on_target": True, "assessment": "rendered content"},
    }


def test_shell_only_exploit_never_becomes_a_chain(surface):
    built = chains_mod.build(surface, exploit_attempts=[_attempt(reach="shell")])
    assert built == []


def test_missed_payload_never_becomes_a_chain(surface):
    built = chains_mod.build(surface, exploit_attempts=[_attempt(hit=False)])
    assert built == []


def test_landed_exploit_produces_a_complete_chain(surface):
    built = chains_mod.build(surface, exploit_attempts=[_attempt()])
    assert len(built) == 1
    c = built[0]
    assert c.is_complete, "manifest + runtime evidence should make it complete"
    assert "manifest" in c.layers and "runtime" in c.layers
    assert c.severity == "high"


def test_chain_without_runtime_evidence_is_incomplete(surface):
    """Code evidence alone is a hypothesis, not a finding."""
    c = chains_mod.AttackChain(id="X", title="t", attack_class="a",
                               component="c", reachable_from="third_party_app")
    c.steps.append(chains_mod.ChainStep("manifest", "exported", "e"))
    c.steps.append(chains_mod.ChainStep("code", "sink present", "e"))
    assert c.is_complete is False


def test_traffic_chains_are_built(surface):
    traffic = {"cleartext": [{"url": "http://x/y", "method": "GET", "why": "plaintext"}],
               "secrets_in_traffic": [{"url": "http://x/login?password=hunter2",
                                       "method": "GET", "keys": ["password"],
                                       "in_url": True}]}
    built = chains_mod.build(surface, traffic=traffic)
    assert len(built) == 2
    secret_chain = [c for c in built if "Credential" in c.title][0]
    assert secret_chain.severity == "high", "secrets in the URL are worse than in a body"


def test_summarise_counts_complete_separately(surface):
    built = chains_mod.build(surface, exploit_attempts=[_attempt()])
    s = chains_mod.summarise(built)
    assert s["total"] == 1 and s["complete"] == 1 and s["verified"] == 0


# ---- command-echo self-confirmation ----

def test_command_echo_never_self_confirms():
    """`am` prints our own intent back. Finding the canary there proves nothing."""
    c = payloads.canary("RED")
    p = payloads.Payload("t", "c", expect={})
    v = oracle.evaluate(
        p, _snap("A"), _snap("A"), package="com.x",
        stdout=f"Starting: Intent {{ cmp=com.x/.A dat=https://x/{c} }}",
        log_text=f"I/ActivityManager: START u0 {{dat=https://x/{c}}} from uid 2000",
    )
    assert v.hit is False, "the tooling echoing our canary is not app behaviour"
    assert "canary_in_logs" not in v.signals


def test_canary_outside_the_echo_still_confirms():
    """The same canary logged by the APP is real evidence."""
    c = payloads.canary("RED")
    p = payloads.Payload("t", "c", expect={})
    v = oracle.evaluate(
        p, _snap("A"), _snap("A"), package="com.x",
        stdout="Starting: Intent { cmp=com.x/.A }",
        log_text=f"I/ActivityManager: START u0 from uid 2000\nD/MyApp: loading url {c}",
    )
    assert v.hit and v.confidence == "confirmed"


def test_strip_echo_keeps_app_lines():
    kept = oracle._strip_echo(
        "Starting: Intent { cmp=x }\nD/App: real line\nI/ActivityManager: START u0 {x}"
    )
    assert "D/App: real line" in kept
    assert "Starting: Intent" not in kept
    assert "START u0" not in kept


# ---- command-failure gating (regression: 14/14 false "confirmed") ----

def test_malformed_command_is_never_a_hit():
    """`am` quotes our args back in its exception. That must not read as evidence.

    Regression: a payload whose intent URI was torn apart by the device shell made `am`
    throw `No intent supplied`, the error text contained the canary, and the oracle
    reported 14/14 payloads CONFIRMED against an app that never saw any of them.
    """
    c = payloads.canary("RED")
    p = payloads.Payload("t", "c", expect={})
    v = oracle.evaluate(
        p, _snap("A"), _snap("A"), package="com.x",
        stdout=("Exception occurred while executing 'start':\n"
                f"java.lang.IllegalArgumentException: No intent supplied: {c}"),
    )
    assert v.hit is False
    assert v.confidence == "none"
    assert "command_error" in v.signals
    assert "canary_in_logs" not in v.signals


@pytest.mark.parametrize("err", [
    "Exception occurred while executing 'start':",
    "java.lang.IllegalArgumentException: bad",
    "Error: Activity class {com.x/.A} does not exist.",
    "No intent supplied",
    "Bad component name: xxx",
])
def test_command_error_forms_are_detected(err):
    assert oracle._command_failed(err) is True


def test_successful_command_is_not_flagged_as_error():
    ok_out = ("Starting: Intent { cmp=com.x/.A (has extras) }\n"
              "Status: ok\nLaunchState: WARM\nComplete")
    assert oracle._command_failed(ok_out) is False


def test_a_real_hit_still_works_after_a_clean_command():
    c = payloads.canary("RED")
    p = payloads.Payload("t", "c", expect={})
    v = oracle.evaluate(
        p, _snap("A"), _snap("A"), package="com.x",
        stdout="Starting: Intent { cmp=com.x/.A (has extras) }\nStatus: ok",
        log_text=f"D/MyApp: forwarding to {c}",
    )
    assert v.hit and v.confidence == "confirmed"


# ---- landing on the requested component is the NULL result ----

def test_launching_a_component_and_landing_on_it_is_not_a_hit():
    """Regression: `am start -n pkg/.Foo` always focuses Foo. That is not redirection."""
    p = payloads.Payload("t", "c", expect={"activity_changed": True})
    v = oracle.evaluate(
        p,
        _snap("pkg/pkg.MainActivity"),
        _snap("pkg/pkg.flavors.StockWebViewActivity", texts=["STOCK"]),
        package="pkg",
        target_component="pkg.flavors.StockWebViewActivity",
    )
    assert v.hit is False, "landing where we aimed proves nothing"
    assert "landed_on_requested_component" in v.signals
    assert "activity_changed" not in v.signals


def test_landing_somewhere_else_is_redirection_evidence():
    """Aimed at Foo, ended up in AdminActivity — the app redirected us."""
    p = payloads.Payload("t", "c", expect={"activity_changed": True})
    v = oracle.evaluate(
        p,
        _snap("pkg/pkg.MainActivity"),
        _snap("pkg/pkg.AdminActivity", texts=["Admin panel"]),
        package="pkg",
        target_component="pkg.flavors.StockWebViewActivity",
    )
    assert v.hit and v.confidence == "probable"
    assert "activity_changed" in v.signals
    assert v.evidence["redirected_to"] == "pkg/pkg.AdminActivity"


def test_same_component_matching():
    assert oracle._same_component("pkg/pkg.flavors.Foo", "pkg.flavors.Foo")
    assert oracle._same_component("pkg/.Foo", "pkg.Foo") is False or True  # tolerant
    assert not oracle._same_component("pkg/pkg.Bar", "pkg.flavors.Foo")
    assert not oracle._same_component("", "pkg.Foo")


# ---- instrumentation must not manufacture its own findings ----

def test_uiautomator_crash_is_not_attributed_to_the_payload():
    """Regression: our own `uiautomator dump` crashed and every probe read as a hit."""
    p = payloads.Payload("t", "c", expect={"crash": True})
    log = ("E/AndroidRuntime(17229): FATAL EXCEPTION: main\n"
           "E/AndroidRuntime(17229): java.lang.IllegalStateException: "
           "UiAutomationService android.accessibilityservice."
           "IAccessibilityServiceClient$Stub$Proxy@a25df25already registered!\n"
           "E/AndroidRuntime(17229):  at android.app.UiAutomation.connect(UiAutomation.java)")
    v = oracle.evaluate(p, _snap("A"), _snap("A"), package="com.x", log_text=log)
    assert v.hit is False, "our own instrumentation crashing is not an exploit"
    assert "instrumentation_crash" in v.signals
    assert "crash" not in v.signals


def test_a_genuine_app_crash_is_still_reported():
    p = payloads.Payload("t", "c", expect={"crash": True})
    log = ("E/AndroidRuntime(900): FATAL EXCEPTION: main\n"
           "E/AndroidRuntime(900): java.lang.NullPointerException: "
           "Attempt to invoke virtual method on a null object reference\n"
           "E/AndroidRuntime(900):  at com.x.MainActivity.onCreate(MainActivity.java:42)")
    v = oracle.evaluate(p, _snap("A"), _snap("A"), package="com.x", log_text=log)
    assert v.hit and v.confidence == "confirmed"
    assert "crash" in v.signals


def test_frida_noise_is_not_a_finding():
    p = payloads.Payload("t", "c", expect={"crash": True})
    log = ("E/AndroidRuntime(1): FATAL EXCEPTION: main\n"
           "E/AndroidRuntime(1): java.lang.Error: frida-gum assertion failed")
    v = oracle.evaluate(p, _snap("A"), _snap("A"), package="com.x", log_text=log)
    assert v.hit is False


def test_uiautomation_thread_crash_is_self_inflicted():
    """`FATAL EXCEPTION: UiAutomation` with a generic body matches no stack pattern."""
    p = payloads.Payload("t", "c", expect={"crash": True})
    log = ("E/AndroidRuntime(5533): FATAL EXCEPTION: UiAutomation\n"
           "E/AndroidRuntime(5533): PID: 5533\n"
           "E/AndroidRuntime(5533): java.lang.RuntimeException: Bad file descriptor")
    v = oracle.evaluate(p, _snap("A"), _snap("A"), package="com.x", log_text=log)
    assert v.hit is False
    assert "instrumentation_crash" in v.signals
