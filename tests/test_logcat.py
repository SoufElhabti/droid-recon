"""Credential detection in logcat — the regression suite for a real false positive.

The first end-to-end run on com.epicgames.portal produced three "credential leak"
findings. Every one was bogus: the matches were `errorCallbackToken=null` and
`RemoteToken{...}` logged by WindowManager on ordinary activity transitions. The lines
below are verbatim from that run and must never match again.
"""

from __future__ import annotations

import pytest

from droid_recon.device.logcat import crashed, denied, has_sensitive

PKG = "com.epicgames.portal"

# --- verbatim framework noise from the failing run ---
REAL_FALSE_POSITIVES = [
    "V/WindowManager(  539):     startWCT=WindowContainerTransaction { changes = {} "
    "hops = [] errorCallbackToken=null taskFragmentOrganizer=null }",
    "V/WindowManager(  539):     info={id=7 t=OPEN f=0x0 trk=0 r=[0@Point(0, 0)] "
    "c=[{WCT{RemoteToken{dfe66dc Task{5491598 #18 type=standard A=10193:com.epicgames.portal",
    "V/WindowManagerShell(  745): Transition requested: android.os.BinderProxy@c6aac2b "
    "TransitionRequestInfo { type = OPEN, triggerTask = TaskInfo{userId=0 taskId=19",
    "V/WindowManagerShell(  745): onTransitionReady android.os.BinderProxy@4c6218c: "
    "{id=13 t=CLOSE f=0x0 trk=0 r=[0@Point(0, 0)] c=[{WCT{android.window.IWindowContai",
    "I/ActivityManager(  539): Start proc 10193:com.epicgames.portal/u0a193 for "
    "next-top-activity {com.epicgames.portal/com.epicgames.portal.ui.MainActivity}",
]


@pytest.mark.parametrize("line", REAL_FALSE_POSITIVES)
def test_framework_transition_noise_is_not_a_credential(line):
    assert has_sensitive(line, PKG) == [], f"false positive on: {line[:90]}"


def test_all_noise_together_yields_nothing():
    assert has_sensitive("\n".join(REAL_FALSE_POSITIVES), PKG) == []


# --- things that genuinely ARE credentials ---

@pytest.mark.parametrize("line,expect_substr", [
    (f"D/Net({PKG}): authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
     f"eyJzdWIiOiIxMjM0NSJ9.abcdefghijklmno", "eyJ"),
    (f"D/Auth({PKG}): access_token=ya29.a0AfH6SMBx7QK2mZpQwErTyUiOp1234567890", "access_token"),
    (f"D/Cfg({PKG}): api_key=AIzaSyD-1234567890abcdefghijklmnopqrstuv", "AIza"),
    (f"E/Login({PKG}): password=hunter2correcthorsebattery", "password"),
    (f"D/S3({PKG}): aws key AKIAIOSFODNN7EXAMPLE used", "AKIA"),
    (f"D/Api({PKG}): client_secret=s3cr3t-value-9f8a7b6c5d4e", "client_secret"),
])
def test_real_credentials_are_detected(line, expect_substr):
    found = has_sensitive(line, PKG)
    assert found, f"missed a real credential in: {line[:90]}"
    assert any(expect_substr in f for f in found), found


def test_high_confidence_literals_match_even_without_the_package():
    """A JWT is a JWT wherever it appears — but framework noise still must not match."""
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    assert has_sensitive(f"D/Unknown(999): dumping {jwt}", PKG)


def test_null_and_boolean_values_are_rejected():
    for val in ("null", "false", "true", "0", "-1", "undefined", "0x7f0a01"):
        assert has_sensitive(f"D/X({PKG}): auth_token={val}", PKG) == [], val


def test_short_alpha_values_are_rejected_as_field_names():
    """`password=enabled` is a config flag being logged, not a credential."""
    assert has_sensitive(f"D/X({PKG}): password=enabled", PKG) == []


def test_substring_keywords_do_not_match():
    """The core fix: a keyword inside a longer identifier is not a keyword."""
    for ident in ("errorCallbackToken", "RemoteToken", "WindowContainerToken",
                  "mTokenizer", "tokenized", "SecretaryService"):
        assert has_sensitive(f"D/X({PKG}): {ident}=somelongvalue12345", PKG) == [], ident


def test_noise_tag_suppresses_even_a_plausible_assignment():
    """WindowManager is framework-owned; its output is never the app's secret."""
    assert has_sensitive(
        "V/WindowManager(539): session_id=abcdef1234567890abcdef", PKG
    ) == []


def test_package_scoping_excludes_other_apps():
    """A credential logged by a different app is not this app's finding."""
    line = "D/OtherApp(777): access_token=ya29.SomeOtherAppsTokenValue123456"
    assert has_sensitive(line, PKG) == []
    assert has_sensitive(line, "")  # unscoped still sees it


def test_crash_and_denial_detection():
    assert crashed("E/AndroidRuntime(1): FATAL EXCEPTION: main")
    assert not crashed("D/X: everything is fine")
    assert denied("W/ActivityManager: Permission Denial: opening provider")
    assert denied("java.lang.SecurityException: not allowed")
    assert not denied("D/X: ok")
