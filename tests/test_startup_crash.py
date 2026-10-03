"""A provider startup crash must not become a finding for every IPC probe."""

from __future__ import annotations

from droid_recon.device import logcat, oracle, payloads, probes
from droid_recon.models import Observation
from droid_recon.static.manifest import parse_manifest
from droid_recon.triage import triage

PACKAGE = "com.watchguard.authpoint"
ACTIVITY = "androidx.test.core.app.InstrumentationActivityInvoker$BootstrapActivity"
RECEIVER = "com.google.firebase.iid.FirebaseInstanceIdReceiver"

STARTUP_LOG = f"""\
I/ActivityTaskManager(  495): START u0 {{cmp={PACKAGE}/{ACTIVITY}}} from uid 0
I/ActivityManager(  495): Start proc 5610:{PACKAGE}/u0a167 for top-activity {{{PACKAGE}/{ACTIVITY}}}
E/AndroidRuntime( 5610): FATAL EXCEPTION: main
E/AndroidRuntime( 5610): Process: {PACKAGE}, PID: 5610
E/AndroidRuntime( 5610): java.lang.RuntimeException: Unable to get provider com.google.firebase.provider.FirebaseInitProvider: java.lang.ArrayIndexOutOfBoundsException: length=0; index=-1
E/AndroidRuntime( 5610):     at android.app.ActivityThread.installProvider(ActivityThread.java:7244)
E/AndroidRuntime( 5610): Caused by: java.lang.ArrayIndexOutOfBoundsException: length=0; index=-1
E/AndroidRuntime( 5610):     at com.google.firebase.provider.FirebaseInitProvider.onCreate(MyApplication:593)
E/AndroidRuntime( 5610):     at android.content.ContentProvider.attachInfo(ContentProvider.java:2397)
"""


def _surface():
    return parse_manifest(f'''\
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{PACKAGE}">
  <application>
    <activity android:name="{ACTIVITY}" android:exported="true" />
    <receiver android:name="{RECEIVER}" android:exported="true"
      android:permission="com.google.android.c2dm.permission.SEND" />
  </application>
</manifest>''')


def _observation(component=ACTIVITY, log_text=STARTUP_LOG, **updates):
    obs = Observation(
        id="O0001-launch_activity", kind="launch_activity", package=PACKAGE,
        component=component, reachable_from="third_party_app",
        command=["adb", "shell", "am", "start", "-n", f"{PACKAGE}/{component}"],
        rc=0, stdout_excerpt="Status: ok", logcat_excerpt=log_text,
    )
    for key, value in updates.items():
        setattr(obs, key, value)
    return obs


def test_firebase_provider_startup_failure_is_not_activity_failure():
    assert logcat.crash_origin(STARTUP_LOG, PACKAGE, ACTIVITY) == "app_initialization"
    obs = _observation()
    probes._classify(obs, obs.stdout_excerpt, STARTUP_LOG, PACKAGE, component=ACTIVITY)
    assert obs.signal == "crash"  # raw effect remains visible
    assert obs.detail["crash_origin"] == "app_initialization"
    assert obs.interesting is False
    result = triage(_surface(), [obs])
    assert not result.findings
    assert "before the requested component" in result.rejected[0]["why"]


def test_stale_crash_after_rejected_service_command_is_not_attributed():
    obs = _observation(component="com.example.RevocationBoundService", rc=255,
                       stderr_excerpt="Error: app is in background uid null")
    probes._classify(obs, obs.stderr_excerpt, STARTUP_LOG, PACKAGE,
                     component=obs.component)
    assert obs.signal == "error"
    assert obs.interesting is False
    assert obs.detail["command_rejected"].startswith("Error: app is in background uid")
    assert obs.detail["unattributed_logcat_crash"] == "probe command rejected before dispatch"


def test_guarded_receiver_shell_crash_needs_ordinary_uid_proof():
    log = (f"E/AndroidRuntime(5610): FATAL EXCEPTION: main\n"
           f"E/AndroidRuntime(5610): Process: {PACKAGE}, PID: 5610\n"
           f"E/AndroidRuntime(5610): java.lang.IllegalArgumentException: bad Intent\n"
           f"E/AndroidRuntime(5610):     at {RECEIVER}.onReceive(FirebaseInstanceIdReceiver.java:42)")
    obs = _observation(component=RECEIVER, log_text=log,
                       kind="broadcast", signal="crash",
                       detail={"crash_origin": "target_component"})
    result = triage(_surface(), [obs])
    assert not result.findings
    assert len(result.candidates) == 1
    assert "ordinary app UID" in result.candidates[0]["why_candidate"]


def test_unattributed_crash_remains_inconclusive():
    obs = _observation(log_text="E/AndroidRuntime: FATAL EXCEPTION: main",
                       signal="crash")
    result = triage(_surface(), [obs])
    assert not result.findings
    assert "inconclusive" in result.candidates[0]["why_candidate"]


def test_component_stack_still_produces_a_low_severity_finding():
    log = (f"E/AndroidRuntime(900): FATAL EXCEPTION: main\n"
           f"E/AndroidRuntime(900): Process: {PACKAGE}, PID: 900\n"
           f"E/AndroidRuntime(900): java.lang.NullPointerException: bad extra\n"
           f"E/AndroidRuntime(900):     at {ACTIVITY}.onCreate(BootstrapActivity.java:42)")
    obs = _observation(log_text=log)
    probes._classify(obs, obs.stdout_excerpt, log, PACKAGE, component=ACTIVITY)
    assert obs.signal == "crash" and obs.interesting
    result = triage(_surface(), [obs])
    assert len(result.findings) == 1
    assert result.findings[0].severity == "low"
    assert result.findings[0].observations == [obs.id]


def test_exploit_oracle_does_not_confirm_provider_startup_failure():
    payload = payloads.Payload("test", "test", expect={"crash": True})
    before = oracle.Snapshot(pid="5610")
    after = oracle.Snapshot(pid="")
    verdict = oracle.evaluate(payload, before, after, package=PACKAGE,
                              log_text=STARTUP_LOG, target_component=ACTIVITY)
    assert not verdict.hit
    assert "startup_crash" in verdict.signals
    assert "crash" not in verdict.signals
