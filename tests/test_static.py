"""UriMatcher path extraction, pattern sweep, and session persistence."""

from __future__ import annotations

import pytest

from droid_recon.models import Observation, SessionState
from droid_recon.session import Session
from droid_recon.static import patterns, sweep, urimatcher
from droid_recon.static.manifest import parse_manifest, resolve_apks

from .fixtures import KNOWN_ANSWERS_MANIFEST, PROVIDER_JAVA, SINK_JAVA


@pytest.fixture
def java_tree(tmp_path):
    root = tmp_path / "sources"
    pkg = root / "com" / "example" / "target"
    pkg.mkdir(parents=True)
    (pkg / "OpenProvider.java").write_text(PROVIDER_JAVA)
    (pkg / "BrowsableActivity.java").write_text(SINK_JAVA)
    # Library noise that must be filtered out of the focused view.
    lib = root / "androidx" / "webkit"
    lib.mkdir(parents=True)
    (lib / "Internal.java").write_text(
        "class Internal { void f(android.webkit.WebView w){ w.loadUrl(\"x\"); } }"
    )
    return root


# ---- UriMatcher ----

def test_extracts_addURI_literal_paths(java_tree):
    out = urimatcher.extract(java_tree, ["com.example.target.open"])
    paths = out["paths"]["com.example.target.open"]
    assert "notes" in paths
    assert "secrets" in paths


def test_numeric_wildcard_becomes_probeable(java_tree):
    """`notes/#` is a UriMatcher pattern; `content query` needs a concrete value."""
    out = urimatcher.extract(java_tree, ["com.example.target.open"])
    paths = out["paths"]["com.example.target.open"]
    assert "notes/1" in paths, paths
    assert "notes/#" not in paths


def test_resolves_authority_through_a_constant(java_tree):
    """addURI(AUTHORITY, ...) must resolve via `static final String AUTHORITY = "..."`."""
    out = urimatcher.extract(java_tree, ["com.example.target.open"])
    assert out["consts_seen"] >= 1
    assert out["paths"]["com.example.target.open"]


def test_harvests_literal_content_uris(java_tree):
    out = urimatcher.extract(java_tree, ["com.example.target.open"])
    assert "content://com.example.target.open/notes" in out["uris"]


def test_probeable_substitutes_wildcards():
    assert urimatcher._probeable("notes/#") == "notes/1"
    assert urimatcher._probeable("files/*") == "files/x"
    assert urimatcher._probeable("/leading/") == "leading"


# ---- sweep ----

def test_sweep_finds_sinks_and_sources(java_tree):
    surface = parse_manifest(KNOWN_ANSWERS_MANIFEST)
    report = sweep.sweep(java_tree, surface)
    labels = {h.label for h in report.sink_hits}
    assert "WebView.loadUrl" in labels
    assert "WebView.addJavascriptInterface" in labels
    assert "setAllowUniversalAccessFromFileURLs(true)" in labels
    assert "startActivity(getParcelableExtra) — intent redirect" in labels
    assert any(h.label == "getIntent().getXExtra" for h in report.source_hits)


def test_library_hits_are_marked_and_excluded(java_tree):
    surface = parse_manifest(KNOWN_ANSWERS_MANIFEST)
    report = sweep.sweep(java_tree, surface)
    lib_hits = [h for h in report.sink_hits if h.library]
    assert lib_hits, "the androidx fixture should have produced a library hit"
    assert all("androidx" in h.file for h in lib_hits)
    assert len(report.app_only(report.sink_hits)) < len(report.sink_hits)


def test_focused_view_prioritises_exported_components(java_tree):
    surface = parse_manifest(KNOWN_ANSWERS_MANIFEST)
    report = sweep.sweep(java_tree, surface)
    view = sweep.focused(report, surface)
    assert view["sinks"], "expected sinks in the focused view"
    assert all(not h.get("library") for h in view["sinks"])
    assert any(h["in_exported_component"] for h in view["sinks"])


def test_is_library_path():
    assert patterns.is_library_path("androidx/core/App.java")
    assert patterns.is_library_path("com/google/gson/Gson.java")
    assert not patterns.is_library_path("com/example/target/Main.java")


# ---- verdicts ----

def test_verdict_skips_when_nothing_exported():
    surface = parse_manifest(
        '<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.x"><application><activity android:name=".A" android:exported="false"/>'
        "</application></manifest>"
    )
    assert sweep.verdict(surface).startswith("SKIP")


def test_verdict_low_when_all_exported_are_signature_guarded():
    surface = parse_manifest(
        '<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.x"><application>'
        '<activity android:name=".A" android:exported="true"'
        ' android:permission="android.permission.BIND_JOB_SERVICE"/>'
        "</application></manifest>"
    )
    v = sweep.verdict(surface)
    assert v.startswith("LOW"), v
    assert "not reachable by a third-party app" in v


def test_verdict_investigates_real_surface():
    surface = parse_manifest(KNOWN_ANSWERS_MANIFEST)
    assert sweep.verdict(surface).startswith("INVESTIGATE")


# ---- input handling ----

def test_resolve_apks_rejects_a_directory_without_apks(tmp_path):
    d = tmp_path / "extracted.apk"
    d.mkdir()
    (d / "AndroidManifest.xml").write_text("<manifest/>")
    with pytest.raises(ValueError, match="no valid APK"):
        resolve_apks(d)


def test_resolve_apks_rejects_a_non_zip_file(tmp_path):
    f = tmp_path / "fake.apk"
    f.write_text("not a zip")
    with pytest.raises(ValueError, match="not a valid APK"):
        resolve_apks(f)


def test_resolve_apks_rejects_missing_path(tmp_path):
    with pytest.raises(ValueError, match="no such path"):
        resolve_apks(tmp_path / "nope.apk")


def test_resolve_apks_orders_base_before_splits(tmp_path):
    import zipfile

    d = tmp_path / "split_set"
    d.mkdir()
    for name in ("config.arm64_v8a.apk", "base.apk", "config.en.apk"):
        with zipfile.ZipFile(d / name, "w") as zf:
            zf.writestr("AndroidManifest.xml", "x")
    got = resolve_apks(d)
    assert got[0].name == "base.apk"
    assert len(got) == 3


# ---- session ----

def test_session_streams_are_separate(tmp_path):
    s = Session.open("com.x", tmp_path)
    s.add_observation(Observation(
        id="O1", kind="launch_activity", package="com.x", component="com.x.A",
        reachable_from="shell", signal="ok",
    ))
    assert s.count_observations() == 1
    assert s.count_findings() == 0, "observations must never land in findings.jsonl"


def test_session_state_roundtrip(tmp_path):
    s = Session.open("com.x", tmp_path)
    state = SessionState(session_id="sid", target_package="com.x", components_total=9)
    s.save_state(state)
    loaded = s.load_state()
    assert loaded is not None
    assert loaded.session_id == "sid"
    assert loaded.components_total == 9


def test_session_resumes_steps(tmp_path):
    s = Session.open("com.x", tmp_path)
    state = SessionState(session_id="sid", target_package="com.x")
    s.mark_step(state, "static")
    s.mark_step(state, "code")
    s.mark_step(state, "static")  # idempotent
    assert s.load_state().steps_done == ["static", "code"]


def test_dead_ends_are_appended(tmp_path):
    s = Session.open("com.x", tmp_path)
    s.add_dead_end("provider com.x.auth", "no addURI literals found")
    s.add_dead_end("frida", "server would not start")
    text = s.dead_ends_path.read_text()
    assert "no addURI literals found" in text
    assert "frida" in text
    assert text.count("- **") == 2


def test_next_finding_id_increments(tmp_path):
    from droid_recon.models import Finding

    s = Session.open("com.x", tmp_path)
    assert s.next_finding_id() == "F001"
    s.add_finding(Finding(
        id="F001", title="t", severity="low", exploitability="local-zero-click",
        confidence="80%", attack_class="x", component={}, reachable_from="third_party_app",
        source={}, sink={}, chain=["a", "b", "c"], poc="p", impact="i",
    ))
    assert s.next_finding_id() == "F002"


# ---- floating paths and call() methods ----

def test_unresolved_authority_paths_are_kept_separate(tmp_path):
    """A path whose authority we can't resolve must NOT be attributed to every provider.

    Fanning it out would make the report claim the code said something it didn't.
    """
    root = tmp_path / "sources" / "com" / "x"
    root.mkdir(parents=True)
    (root / "P.java").write_text(
        'class P { static { M.addURI(SOME_UNKNOWN_CONST, "widgets", 1); '
        'M.addURI("com.x.known", "gadgets", 2); } }'
    )
    out = urimatcher.extract(tmp_path / "sources", ["com.x.known", "com.x.other"])
    assert out["paths"]["com.x.known"] == ["gadgets"]
    assert "com.x.other" not in out["paths"], "must not fan out to unrelated authorities"
    assert "widgets" in out["floating_paths"]


def test_extracts_contentprovider_call_methods(tmp_path):
    """call() bypasses the UriMatcher and is often unguarded when query() is not."""
    root = tmp_path / "sources" / "com" / "x"
    root.mkdir(parents=True)
    (root / "P.java").write_text('''
        class P extends android.content.ContentProvider {
            public Bundle call(String method, String arg, Bundle extras) {
                if (method.equals("getDeviceId")) { return a(); }
                if (method.equals("setAuthToken")) { return b(); }
                switch (method) { case "dumpState": return c(); }
                return null;
            }
        }
    ''')
    out = urimatcher.extract(tmp_path / "sources", ["com.x.p"])
    assert "getDeviceId" in out["call_methods"]
    assert "setAuthToken" in out["call_methods"]
    assert "dumpState" in out["call_methods"]


def test_no_call_methods_when_provider_has_no_call(java_tree):
    out = urimatcher.extract(java_tree, ["com.example.target.open"])
    assert out["call_methods"] == []


# ---- device-shell quoting (regression: payloads torn apart at `;`) ----

def test_device_quote_protects_shell_metacharacters():
    """An intent URI contains `;` — unquoted, the DEVICE shell splits the command."""
    from droid_recon.shell import _device_quote

    uri = "intent:#Intent;component=com.x/.A;S.k=v;end"
    q = _device_quote(uri)
    assert q.startswith("'") and q.endswith("'")
    assert ";" in q  # preserved, but inside quotes


def test_device_quote_leaves_plain_tokens_alone():
    from droid_recon.shell import _device_quote

    for plain in ("am", "start", "-n", "com.x/.A", "content://a/b", "1.5"):
        assert _device_quote(plain) == plain


def test_device_quote_handles_embedded_single_quotes():
    from droid_recon.shell import _device_quote

    assert _device_quote("O'Brien") == "'O'\\''Brien'"


def test_device_quote_handles_empty_and_spaces():
    from droid_recon.shell import _device_quote

    assert _device_quote("") == "''"
    assert _device_quote("a b") == "'a b'"


def test_sql_selection_payloads_survive_quoting():
    """`' OR '1'='1` must reach the provider intact, quotes and all."""
    from droid_recon.device import payloads as pl
    from droid_recon.shell import _device_quote

    for sel in pl.sql_injection_selection():
        q = _device_quote(sel)
        assert q  # never empty
        if any(ch in sel for ch in " '\";"):
            assert q.startswith("'")
