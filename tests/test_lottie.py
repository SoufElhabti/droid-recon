"""Lottie Q1-Q10 fingerprinting and local delivery-path tracing."""

from __future__ import annotations

import zipfile
from pathlib import Path

from droid_recon.static import lottie


def _java(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _apk(path: Path, entries: dict[str, str | bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return path


def test_answers_q1_through_q10_and_traces_delivery_sources(tmp_path):
    tree = tmp_path / "sources"
    _java(tree, "x/a.java", """
        package x;
        class a {
          String p = "Unable to parse composition";
          String q = "Unknown layer type";
          String r = "You must set an images folder";
        }
    """)
    _java(tree, "app/LottieEntry.java", """
        package app;
        import android.webkit.WebView;
        class LottieEntry {
          void render() {
            String animationUrl = getIntent().getStringExtra("animation_url");
            view.setAnimationFromUrl(animationUrl);
            view.setImageAssetDelegate(new AppImages());
            view.setExpression("opacity", expression);

            String json = response.body().string();
            view.setAnimation(json);

            android.net.Uri uri = getIntent().getData();
            java.io.InputStream stream = getContentResolver().openInputStream(uri);
            factory.fromJsonInputStream(stream, "provider");

            WebView web = new WebView(context);
            web.addJavascriptInterface(bridge, "native");
            String page = "file:///android_asset/player.html";
            web.loadUrl(page);
          }
        }
    """)

    base = _apk(tmp_path / "base.apk", {
        # No class/package symbol: Q1 must succeed from stable strings.
        "classes.dex": b"dex\x00Unable to extract font\x00data URL did not have correct base64",
        "assets/lottie.min.js": "window.bodymovin = {};",
        "assets/player.html": '<script src="lottie.min.js"></script>',
        "res/raw/welcome.lottie": b"PK fake dotLottie",
        "META-INF/maven/com.airbnb.android/lottie/pom.properties": "version=6.7.1\n",
    })
    split = _apk(tmp_path / "config.arm64_v8a.apk", {
        "lib/arm64-v8a/librlottie.so": b"\x7fELF",
    })

    report = lottie.analyze(tree, [base, split])
    q = report["questions"]

    assert q["q1_lottie_android"]["answer"] is True
    assert q["q1_lottie_android"]["confidence"] == "high"
    assert q["q1_lottie_android"]["symbol_markers"] == []
    assert q["q2_lottie_android_version"]["answer"] == "6.7.1"
    for key in (
        "q3_lottie_web", "q4_rlottie", "q5_dotlottie", "q6_expressions",
        "q7_custom_asset_delegates", "q8_url_loading", "q9_intent_loading",
        "q10_lottie_webview",
    ):
        assert q[key]["answer"] is True, (key, q[key])

    assert report["summary"]["stacks_present"] == [
        "lottie-android", "lottie-web", "rlottie", "dotlottie",
    ]
    assert report["summary"]["attacker_influenced_delivery"] is True
    sources = {
        source["type"]
        for path in report["delivery_paths"]
        for source in path["sources"]
    }
    assert {"intent", "http_response", "content_provider"} <= sources

    web_flow = q["q10_lottie_webview"]["evidence"][0]
    assert web_flow["asset"] == "player.html"
    assert web_flow["javascript_bridge"] is True
    assert report["coverage"]["apk_files_scanned"] == 2


def test_obfuscated_dex_strings_are_sufficient_without_java_symbols(tmp_path):
    tree = tmp_path / "sources"
    tree.mkdir()
    apk = _apk(tmp_path / "obfuscated.apk", {
        "classes.dex": (
            b"dex\x00Unable to parse composition\x00Unknown layer type\x00"
            b"data URL did not have correct base64"
        ),
    })

    q1 = lottie.analyze(tree, apk)["questions"]["q1_lottie_android"]
    assert q1["answer"] is True
    assert q1["confidence"] == "high"
    assert q1["symbol_markers"] == []
    assert {e["kind"] for e in q1["evidence"]} == {"dex_stable_string"}


def test_renamed_rlottie_fork_is_found_from_wrapper_and_native_symbols(tmp_path):
    tree = tmp_path / "sources"
    _java(tree, "com/acme/rlottie/RLottieDrawable.java", """
        package com.acme.rlottie;
        final class RLottieDrawable {
          static native long createWithJson(String json, int width, int height);
          static native int getFrame(long ptr, int frame, Object bitmap);
          static native void replaceColors(long ptr, int[] colors);
        }
    """)
    apk = _apk(tmp_path / "renamed.apk", {
        "classes.dex": b"dex",
        "lib/arm64-v8a/libdsti.so": (
            b"\x7fELF\x00_ZN7rlottie9Animation12loadFromData\x00"
            b"_ZN7rlottie9Animation10renderSync\x00"
        ),
    })

    q4 = lottie.analyze(tree, apk)["questions"]["q4_rlottie"]
    assert q4["answer"] is True
    assert q4["confidence"] == "high"
    assert {e["kind"] for e in q4["evidence"]} == {
        "java_native_wrapper", "native_symbol",
    }


def test_renamed_dotlottie_thorvg_expression_engine_is_fingerprinted(tmp_path):
    tree = tmp_path / "sources"
    tree.mkdir()
    apk = _apk(tmp_path / "native-player.apk", {
        "lib/arm64-v8a/libopaque.so": (
            b"\x7fELF\x00dotlottie_load_animation_data\x00"
            b"dotlottie_load_dotlottie_data\x00$bm_rt\x00propertyGroup\x00"
            b"toComp\x00valueAtTime\x00"
        ),
    })

    report = lottie.analyze(tree, apk)
    q5 = report["questions"]["q5_dotlottie"]
    q6 = report["questions"]["q6_expressions"]

    assert q5["answer"] is True
    assert q5["confidence"] == "high"
    assert {e["kind"] for e in q5["evidence"]} == {"native_dotlottie_api"}
    assert q6["answer"] is True
    assert q6["confidence"] == "high"
    assert q6["evidence"][0]["kind"] == (
        "native_dotlottie_thorvg_expression_engine"
    )
    assert set(q6["evidence"][0]["expression_markers"]) == {
        "$bm_rt", "propertyGroup", "toComp", "valueAtTime",
    }
    assert "dotlottie-native-thorvg-expressions" in (
        report["summary"]["stacks_present"]
    )


def test_b64_partial_overwrite_sink_reported_with_expression_engine(tmp_path):
    """The base64 data-URI decoder is a parse-time raw-byte heap write.

    Its allocation size comes from ``strlen`` while writing stops at ``=``
    padding, so it can partially overwrite a freed same-size-class object and
    keep that object's slide-bearing bytes.  Verified on the released
    dotlottie-android 0.15.0 arm64 player.
    """
    tree = tmp_path / "sources"
    tree.mkdir()
    apk = _apk(tmp_path / "b64-player.apk", {
        "lib/arm64-v8a/libopaque.so": (
            b"\x7fELF\x00dotlottie_load_animation_data\x00"
            b"dotlottie_load_dotlottie_data\x00$bm_rt\x00propertyGroup\x00"
            b"toComp\x00valueAtTime\x00data:font/\x00;base64,\x00data:image\x00"
        ),
    })

    q6 = lottie.analyze(tree, apk)["questions"]["q6_expressions"]
    engine = q6["evidence"][0]

    assert engine["kind"] == "native_dotlottie_thorvg_expression_engine"
    assert engine["b64_partial_overwrite_reachable"] is True
    assert set(engine["b64_raw_write_sink"]) == {
        "data:font/", ";base64,", "data:image",
    }


def test_b64_sink_not_claimed_without_a_native_expression_engine(tmp_path):
    """Embedded-font/image support alone is ordinary and must not be flagged."""
    tree = tmp_path / "sources"
    tree.mkdir()
    apk = _apk(tmp_path / "plain-loader.apk", {
        "lib/arm64-v8a/libimg.so": (
            b"\x7fELF\x00data:font/\x00;base64,\x00data:image\x00"
        ),
    })

    q6 = lottie.analyze(tree, apk)["questions"]["q6_expressions"]

    assert q6["answer"] is False
    assert not any(
        e.get("b64_partial_overwrite_reachable") for e in q6["evidence"]
    )


def test_native_expression_marker_requires_same_elf_and_multiple_markers(tmp_path):
    tree = tmp_path / "sources"
    tree.mkdir()
    apk = _apk(tmp_path / "near-miss.apk", {
        "lib/arm64-v8a/libformat.so": (
            b"\x7fELF\x00dotlottie_load_animation_data\x00propertyGroup\x00"
        ),
        "lib/arm64-v8a/libunrelated.so": (
            b"\x7fELF\x00$bm_rt\x00toComp\x00valueAtTime\x00"
        ),
    })

    report = lottie.analyze(tree, apk)
    assert report["questions"]["q5_dotlottie"]["answer"] is True
    assert report["questions"]["q6_expressions"]["answer"] is False
    assert "dotlottie-native-thorvg-expressions" not in (
        report["summary"]["stacks_present"]
    )


def test_native_expression_marker_requires_three_markers_in_one_elf(tmp_path):
    tree = tmp_path / "sources"
    tree.mkdir()
    apk = _apk(tmp_path / "two-markers.apk", {
        "lib/arm64-v8a/libpartial.so": (
            b"\x7fELF\x00dotlottie_load_animation_data\x00"
            b"$bm_rt\x00propertyGroup\x00"
        ),
    })

    report = lottie.analyze(tree, apk)
    assert report["questions"]["q5_dotlottie"]["answer"] is True
    assert report["questions"]["q6_expressions"]["answer"] is False


def test_native_markers_in_non_elf_so_are_not_engine_evidence(tmp_path):
    tree = tmp_path / "sources"
    tree.mkdir()
    apk = _apk(tmp_path / "spoofed.apk", {
        "lib/arm64-v8a/libspoof.so": (
            b"not-an-elf\x7fELF\x00dotlottie_load_animation_data\x00"
            b"$bm_rt\x00propertyGroup\x00"
            b"toComp\x00valueAtTime\x00"
        ),
    })

    report = lottie.analyze(tree, apk)
    assert report["questions"]["q5_dotlottie"]["answer"] is False
    assert report["questions"]["q6_expressions"]["answer"] is False
    assert report["coverage"]["archive_bytes_scanned"] == 0


def test_version_is_recovered_from_an_obfuscated_build_config(tmp_path):
    tree = tmp_path / "sources"
    _java(tree, "x/b.java", """
        package x;
        final class b {
          static final String LIBRARY_PACKAGE_NAME = "com.airbnb.lottie";
          static final String VERSION_NAME = "5.2.0";
        }
    """)
    apk = _apk(tmp_path / "app.apk", {"classes.dex": b"dex"})

    q2 = lottie.analyze(tree, apk)["questions"]["q2_lottie_android_version"]
    assert q2["answer"] == "5.2.0"
    assert q2["confidence"] == "high"


def test_library_api_definitions_and_unrelated_set_animation_are_not_delivery(tmp_path):
    tree = tmp_path / "sources"
    _java(tree, "com/airbnb/lottie/LottieAnimationView.java", """
        package com.airbnb.lottie;
        class LottieAnimationView {
          void setAnimationFromUrl(String url) {
            LottieCompositionFactory.fromUrl(context, url);
          }
          void setImageAssetDelegate(ImageAssetDelegate delegate) {}
        }
    """)
    _java(tree, "app/Unrelated.java", """
        package app;
        class Unrelated {
          void update() {
            animator.setAnimation(getIntent().getStringExtra("transition"));
          }
        }
    """)
    apk = _apk(tmp_path / "app.apk", {"classes.dex": b"com.airbnb.lottie"})

    report = lottie.analyze(tree, apk)
    q = report["questions"]
    assert q["q1_lottie_android"]["answer"] is True
    assert q["q7_custom_asset_delegates"]["answer"] is False
    assert q["q8_url_loading"]["answer"] is False
    assert q["q9_intent_loading"]["answer"] is False
    assert report["summary"]["attacker_influenced_delivery"] is False


def test_lottie_web_and_webview_cooccurrence_is_only_a_candidate(tmp_path):
    tree = tmp_path / "sources"
    _java(tree, "app/Browser.java", """
        package app;
        import android.webkit.WebView;
        class Browser {
          void open() {
            WebView web = new WebView(context);
            web.loadUrl("https://example.test/unrelated");
          }
        }
    """)
    apk = _apk(tmp_path / "app.apk", {
        "assets/lottie.min.js": "window.bodymovin = {};",
    })

    q = lottie.analyze(tree, apk)["questions"]
    assert q["q3_lottie_web"]["answer"] is True
    assert q["q10_lottie_webview"]["answer"] is False
    assert q["q10_lottie_webview"]["confidence"] == "not_demonstrated"
    assert len(q["q10_lottie_webview"]["candidates"]) == 1


def test_brief_keeps_all_answers_but_bounds_repeated_evidence():
    report = {
        "summary": {"stacks_present": ["lottie-android"]},
        "questions": {
            "q1_lottie_android": {
                "answer": True,
                "confidence": "high",
                "evidence": [{"n": i} for i in range(10)],
            },
            "q2_lottie_android_version": {
                "answer": None,
                "confidence": "unknown",
                "evidence": [],
            },
        },
        "delivery_paths": [{"n": i} for i in range(20)],
    }

    out = lottie.brief(report, evidence_per_question=2, max_delivery_paths=3)
    assert set(out["questions"]) == set(report["questions"])
    assert len(out["questions"]["q1_lottie_android"]["evidence"]) == 2
    assert len(out["delivery_paths"]) == 3


def test_overwritten_intent_value_is_not_reported_as_attacker_influenced(tmp_path):
    tree = tmp_path / "sources"
    _java(tree, "app/Entry.java", """
        class Entry {
          void render() {
            String json = getIntent().getStringExtra("animation");
            json = "safe.json";
            lottieView.setAnimation(json);
          }
        }
    """)
    apk = _apk(tmp_path / "app.apk", {"classes.dex": b"com.airbnb.lottie"})

    report = lottie.analyze(tree, apk)
    assert report["delivery_paths"][0]["sources"] == []
    assert report["summary"]["attacker_influenced_delivery"] is False
    assert report["summary"]["needs_dynamic_confirmation"] is True


def test_unrelated_string_and_database_query_are_not_delivery_sources(tmp_path):
    tree = tmp_path / "sources"
    _java(tree, "app/Entry.java", """
        class Entry {
          void render() {
            String formatted = formatter.string();
            lottieView.setAnimation(formatted);
            Object row = database.query("animations");
            factory.fromJsonString(row, "cache");
            String extra = settings.getStringExtra("bundled_name");
            lottieView.setAnimation(extra);
          }
        }
    """)
    apk = _apk(tmp_path / "app.apk", {"classes.dex": b"com.airbnb.lottie"})

    report = lottie.analyze(tree, apk)
    assert all(not path["sources"] for path in report["delivery_paths"])
    assert report["summary"]["attacker_influenced_delivery"] is False


def test_receiver_qualified_http_and_provider_sources_still_trace(tmp_path):
    tree = tmp_path / "sources"
    _java(tree, "app/Entry.java", """
        class Entry {
          void render() {
            String json = response.body().string();
            lottieView.setAnimation(json);
            Object stream = contentResolver.openInputStream(uri);
            factory.fromJsonInputStream(stream, "provider");
          }
        }
    """)
    apk = _apk(tmp_path / "app.apk", {"classes.dex": b"com.airbnb.lottie"})

    report = lottie.analyze(tree, apk)
    sources = {
        source["type"]
        for path in report["delivery_paths"]
        for source in path["sources"]
    }
    assert {"http_response", "content_provider"} <= sources
    assert report["summary"]["attacker_influenced_delivery"] is True


def test_archive_text_scan_has_a_cumulative_budget(tmp_path, monkeypatch):
    tree = tmp_path / "sources"
    tree.mkdir()
    monkeypatch.setattr(lottie, "MAX_TEXT_SCAN_BYTES", 48)
    apk = _apk(tmp_path / "assets.apk", {
        "assets/first.js": b"bodymovin" + b"a" * 23,
        "assets/second.js": b"lottie.loadAnimation" + b"b" * 23,
    })

    report = lottie.analyze(tree, apk)
    assert report["coverage"]["archive_bytes_scanned"] <= 48
    assert any("text budget" in note for note in report["coverage"]["truncated"])


def test_archive_coverage_notices_are_bounded(tmp_path, monkeypatch):
    tree = tmp_path / "sources"
    tree.mkdir()
    monkeypatch.setattr(lottie, "MAX_TEXT_ASSET_BYTES", 1)
    entries = {f"assets/page-{i}.html": "xx" for i in range(100)}
    apk = _apk(tmp_path / "many-assets.apk", entries)

    notices = lottie.analyze(tree, apk)["coverage"]["truncated"]
    assert len(notices) == lottie.MAX_COVERAGE_NOTICES + 1
    assert notices[-1] == "additional coverage notices omitted"


def _vuln_so() -> bytes:
    return (b"\x7fELF\x00dotlottie_load_animation_data\x00"
            b"dotlottie_load_dotlottie_data\x00$bm_rt\x00propertyGroup\x00"
            b"toComp\x00valueAtTime\x00data:font/\x00;base64,\x00data:image\x00")


def test_scan_many_ranks_the_exploitable_stack_first(tmp_path):
    """Batch triage must put the RCE-precondition stack above mere presence."""
    vuln = _apk(tmp_path / "vuln.apk", {"lib/arm64-v8a/libplayer.so": _vuln_so()})
    # dotLottie format markers in dex only — no native expression engine
    fmt = _apk(tmp_path / "format-only.apk", {"classes.dex": b"DotLottie\x00LottieZip\x00"})
    plain = _apk(tmp_path / "plain.apk", {"classes.dex": b"nothing to see"})

    res = lottie.scan_many({"vuln": [vuln], "format-only": [fmt], "plain": [plain]})

    assert res["scanned"] == 3
    assert res["errors"] == []
    assert res["candidates"] == ["vuln"]
    assert [r["label"] for r in res["results"]][0] == "vuln"
    by = {r["label"]: r for r in res["results"]}
    assert by["vuln"]["verdict"] == "dotlottie_native_expressions_b64"
    assert by["vuln"]["exploitable_stack"] is True
    assert by["format-only"]["exploitable_stack"] is False
    assert by["plain"]["verdict"] == "none"


def test_scan_many_survives_a_hostile_archive(tmp_path):
    """One unreadable APK must not abort a corpus sweep.

    ``analyze`` already degrades a malformed archive to "not found by this pass"
    rather than raising, so the sweep should still report it — as a scanned
    non-candidate, not as an error.  Silently dropping it would read as
    "checked and clean" when it was never parsed.
    """
    good = _apk(tmp_path / "good.apk", {"lib/arm64-v8a/libplayer.so": _vuln_so()})
    bad = tmp_path / "broken.apk"
    bad.write_bytes(b"this is not a zip")

    res = lottie.scan_many({"good": [good], "broken": [bad]})

    assert res["scanned"] == 2
    assert res["errors"] == []
    assert res["candidates"] == ["good"]
    by = {r["label"]: r for r in res["results"]}
    assert by["broken"]["verdict"] == "none"
    assert by["broken"]["exploitable_stack"] is False


def test_scan_one_needs_no_jadx_tree(tmp_path):
    """Triage is archive-only; a missing source tree is expected, not an error."""
    apk = _apk(tmp_path / "x.apk", {"lib/arm64-v8a/libplayer.so": _vuln_so()})

    r = lottie.scan_one(apk, label="x")

    assert r["exploitable_stack"] is True
    assert "dotlottie-native-thorvg-expressions" in r["stacks_present"]
