"""Measured fixture corpus for local source-to-sink candidates."""

from pathlib import Path

import pytest

from droid_recon.models import AttackSurface, Component
from droid_recon.static import flows


CORPUS = Path(__file__).parent / "benchmark"
CASES = (
    ("webview_unguarded", True, "WebView.loadUrl"),
    ("webview_guarded", False, "WebView.loadUrl"),
    ("command_unguarded", True, "Runtime.exec"),
    ("command_fixed", False, None),
    ("redirect_unguarded", True, "startActivity"),
    ("redirect_guarded", False, "startActivity"),
    ("sql_unguarded", True, "raw SQL"),
    ("sql_parameterized", False, None),
)


def _surface(*, reachable: str = "browser") -> AttackSurface:
    return AttackSurface(package="com.example.flow", components=[Component(
        name="com.example.flow.Entry", type="activity", exported=True,
        reachable_from=reachable,
    )])


def _run_case(tmp_path, name: str, *, reachable: str = "browser") -> dict:
    target = tmp_path / "com" / "example" / "flow" / "Entry.java"
    target.parent.mkdir(parents=True)
    target.write_text((CORPUS / name / "Entry.java").read_text())
    return flows.analyze(tmp_path, _surface(reachable=reachable))


@pytest.mark.parametrize("case,expected_high,expected_sink", CASES)
def test_benchmark_case(tmp_path, case, expected_high, expected_sink):
    result = _run_case(tmp_path, case)
    high = [candidate for candidate in result["candidates"]
            if candidate["review_bucket"] == "no_guard_seen"]
    assert bool(high) is expected_high, case
    if expected_sink:
        assert any(candidate["sink"]["api"] == expected_sink
                   for candidate in result["candidates"])
        assert all(candidate["result_state"] == "STATIC_CANDIDATE"
                   for candidate in result["candidates"])
    else:
        assert result["candidates"] == []


def test_benchmark_confusion_matrix_has_no_false_claims(tmp_path):
    # High-priority means a same-method flow with no nearby guard seen. A
    # guarded_candidate remains visible for review but is not counted as an
    # unguarded alert. This small corpus measures the heuristic, not Android.
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case, expected_high, _ in CASES:
        result = _run_case(tmp_path / case, case)
        detected = result["summary"]["no_guard_seen"] > 0
        if detected and expected_high:
            counts["tp"] += 1
        elif detected:
            counts["fp"] += 1
        elif expected_high:
            counts["fn"] += 1
        else:
            counts["tn"] += 1
    assert counts == {"tp": 4, "fp": 0, "fn": 0, "tn": 4}


def test_source_lines_validation_and_reachability_are_explicit(tmp_path):
    result = _run_case(tmp_path, "webview_guarded")
    candidate = result["candidates"][0]
    assert candidate["source"]["line"] == 4
    assert candidate["sink"]["line"] == 10
    assert candidate["review_bucket"] == "guard_seen"
    assert {check["kind"] for check in candidate["nearby_validation"]} == {
        "URI scheme/host comparison"
    }
    assert result["limitations"]

    shell_only = _run_case(tmp_path / "private", "webview_unguarded", reachable="shell")
    assert shell_only["summary"]["reachable_components"] == 0
    assert shell_only["candidates"] == []


def test_multiline_sink_and_method_boundary(tmp_path):
    target = tmp_path / "com" / "example" / "flow" / "Entry.java"
    target.parent.mkdir(parents=True)
    target.write_text('''
        class Entry {
            void vulnerable() {
                String url = getIntent().getStringExtra("url");
                webView.loadUrl(
                    url
                );
            }
            void unrelated() {
                webView.loadUrl("https://safe.example");
            }
        }
    ''')
    result = flows.analyze(tmp_path, _surface())
    assert len(result["candidates"]) == 1
    assert result["candidates"][0]["method"] == "vulnerable"
