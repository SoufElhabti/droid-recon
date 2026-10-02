"""OWASP references must remain scoped to evidence the tool really collects."""

from datetime import date
from urllib.parse import urlparse

import pytest

from droid_recon import standards


def test_catalog_uses_current_android_references_and_records_review_date():
    assert date.fromisoformat(standards.metadata()["checked_on"])
    assert standards.metadata()["upstream_versions"]["MASTG"].startswith("v2")
    for check_id in standards.check_ids():
        mapping = standards.for_check(check_id)
        assert mapping["verified_control"] is False
        assert mapping["limitation"]
        assert mapping["masvs"] and mapping["maswe"]
        for family in ("masvs", "maswe", "mastg"):
            for ref in mapping[family]:
                assert ref["id"].startswith(family.upper() + "-")
                assert urlparse(ref["url"]).netloc == "mas.owasp.org"
                assert "deprecated" not in ref["title"].lower()


def test_component_mapping_supports_test_without_declaring_a_pass():
    entry = {
        "stage": "static", "check": "manifest", "component": "com.example.Entry",
        "status": "tested", "result_state": "STATIC_CANDIDATE",
    }
    tagged = standards.annotate_coverage(entry, "manifest.activity")
    assert tagged is not entry
    assert tagged["status"] == "tested"
    assert tagged["result_state"] == "STATIC_CANDIDATE"
    assert tagged["standards"]["relationship"] == "supports_test"
    assert tagged["standards"]["verified_control"] is False
    assert [r["id"] for r in tagged["standards"]["mastg"]] == ["MASTG-TEST-0364"]
    assert "standards" not in entry


def test_deeplink_mapping_explicitly_marks_enumeration_as_preparatory():
    mapping = standards.for_check("manifest.deeplink")
    assert mapping["relationship"] == "preparatory"
    assert "does not assess handler validation" in mapping["limitation"]
    assert [ref["id"] for ref in mapping["mastg"]] == ["MASTG-TEST-0394"]


@pytest.mark.parametrize("sink,check_id", [
    ("WebView.loadUrl", "flow.webview"),
    ("WebView.evaluateJavascript", "flow.webview"),
    ("startActivity", "flow.intent"),
    ("Runtime.exec", "flow.untrusted_input"),
    ("ProcessBuilder", "flow.untrusted_input"),
    ("raw SQL", "flow.untrusted_input"),
])
def test_flow_candidate_maps_only_its_recognized_sink(sink, check_id):
    candidate = {"component": "com.example.Entry", "sink": {"api": sink},
                 "result_state": "STATIC_CANDIDATE"}
    tagged = standards.annotate_flow_candidate(candidate)
    assert tagged["standards"]["check_id"] == check_id
    assert tagged["standards"]["relationship"] == "static_candidate"
    assert tagged["standards"]["verified_control"] is False


def test_unknown_check_or_sink_does_not_gain_a_spurious_mapping():
    with pytest.raises(KeyError):
        standards.for_check("not-a-real-check")
    candidate = {"sink": {"api": "SomeFutureSink"}}
    assert standards.annotate_flow_candidate(candidate) == candidate
    assert "standards" not in candidate
