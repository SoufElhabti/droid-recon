"""The compact report keeps standards and platform context tied to actual checks."""

import json

from droid_recon import report
from droid_recon.models import AttackSurface, Component, Finding, IntentFilter
from droid_recon.session import Session


def test_report_maps_recorded_checks_and_qualifies_web_links(tmp_path):
    component = Component(
        name="org.example.app.Link", type="activity", exported=True,
        reachable_from="browser", intent_filters=[IntentFilter(
            actions=["android.intent.action.VIEW"],
            categories=["android.intent.category.BROWSABLE"],
            data=[{"scheme": "https", "host": "example.test"}],
        )],
    )
    surface = AttackSurface(package="org.example.app", target_sdk=36,
                            components=[component])
    session = Session.open(surface.package, tmp_path)
    session.write_surface(surface)
    session.record_coverage("manifest", "tested", component=component.name,
                            result_state="STATIC_CANDIDATE")
    session.record_coverage("ordinary_uid", "skipped", component=component.name,
                            reason="no device")

    doc = report.build(session)
    entries = doc["coverage"]["entries"]
    manifest = next(e for e in entries if e["stage"] == "manifest")
    ordinary = next(e for e in entries if e["stage"] == "ordinary_uid")
    assert manifest["standards"]["check_id"] == "manifest.activity"
    assert ordinary["standards"]["check_id"] == "dynamic.ordinary_caller"
    assert ordinary["result_state"] == "NOT_TESTED"
    assert manifest["standards"]["verified_control"] is False
    assert "web_app_links_approval_unknown" in {
        caveat["id"] for caveat in doc["android_version_caveats"]
    }
    markdown = report.to_markdown(doc)
    assert "OWASP cross-reference" in markdown
    assert "Android version caveats" in markdown
    assert "developer.android.com" in markdown


def test_ordinary_summary_does_not_count_unverified_caller_as_access(tmp_path):
    session = Session.open("org.example.app", tmp_path)
    artifact = session.dir / "ordinary_results.jsonl"
    artifact.write_text("\n".join(json.dumps(item) for item in [
        {"component": ".Entry", "operation": "activity", "status": "accepted_by_os",
         "accessible": True, "verified_ordinary_uid": True, "request_id": "a"},
        {"component": ".Other", "operation": "activity", "status": "accepted_by_os",
         "accessible": True, "verified_ordinary_uid": False, "request_id": "b"},
    ]), encoding="utf-8")
    doc = report.build(session)
    summary = doc["ordinary_caller_summary"]
    assert summary["accessible"] == 1
    assert summary["inconclusive"] == 1
    assert "Ordinary app caller checks" in report.to_markdown(doc)


def test_ordinary_deeplink_report_uses_package_level_attribution(tmp_path):
    session = Session.open("org.example.app", tmp_path)
    (session.dir / "ordinary_results.jsonl").write_text(json.dumps({
        "component": None, "declared_component": "org.example.app.Link",
        "resolution_scope": "package", "operation": "deeplink",
        "status": "accepted_by_os", "verified_ordinary_uid": True,
        "accessible": True, "request_id": "abc",
    }) + "\n", encoding="utf-8")
    doc = report.build(session)
    assert doc["ordinary_caller_summary"]["examples"][0]["component"] is None
    assert "package-level resolution" in report.to_markdown(doc)


def test_bounded_report_shows_total_findings_and_omitted_count(tmp_path):
    session = Session.open("org.example.app", tmp_path)
    for number in (1, 2):
        session.add_finding(Finding(
            id=f"F{number:03d}", title="reviewed issue", severity="low",
            exploitability="local", confidence="60%", attack_class="ipc",
            component={"name": "org.example.app.Entry", "type": "activity"},
            reachable_from="third_party_app", source={}, sink={},
            chain=["input", "effect"], poc="test", impact="test",
        ))
    doc = report.build(session, top_n=1)
    assert doc["finding_count"] == 2
    assert len(doc["findings"]) == 1
    assert doc["findings_omitted"] == 1
    markdown = report.to_markdown(doc)
    assert "Findings (2)" in markdown
    assert "1 additional finding" in markdown


def test_report_displays_extracted_inputs_with_source_and_uncertainty(tmp_path):
    session = Session.open("org.example.app", tmp_path)
    session.write_code_report({"intent_extras": {
        "by_component": {"org.example.app.Entry": [{
            "key": "ITEM_ID", "type": "int", "accessor": "getIntExtra",
            "source": "org/example/app/Entry.java", "line": 42,
            "default": {"literal": "-1", "type": "int", "line": 42},
            "default_status": "literal",
            "validation_evidence": [{"check": "value_check", "line": 45}],
        }]},
        "global_keys": [{"key": "ITEM_ID"}],
    }})
    doc = report.build(session)
    assert doc["intent_input_summary"]["defaults_observed"] == 1
    assert doc["intent_input_summary"]["validation_evidence_observed"] == 1
    markdown = report.to_markdown(doc)
    assert "Extracted Intent inputs" in markdown
    assert "ITEM_ID" in markdown
    assert "org/example/app/Entry.java:42" in markdown
    assert "effectiveness is unverified" in markdown
