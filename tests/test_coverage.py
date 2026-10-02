"""Coverage must expose omissions and never upgrade a check without evidence."""

import json

import pytest

from droid_recon import report
from droid_recon.session import Session


def test_recovered_check_replaces_failed_status_without_hiding_other_gaps(tmp_path):
    session = Session.open("org.example.app", tmp_path)
    session.record_coverage(
        "dynamic", "failed", component=".Entry", check="launch",
        reason="emulator was offline",
    )
    session.record_coverage(
        "dynamic", "tested", component=".Entry", check="launch",
        result_state="OBSERVED", evidence_ids=["O001"],
    )
    session.record_coverage(
        "dynamic", "unsupported", component=".Provider", check="call",
        reason="device API does not expose this operation",
    )

    # A reopened session must report current coverage, not count retry events as
    # separate checks or preserve the old failure in the current matrix.
    reopened = Session.open("org.example.app", tmp_path)
    doc = report.build(reopened)
    coverage = doc["coverage"]
    assert coverage["total_checks"] == 2
    assert coverage["by_status"]["failed"] == 0
    assert coverage["by_status"]["tested"] == 1
    assert coverage["by_status"]["unsupported"] == 1
    assert coverage["by_result_state"]["OBSERVED"] == 1
    assert coverage["by_result_state"]["NOT_TESTED"] == 1
    assert doc["artifacts"]["coverage"] == str(session.coverage_path)

    markdown = report.to_markdown(doc)
    assert "Coverage (recorded checks only)" in markdown
    assert "device API does not expose this operation" in markdown
    assert "emulator was offline" not in markdown


def test_absent_ledger_is_explicitly_unknown(tmp_path):
    session = Session.open("org.example.app", tmp_path)
    markdown = report.to_markdown(report.build(session))
    assert "No checks have been recorded" in markdown
    assert "cannot infer what was tested" in markdown


def test_new_run_does_not_claim_checks_from_an_older_run(tmp_path):
    session = Session.open("org.example.app", tmp_path)
    session.begin_coverage_run()
    session.record_coverage("static", "tested", check="manifest")

    new_run_id = session.begin_coverage_run()
    session.record_coverage("dynamic", "skipped", reason="no emulator")
    summary = session.coverage_summary()

    assert summary["run_id"] == new_run_id
    assert summary["total_checks"] == 1
    assert summary["stages"][0]["stage"] == "dynamic"
    assert summary["by_status"]["tested"] == 0
    assert "static" in session.coverage_path.read_text(), "prior events remain available for review"


def test_confirmed_requires_linked_evidence(tmp_path):
    session = Session.open("org.example.app", tmp_path)
    with pytest.raises(ValueError, match="evidence IDs"):
        session.record_coverage("triage", "tested", result_state="CONFIRMED")
    assert not session.coverage_path.exists()

    session.record_coverage(
        "triage", "tested", component=".Entry", result_state="CONFIRMED",
        evidence_ids=["F001", "O001"],
    )
    assert session.coverage_summary()["by_result_state"]["CONFIRMED"] == 1


def test_report_keeps_reproduction_context_compact(tmp_path):
    session = Session.open("org.example.app", tmp_path)
    session.evidence_path.write_text(json.dumps({
        "generated_at": "2026-10-01T12:00:00Z",
        "app_version": {"name": "1.2.3", "code": 12},
        "sdk": {"min": 24, "target": 35, "device": 36},
        "apks": [{
            "path": str(tmp_path / "base.apk"), "sha256": "a" * 64,
            "signing_certificate": {"sha256": ["b" * 64]},
        }],
        "device": {"product": "Test Emulator", "release": "16",
                   "webview_package": "com.android.webview 140"},
        "execution_contexts": ["static_only", "adb_shell"],
        "configuration": {"private-key": "must-not-appear-in-digest"},
    }))

    doc = report.build(session)
    assert doc["artifacts"]["evidence_manifest"] == str(session.evidence_path)
    assert doc["evidence_summary"]["apks"][0]["sha256"] == "a" * 64
    assert "configuration" not in doc["evidence_summary"]
    markdown = report.to_markdown(doc)
    assert "target 35, device 36" in markdown
    assert "com.android.webview 140" in markdown
    assert "must-not-appear-in-digest" not in markdown
