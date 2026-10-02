from argparse import Namespace
from pathlib import Path

from droid_recon import evidence
from droid_recon.models import AttackSurface


def test_evidence_records_hashes_and_excludes_credentials(tmp_path: Path, monkeypatch):
    apk = tmp_path / "target.apk"
    apk.write_bytes(b"fixture")
    monkeypatch.setattr(evidence, "signing_fingerprint",
                        lambda path: {"sha256": ["fingerprint"]})
    surface = AttackSurface(package="example.app", apk_paths=[str(apk)], target_sdk=35)
    args = Namespace(screenshots=True, password="secret-value", api_key="secret-key")
    doc = evidence.record(tmp_path / "session", surface, args=args)
    assert doc["apks"][0]["sha256"] == evidence._sha256(apk)
    assert doc["sdk"]["target"] == 35
    raw = (tmp_path / "session" / "evidence_manifest.json").read_text()
    assert "secret-value" not in raw
    assert "secret-key" not in raw


def test_evidence_updates_context_without_losing_first_stage(tmp_path: Path):
    surface = AttackSurface(package="example.app")
    evidence.record(tmp_path, surface)
    doc = evidence.record(tmp_path, surface, execution_context="adb_shell",
                          device_info={"sdk": "34", "webview_package": "WebView 1"})
    assert doc["execution_contexts"] == ["static_only", "adb_shell"]
    assert doc["sdk"]["device"] == "34"
