from argparse import Namespace

import pytest

from droid_recon.models import AttackSurface
from droid_recon.runs import bind_device, prepare
from droid_recon.session import Session


def test_new_audit_preserves_previous_artifacts_and_resume_checks_inputs(tmp_path):
    session = Session.open("example.app", tmp_path)
    session.observations_path.write_text('{"id":"old"}\n')
    surface = AttackSurface(package="example.app", apk_sha256="abc")
    args = Namespace(limit=2, password="never-save-this")
    active = prepare(session, surface, args, resume=False)
    assert not session.observations_path.exists()
    assert list((session.dir / "runs").rglob("observations.jsonl"))
    assert prepare(session, surface, args, resume=True)["run_id"] == active["run_id"]
    assert "never-save-this" not in (session.dir / "run_manifest.json").read_text()
    try:
        prepare(session, surface, Namespace(limit=3), resume=True)
    except ValueError as exc:
        assert "differ" in str(exc)
    else:
        raise AssertionError("mismatched audit options were accepted")


def test_resume_rejects_a_different_automatically_selected_device(tmp_path):
    session = Session.open("example.app", tmp_path)
    surface = AttackSurface(package="example.app", apk_sha256="abc")
    args = Namespace(serial=None)
    prepare(session, surface, args, resume=False)
    bind_device(session, "emulator-5554")
    assert prepare(session, surface, args, resume=True)["device_serial"] == "emulator-5554"
    bind_device(session, "emulator-5554")
    with pytest.raises(ValueError, match="active run used device"):
        bind_device(session, "emulator-5556")
