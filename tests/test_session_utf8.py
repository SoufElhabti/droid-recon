"""Session artifacts must round-trip Unicode on Windows' non-UTF-8 locale."""

from __future__ import annotations

from droid_recon.models import AttackSurface, Observation, SessionState
from droid_recon.session import Session


def test_session_artifacts_round_trip_unicode(tmp_path):
    text = "رابط عميق — 日本語 🔎"
    session = Session.open("com.example.target", tmp_path)

    state = SessionState(session_id="utf8", target_package=session.package, phase=text)
    session.save_state(state)
    assert session.load_state().phase == text

    surface = AttackSurface(package=session.package, app_issues=[text])
    session.write_surface(surface)
    assert session.read_surface().app_issues == [text]

    session.write_code_report({"note": text})
    assert session.read_code_report() == {"note": text}

    session.add_observation(Observation(
        id="O0001", kind="deeplink", package=session.package,
        component=None, reachable_from="browser", stdout_excerpt=text,
        detail={"label": text},
    ))
    assert session.observations()[0].detail["label"] == text

    session.record_coverage("ipc", "skipped", reason=text)
    assert session.coverage_summary()["entries"][0]["reason"] == text

    session.add_dead_end(text, text)
    assert text in session.dead_ends_path.read_bytes().decode("utf-8")
