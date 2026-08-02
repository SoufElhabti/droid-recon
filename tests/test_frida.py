"""Built-in Frida script registration and syntax checks."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from droid_recon import shell
from droid_recon.cli import build_parser
from droid_recon.frida import server


def test_lottie_tracer_is_registered_and_cli_selectable():
    scripts = server.list_scripts()
    tracer = scripts["lottie_tracer"]
    assert tracer.is_file()

    args = build_parser().parse_args(
        ["frida", "run", "ma.poneglyph.lottieharness", "--script", "lottie_tracer"]
    )
    assert args.script == "lottie_tracer"
    assert scripts[args.script] == tracer


def test_lottie_tracer_covers_factory_families_without_reading_streams():
    source = server.list_scripts()["lottie_tracer"].read_text()
    for entry in (
        "fromJsonString",
        "fromJsonInputStream",
        "fromJsonReader",
        "fromUrl",
        "fromAsset",
        "fromRawRes",
        "fromZipStream",
    ):
        assert f'"{entry}"' in source

    assert "getStackTrace()" in source
    assert "installCanonicalDirect" in source
    assert 'Java.enumerateMethods("*!*/su")' in source
    assert "getDeclaredMethods" not in source
    assert ".getNextEntry(" not in source
    assert ".available(" not in source

    for entry in ("createWithJson", "getFrame", "setAnimation", "asLottie"):
        assert entry in source
    assert "rlottie-native-wrapper" in source
    assert "rlottie-sticker-delivery" in source

    for entry in (
        "nativeLoadAnimationData",
        "nativeLoadAnimationPath",
        "nativeLoadAnimation",
        "nativeLoadDotLottieData",
    ):
        assert entry in source
    assert "dotlottie-native-player" in source


def test_lottie_tracer_javascript_syntax():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is unavailable")
    tracer = server.list_scripts()["lottie_tracer"]
    proc = subprocess.run(
        [node, "--check", str(tracer)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0, proc.stderr


def test_run_script_returns_complete_output(monkeypatch, tmp_path):
    script = tmp_path / "trace.js"
    script.write_text("console.log('x');")
    transcript = "HEAD\n" + ("x" * 12_000) + "\nTAIL"
    monkeypatch.setattr(server.shell, "which", lambda name: "/frida")
    monkeypatch.setattr(
        server.shell,
        "run",
        lambda argv, timeout: shell.Proc(argv, 0, transcript, ""),
    )

    good, output = server.run_script("com.x", script, duration=1)
    assert good is True
    assert output == transcript
    assert output.endswith("TAIL")


def test_app_event_error_words_do_not_masquerade_as_frida_failure(monkeypatch, tmp_path):
    script = tmp_path / "trace.js"
    script.write_text("console.log('x');")
    transcript = '[lottie] EVENT {"json":"Unable to parse composition"}'
    monkeypatch.setattr(server.shell, "which", lambda name: "/frida")
    monkeypatch.setattr(
        server.shell,
        "run",
        lambda argv, timeout: shell.Proc(argv, 0, transcript, ""),
    )

    good, output = server.run_script("com.x", script, duration=1)
    assert good is True
    assert output == transcript


def test_frida_output_excerpt_keeps_start_and_end():
    output = "START" + ("x" * 10_000) + "END"
    excerpt = server.output_excerpt(output, 500)
    assert len(excerpt) <= 500
    assert excerpt.startswith("START")
    assert excerpt.endswith("END")
    assert "omitted; see artifact" in excerpt


def test_frida_output_is_persisted_without_truncation(tmp_path):
    output = "event\n" * 3000
    path = server.persist_output(output, tmp_path / "frida", "lottie tracer")
    assert path is not None
    assert path.parent == tmp_path / "frida"
    assert path.name.startswith("lottie-tracer-")
    assert path.read_text() == output
