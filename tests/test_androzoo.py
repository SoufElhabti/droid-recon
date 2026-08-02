"""AndroZoo corpus resolution and verified download."""

from __future__ import annotations

import csv
import gzip
import hashlib
from pathlib import Path

import pytest

from droid_recon.corpus import androzoo


HEADER = ["sha256", "sha1", "md5", "dex_date", "apk_size", "pkg_name",
          "vercode", "vt_detection", "vt_scan_date", "dex_size", "markets"]


def _index(path: Path, rows: list[dict]) -> Path:
    with gzip.open(path, "wt", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=HEADER)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in HEADER})
    return path


def _row(sha: str, pkg: str, vercode: str, markets: str) -> dict:
    return {"sha256": sha, "pkg_name": pkg, "vercode": vercode,
            "apk_size": "1234", "markets": markets}


def test_resolve_prefers_play_then_newest_vercode(tmp_path):
    index = _index(tmp_path / "i.csv.gz", [
        _row("a" * 64, "com.target", "100", "play.google.com"),
        _row("b" * 64, "com.target", "900", "appchina"),     # newer but not Play
        _row("c" * 64, "com.target", "300", "play.google.com"),
        _row("d" * 64, "com.other", "1", "play.google.com"),
    ])

    got = androzoo.resolve(index, ["com.target"])

    assert set(got) == {"com.target"}
    # Play beats a higher vercode from a third-party market; within Play, newest wins.
    assert got["com.target"]["sha256"] == "c" * 64
    assert got["com.target"]["from_play"] is True


def test_resolve_falls_back_to_non_play_when_that_is_all_there_is(tmp_path):
    index = _index(tmp_path / "i.csv.gz", [
        _row("e" * 64, "com.only", "5", "appchina"),
    ])

    got = androzoo.resolve(index, ["com.only"])

    assert got["com.only"]["sha256"] == "e" * 64
    assert got["com.only"]["from_play"] is False


def test_resolve_ignores_unrequested_packages_and_empty_input(tmp_path):
    index = _index(tmp_path / "i.csv.gz", [_row("f" * 64, "com.a", "1", "")])

    assert androzoo.resolve(index, []) == {}
    assert androzoo.resolve(index, ["com.absent"]) == {}


def test_verify_rejects_a_mismatched_artifact(tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"real bytes")
    good = hashlib.sha256(b"real bytes").hexdigest()

    assert androzoo.verify(apk, good) is True
    assert androzoo.verify(apk, "0" * 64) is False


def test_fetch_discards_an_artifact_whose_hash_does_not_match(tmp_path, monkeypatch):
    """A corpus that serves the wrong bytes must not poison downstream findings."""
    index = _index(tmp_path / "i.csv.gz", [_row("9" * 64, "com.target", "1", "")])

    def fake_download(sha256, apikey, dest, *, timeout=600):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"not the requested content")
        return dest

    monkeypatch.setattr(androzoo, "download", fake_download)
    out = tmp_path / "out"
    res = androzoo.fetch_packages(index, ["com.target"], "KEY", out)

    assert res["fetched"] == []
    assert res["failed"][0]["reason"] == "sha256 mismatch — discarded"
    assert not list(out.rglob("*.apk")), "the bad artifact must be removed, not kept"


def test_fetch_reports_packages_absent_from_the_index(tmp_path, monkeypatch):
    index = _index(tmp_path / "i.csv.gz", [_row("1" * 64, "com.present", "1", "")])
    monkeypatch.setattr(androzoo, "download", lambda *a, **k: None)

    res = androzoo.fetch_packages(index, ["com.present", "com.missing"], "KEY",
                                  tmp_path / "out")

    assert res["not_in_index"] == ["com.missing"]
    assert res["requested"] == 2
