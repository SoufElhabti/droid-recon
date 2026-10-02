"""Resolve package names to APKs via AndroZoo.

AndroZoo (https://androzoo.uni.lu) is a research APK corpus from the University
of Luxembourg. Access needs an API key, granted on request for research use;
this module never embeds one. The operator supplies it.

Two steps, because the download API is content-addressed:

1. The index (``latest.csv.gz``, multi-GB) maps sha256 -> package name, version
   code, size and market. Resolving a package name means streaming that index.
2. ``GET /api/download?apikey=..&sha256=..`` returns the APK for a hash.

Provenance caveat that matters for reporting: AndroZoo is a *research snapshot*,
not the vendor's current artifact. A hit here is a lead. Before filing anything
against a vendor, re-acquire the APK from a real install and confirm the hash —
a memory-corruption report filed against a stale or third-party binary is
trivially dismissed.
"""

from __future__ import annotations

import csv
import gzip
import io
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

from ..log import say, warn


INDEX_URL = "https://androzoo.uni.lu/static/lists/latest.csv.gz"
DOWNLOAD_URL = "https://androzoo.uni.lu/api/download"

#: Columns we care about in the index CSV.
_SHA256 = "sha256"
_PKG = "pkg_name"
_VERCODE = "vercode"
_SIZE = "apk_size"
_MARKETS = "markets"

#: A single APK download that exceeds this is skipped rather than filling a disk.
MAX_APK_BYTES = 512 * 1024 * 1024


def _vercode(row: dict) -> int:
    try:
        return int(row.get(_VERCODE) or 0)
    except ValueError:
        return 0


def resolve(index: Path, packages: list[str], *,
            prefer_market: str = "play.google.com") -> dict[str, dict]:
    """Stream the AndroZoo index and pick one APK per requested package.

    Selection is the highest ``vercode``, preferring rows whose ``markets``
    column mentions Google Play — a Play-sourced row is far more likely to match
    what users actually run than a third-party mirror's repack.

    Streaming matters: the index does not fit comfortably in memory, and the
    caller may be asking for 20 packages out of ~25 million rows.
    """
    wanted = {p.strip() for p in packages if p.strip()}
    if not wanted:
        return {}

    best: dict[str, dict] = {}
    opener = gzip.open if index.suffix == ".gz" else open
    with opener(index, "rt", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or _SHA256 not in reader.fieldnames:
            warn(f"androzoo index missing expected columns: {index}")
            return {}
        for row in reader:
            pkg = (row.get(_PKG) or "").strip()
            if pkg not in wanted:
                continue
            current = best.get(pkg)
            play = prefer_market in (row.get(_MARKETS) or "")
            if current is None:
                best[pkg] = {**row, "_play": play}
                continue
            # Play-sourced beats non-Play; within the same market, newer wins.
            if play and not current["_play"]:
                best[pkg] = {**row, "_play": play}
            elif play == current["_play"] and _vercode(row) > _vercode(current):
                best[pkg] = {**row, "_play": play}

    return {
        pkg: {
            "package": pkg,
            "sha256": row[_SHA256],
            "vercode": row.get(_VERCODE),
            "apk_size": row.get(_SIZE),
            "markets": row.get(_MARKETS),
            "from_play": row["_play"],
        }
        for pkg, row in best.items()
    }


def download(sha256: str, apikey: str, dest: Path, *, timeout: int = 600) -> Path | None:
    """Fetch one APK by hash. Returns the path, or None on any failure.

    The downloaded bytes are *not* trusted to match the requested hash — the
    caller should verify. Corpus mirrors have been wrong before, and a silent
    mismatch would poison every downstream finding.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    query = urllib.parse.urlencode({"apikey": apikey, "sha256": sha256})
    url = f"{DOWNLOAD_URL}?{query}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            length = resp.headers.get("Content-Length")
            if length and int(length) > MAX_APK_BYTES:
                warn(f"androzoo: {sha256[:12]} is {int(length)} bytes — skipped")
                return None
            buf = io.BytesIO()
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                buf.write(chunk)
                if buf.tell() > MAX_APK_BYTES:
                    warn(f"androzoo: {sha256[:12]} exceeded size cap mid-stream")
                    return None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        warn(f"androzoo download failed for {sha256[:12]}: {exc}")
        return None

    data = buf.getvalue()
    if not data:
        warn(f"androzoo returned an empty body for {sha256[:12]}")
        return None
    dest.write_bytes(data)
    return dest


def verify(path: Path, expected_sha256: str) -> bool:
    import hashlib
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest.lower() == expected_sha256.lower()


def fetch_packages(index: Path, packages: list[str], apikey: str,
                   out_dir: Path) -> dict:
    """Resolve then download, verifying every artifact. Bounded, JSON-serialisable."""
    resolved = resolve(index, packages)
    missing = sorted(set(packages) - set(resolved))
    fetched: list[dict] = []
    failed: list[dict] = []

    for pkg, meta in sorted(resolved.items()):
        dest = out_dir / pkg / f"{pkg}-{meta['sha256'][:12]}.apk"
        say("androzoo", f"fetching {pkg} ({meta['sha256'][:12]})")
        got = download(meta["sha256"], apikey, dest)
        if got is None:
            failed.append({"package": pkg, "reason": "download failed"})
            continue
        if not verify(got, meta["sha256"]):
            got.unlink(missing_ok=True)
            failed.append({"package": pkg, "reason": "sha256 mismatch — discarded"})
            continue
        fetched.append({**meta, "path": str(got)})

    return {
        "requested": len(packages),
        "fetched": fetched,
        "failed": failed,
        "not_in_index": missing,
        "out_dir": str(out_dir),
        "provenance": ("AndroZoo research snapshot — re-acquire from a real install "
                       "and re-verify the hash before reporting to a vendor"),
    }
