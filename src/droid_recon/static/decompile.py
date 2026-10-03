"""jadx wrapper with a content-addressed cache.

jadx takes ~15 s on an 18 MB APK (measured) and exits non-zero on *partial* success —
which is the common case for real apps. Treating that as failure would throw away a
perfectly usable tree, so any run that produced .java files counts as success.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Sequence
from pathlib import Path

from .. import shell
from ..log import ok, say, warn
from .manifest import sha256_of

DEFAULT_CACHE = Path(os.environ.get("DROID_RECON_JADX_CACHE") or
                     Path.home() / ".cache" / "droid-recon" / "jadx")
JADX_TIMEOUT = 900


def cache_dir_for(sha256: str, cache_root: Path | None = None) -> Path:
    return (cache_root or DEFAULT_CACHE) / sha256[:16]


def java_files(tree: Path) -> list[Path]:
    return list(tree.rglob("*.java"))


def decompile(
    apk: Path | Sequence[Path],
    sha256: str,
    *,
    cache_root: Path | None = None,
    force: bool = False,
    timeout: int = JADX_TIMEOUT,
) -> Path | None:
    """Decompile one APK or a complete split set to one cached source tree.

    Returns None (rather than raising) when jadx is unavailable or produced nothing —
    the caller degrades to manifest-only analysis.
    """
    apks = [Path(apk)] if isinstance(apk, (str, Path)) else [Path(p) for p in apk]
    if not apks:
        raise ValueError("no APKs supplied for decompilation")
    if len(apks) == 1:
        hashes = [sha256]
        cache_key = sha256
    else:
        # The base hash alone is unsafe: changing a feature APK must invalidate the
        # Java tree even when the base APK is byte-for-byte identical.
        digest = hashlib.sha256()
        hashes = [sha256_of(path) for path in apks]
        for apk_hash in hashes:
            digest.update(bytes.fromhex(apk_hash))
        cache_key = digest.hexdigest()
    out = cache_dir_for(cache_key, cache_root)
    marker = out / ".droid-recon-complete"

    if marker.exists() and not force:
        n = len(java_files(out / "sources"))
        say("code", f"jadx cache hit ({n} .java) -> {out}")
        return out / "sources" if (out / "sources").is_dir() else out

    jadx = shell.which("jadx")
    if not jadx:
        warn("jadx not found on PATH — skipping code analysis")
        return None

    if out.exists():
        shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)

    label = apks[0].name + (f" (+{len(apks) - 1} splits)" if len(apks) > 1 else "")
    say("code", f"jadx decompiling {label} (up to {timeout}s)...")
    proc = shell.run(
        [jadx, "--no-res", "--no-debug-info", "--show-bad-code", "-d", str(out),
         *(str(path) for path in apks)],
        timeout=timeout,
    )

    tree = out / "sources" if (out / "sources").is_dir() else out
    produced = java_files(tree)
    if not produced:
        warn(f"jadx produced no sources (rc={proc.rc}, timed_out={proc.timed_out})")
        return None

    # rc != 0 with output means partial decompile — normal for obfuscated/large apps.
    if not proc.ok:
        warn(f"jadx exited rc={proc.rc} but produced {len(produced)} .java — using partial tree")
    else:
        ok(f"jadx decompiled {len(produced)} .java files")

    marker.write_text(
        "\n".join([f"{path}\t{apk_hash}" for path, apk_hash in zip(apks, hashes)]
                  + [f"rc={proc.rc}", f"files={len(produced)}", ""]),
        encoding="utf-8",
    )
    return tree
