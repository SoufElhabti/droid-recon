"""jadx wrapper with a content-addressed cache.

jadx takes ~15 s on an 18 MB APK (measured) and exits non-zero on *partial* success —
which is the common case for real apps. Treating that as failure would throw away a
perfectly usable tree, so any run that produced .java files counts as success.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .. import shell
from ..log import ok, say, warn

DEFAULT_CACHE = Path.home() / ".cache" / "droid-recon" / "jadx"
JADX_TIMEOUT = 900


def cache_dir_for(sha256: str, cache_root: Path | None = None) -> Path:
    return (cache_root or DEFAULT_CACHE) / sha256[:16]


def java_files(tree: Path) -> list[Path]:
    return list(tree.rglob("*.java"))


def decompile(
    apk: Path,
    sha256: str,
    *,
    cache_root: Path | None = None,
    force: bool = False,
    timeout: int = JADX_TIMEOUT,
) -> Path | None:
    """Decompile `apk` to a cached source tree. Returns the tree root, or None.

    Returns None (rather than raising) when jadx is unavailable or produced nothing —
    the caller degrades to manifest-only analysis.
    """
    out = cache_dir_for(sha256, cache_root)
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

    say("code", f"jadx decompiling {apk.name} (up to {timeout}s)...")
    proc = shell.run(
        [jadx, "--no-res", "--no-debug-info", "--show-bad-code", "-d", str(out), str(apk)],
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

    marker.write_text(f"{apk}\n{sha256}\nrc={proc.rc}\nfiles={len(produced)}\n")
    return tree
