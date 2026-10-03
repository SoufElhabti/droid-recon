"""Extract content-provider URI paths from decompiled code.

Why this exists: `dumpsys` and the manifest give you provider *authorities*, never
*paths*. And `content query --uri content://authority/` against a real provider returns
"Error while accessing provider" unless you name a path the provider's UriMatcher
recognises. Those paths live in the code as `addURI("auth", "notes", 1)` literals.

Extracting them turns blind provider probing into actual enumeration — this is the
difference between a dynamic pass that finds nothing and one that reads the notes table.
"""

from __future__ import annotations

import re
from pathlib import Path

# addURI(<authority>, <path>, <code>) — authority and path may each be a literal or a
# constant reference. Captured loosely, resolved afterwards.
_ADD_URI = re.compile(
    r"""addURI\s*\(\s*
        (?P<auth>"[^"]*"|[A-Za-z_][\w.]*)\s*,\s*
        (?P<path>"[^"]*"|[A-Za-z_][\w.]*|null)\s*,""",
    re.VERBOSE,
)

# `static final String AUTHORITY = "com.foo.provider";`
_CONST = re.compile(
    r'(?:static\s+)?(?:final\s+)?String\s+(?P<name>[A-Z][A-Z0-9_]*)\s*=\s*"(?P<val>[^"]*)"'
)

# Literal content:// URIs anywhere in the source.
_CONTENT_URI = re.compile(r'content://([A-Za-z0-9_.\-]+)(/[A-Za-z0-9_./\-]*)?')

# ContentProvider.call() dispatches on a method-name string, bypassing the UriMatcher
# entirely. Providers routinely guard query() and forget call(). The method names show
# up as string comparisons inside the call() implementation.
_CALL_METHOD = re.compile(
    r'(?:public\s+Bundle\s+call|\bcall\s*\()[^{]*\{(?P<body>(?:[^{}]|\{[^{}]*\})*)',
    re.DOTALL,
)
_STRING_EQ = re.compile(r'\.equals\s*\(\s*"([A-Za-z_][\w.\-]{2,40})"\s*\)|'
                        r'case\s+"([A-Za-z_][\w.\-]{2,40})"\s*:')

_LITERAL = re.compile(r'^"(.*)"$', re.DOTALL)


def _unquote(tok: str) -> str | None:
    m = _LITERAL.match(tok.strip())
    return m.group(1) if m else None


def extract(tree: Path, authorities: list[str], max_files: int = 60000) -> dict:
    """Scan a decompiled tree for provider paths.

    Returns {"paths": {authority: [path, ...]}, "unresolved": [...], "uris": [...]}.
    Paths are UriMatcher patterns with `#` / `*` wildcards substituted for probing.
    """
    consts: dict[str, str] = {}
    raw_pairs: list[tuple[str, str]] = []
    unresolved: list[dict] = []
    literal_uris: set[str] = set()
    call_methods: set[str] = set()

    auth_set = {a for a in authorities if a}

    files = 0
    for java in tree.rglob("*.java"):
        files += 1
        if files > max_files:
            break
        try:
            text = java.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        has_call = "Bundle call(" in text or "Bundle call (" in text
        if "addURI" not in text and "content://" not in text and not has_call:
            continue

        for m in _CONST.finditer(text):
            consts.setdefault(m.group("name"), m.group("val"))

        for m in _ADD_URI.finditer(text):
            raw_pairs.append((m.group("auth"), m.group("path")))

        for m in _CONTENT_URI.finditer(text):
            auth, path = m.group(1), m.group(2) or ""
            literal_uris.add(f"content://{auth}{path}")

        if has_call:
            for cm in _CALL_METHOD.finditer(text):
                for sm in _STRING_EQ.finditer(cm.group("body") or ""):
                    name = sm.group(1) or sm.group(2)
                    if name:
                        call_methods.add(name)

    # Resolve authority/path tokens.
    #
    # Paths whose authority we resolved are attributed to that authority. Paths whose
    # authority we could NOT resolve go in a separate bucket — fanning them out across
    # every declared authority would make the report claim things the code never said.
    paths: dict[str, set[str]] = {a: set() for a in auth_set}
    floating: set[str] = set()

    for auth_tok, path_tok in raw_pairs:
        auth = _unquote(auth_tok)
        if auth is None:
            simple = auth_tok.split(".")[-1]
            auth = consts.get(simple) or consts.get(auth_tok)
        path = _unquote(path_tok)
        if path is None and path_tok != "null":
            simple = path_tok.split(".")[-1]
            path = consts.get(simple) or consts.get(path_tok)

        if path is None:
            unresolved.append({"authority": auth_tok, "path": path_tok})
            continue

        if auth in paths:
            paths[auth].add(path)
        else:
            floating.add(path)

    # Harvest paths from literal content:// URIs too.
    for uri in literal_uris:
        rest = uri[len("content://"):]
        auth, _, path = rest.partition("/")
        if auth in paths and path:
            paths[auth].add(path)

    return {
        # Paths the code explicitly tied to this authority.
        "paths": {a: sorted(_probeable(p) for p in sorted(ps)) for a, ps in paths.items() if ps},
        # Paths from an addURI whose authority we could not resolve. Worth probing against
        # any provider, but NOT attributable to a specific one — kept separate so the
        # report never claims the code said something it didn't.
        "floating_paths": sorted(_probeable(p) for p in sorted(floating)),
        # ContentProvider.call() method names — a separate, often-unguarded entry point.
        "call_methods": sorted(call_methods)[:40],
        "unresolved": unresolved[:50],
        "uris": sorted(literal_uris)[:200],
        "consts_seen": len(consts),
    }


def _probeable(pattern: str) -> str:
    """Turn a UriMatcher pattern into something `content query` can actually take.

    `#` matches a number and `*` matches any segment; substitute concrete values.
    """
    return pattern.replace("/#", "/1").replace("#", "1").replace("*", "x").strip("/")


# Fallback paths for providers whose UriMatcher yields no literals — typically because
# the paths come from framework constants (Settings.System.CONTENT_URI) or are built at
# runtime. Ordered so the highest-yield guesses run first under a --provider-fallbacks cap.
FALLBACK_PATHS: tuple[str, ...] = (
    # Framework-well-known: these are real paths on AOSP providers.
    "system", "secure", "global", "bookmarks",
    # Generic table names.
    "", "1", "items", "item", "data", "files", "file", "users", "user", "notes",
    "messages", "accounts", "settings", "config", "cache", "downloads", "images",
    "documents", "external_files", "root", "cards", "state", "events", "history",
    "tokens", "credentials", "profile", "preferences",
)

# Path-traversal probes for FileProvider-style providers.
TRAVERSAL_PATHS: tuple[str, ...] = (
    "..%2F..%2F..%2Fdata%2Fdata",
    "../../../../data/system/users/0/settings_secure.xml",
    "root/../../../../data/data",
    "external_files/../../../databases",
)
