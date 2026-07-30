"""Recover Intent extra keys (and their types) from decompiled code.

Why this exists — the same reason `urimatcher` does. Guessing key names does not work.
A WebView activity that reads

    getIntent().getStringExtra(MainActivity.EXTRA_URL)   // EXTRA_URL = "EXTRA_URL"

is trivially exploitable, and a payload generator guessing `url`, `link`, `target_url`
will send every one of them and land nothing — producing a confident "no vulnerabilities"
against an app with a direct `loadUrl(attacker_string)` sink. Verified exactly that on
ma.poneglyph.webviewlab before this module existed.

So: mine the real keys out of the jadx tree, per component, along with the accessor type
so the payload is sent with the right `am` flag (`--es` vs `--ei` vs `--ez`).
"""

from __future__ import annotations

import re
from pathlib import Path

# getStringExtra("k") / getIntExtra(K, 0) / getBooleanExtra(...) / getParcelableExtra(...)
_GET_EXTRA = re.compile(
    r"get(?P<kind>String|Int|Long|Float|Double|Boolean|Byte|Char|Short|"
    r"Parcelable|Serializable|CharSequence|StringArray|IntegerArrayList|Bundle)"
    r"Extra\s*\(\s*(?P<key>\"[^\"]*\"|[A-Za-z_][\w.]*)"
)

# Bundle-style reads inside onCreate/getExtras().
_BUNDLE_GET = re.compile(
    r"\.get(?:String|Int|Long|Boolean|Float|Double|Parcelable|Serializable)?\s*"
    r"\(\s*\"(?P<key>[A-Za-z_][\w.\-]{1,60})\"\s*\)"
)

# `static final String EXTRA_URL = "EXTRA_URL";` — including non-uppercase names.
_CONST = re.compile(
    r"(?:static\s+)?(?:final\s+)?String\s+(?P<name>[A-Za-z_]\w*)\s*=\s*\"(?P<val>[^\"]*)\""
)

# hasExtra("k") is a strong signal the key is meaningful.
_HAS_EXTRA = re.compile(r"hasExtra\s*\(\s*(?P<key>\"[^\"]*\"|[A-Za-z_][\w.]*)\s*\)")

_ACCESSOR_TO_TYPE = {
    "String": "string", "CharSequence": "string",
    "Int": "int", "Short": "int", "Byte": "int",
    "Long": "long", "Float": "float", "Double": "float",
    "Boolean": "bool",
    "Parcelable": "string", "Serializable": "string", "Bundle": "string",
    "StringArray": "string_array", "IntegerArrayList": "string_array",
}

_LITERAL = re.compile(r'^"(.*)"$', re.DOTALL)


def _unquote(tok: str) -> str | None:
    m = _LITERAL.match(tok.strip())
    return m.group(1) if m else None


def _resolve(tok: str, consts: dict[str, str]) -> str | None:
    lit = _unquote(tok)
    if lit is not None:
        return lit
    simple = tok.split(".")[-1]
    return consts.get(simple) or consts.get(tok)


def extract(tree: Path, component_names: list[str] | None = None,
            max_files: int = 60000) -> dict:
    """Scan for extra keys.

    Returns:
      by_component: {fully.qualified.Component: [{key, type, accessor}, ...]}
      global_keys:  keys found anywhere (fallback set for components with none)
    """
    # Constants are global-ish: EXTRA_URL is declared in MainActivity but read elsewhere.
    consts: dict[str, str] = {}
    files: list[tuple[str, str]] = []

    scanned = 0
    for java in tree.rglob("*.java"):
        scanned += 1
        if scanned > max_files:
            break
        try:
            text = java.read_text(errors="ignore")
        except OSError:
            continue
        for m in _CONST.finditer(text):
            consts.setdefault(m.group("name"), m.group("val"))
        if "Extra(" in text or "getExtras" in text:
            rel = str(java.relative_to(tree))
            files.append((rel, text))

    by_component: dict[str, list[dict]] = {}
    global_keys: dict[str, str] = {}

    wanted = {c.replace(".", "/") + ".java" for c in (component_names or [])}

    for rel, text in files:
        found: dict[str, str] = {}

        for m in _GET_EXTRA.finditer(text):
            key = _resolve(m.group("key"), consts)
            if key and _plausible(key):
                found[key] = _ACCESSOR_TO_TYPE.get(m.group("kind"), "string")

        for m in _HAS_EXTRA.finditer(text):
            key = _resolve(m.group("key"), consts)
            if key and _plausible(key):
                found.setdefault(key, "string")

        if "getExtras" in text:
            for m in _BUNDLE_GET.finditer(text):
                key = m.group("key")
                if _plausible(key):
                    found.setdefault(key, "string")

        if not found:
            continue

        entries = [{"key": k, "type": t} for k, t in sorted(found.items())]
        global_keys.update(found)

        comp = rel[:-5].replace("/", ".") if rel.endswith(".java") else rel
        if not wanted or rel in wanted:
            by_component[comp] = entries
        else:
            by_component.setdefault(comp, entries)

    return {
        "by_component": by_component,
        "global_keys": [{"key": k, "type": t} for k, t in sorted(global_keys.items())],
        "consts_seen": len(consts),
        "files_with_extras": len(files),
    }


# Keys that are framework plumbing, not app input worth fuzzing.
_BORING = {
    "android.intent.extra.TEXT", "android.intent.extra.SUBJECT",
    "android.support.customtabs.extra.SESSION",
    "androidx.browser.customtabs.extra.SESSION",
}


def _plausible(key: str) -> bool:
    if not key or len(key) > 80 or len(key) < 2:
        return False
    if key in _BORING:
        return False
    # Reject things that are obviously not keys (format strings, paths, sentences).
    if key.startswith(("http", "/", "%")) or " " in key.strip():
        return False
    return True


def keys_for(extracted: dict, component: str) -> list[dict]:
    """Keys for a component, falling back to every key seen in the app.

    The fallback matters: activities frequently delegate to a base class, so the read
    happens in a file that is not named after the component.
    """
    by_comp = extracted.get("by_component") or {}
    exact = by_comp.get(component)
    if exact:
        return exact
    tail = component.split(".")[-1]
    for name, entries in by_comp.items():
        if name.split(".")[-1] == tail:
            return entries
    return extracted.get("global_keys") or []
