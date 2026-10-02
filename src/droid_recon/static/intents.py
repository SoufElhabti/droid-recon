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
    r"\.get(?P<kind>String|Int|Long|Boolean|Float|Double|Parcelable|"
    r"Serializable|CharSequence|StringArray|IntegerArrayList)?\s*"
    r"\(\s*\"(?P<key>[A-Za-z_][\w.\-]{1,60})\"\s*(?:,|\))"
)

# `static final String EXTRA_URL = "EXTRA_URL";` — including non-uppercase names.
_CONST = re.compile(
    r"(?:static\s+)?(?:final\s+)?String\s+(?P<name>[A-Za-z_]\w*)\s*=\s*\"(?P<val>[^\"]*)\""
)

# hasExtra("k") is a strong signal the key is meaningful.
_HAS_EXTRA = re.compile(r"hasExtra\s*\(\s*(?P<key>\"[^\"]*\"|[A-Za-z_][\w.]*)\s*\)")

_ACCESSOR_TO_TYPE = {
    "String": "string", "CharSequence": "string",
    "Int": "int", "Short": "short", "Byte": "byte", "Char": "char",
    "Long": "long", "Float": "float", "Double": "double",
    "Boolean": "bool",
    "Parcelable": "parcelable", "Serializable": "serializable", "Bundle": "bundle",
    "StringArray": "string_array", "IntegerArrayList": "integer_array_list",
}

_LITERAL = re.compile(r'^"(.*)"$', re.DOTALL)
_INT_LITERAL = re.compile(r"[+-]?(?:0|[1-9][0-9]*)(?:[lL])?\Z")
_FLOAT_LITERAL = re.compile(
    r"[+-]?(?:(?:[0-9]+\.[0-9]*|\.[0-9]+|[0-9]+)"
    r"(?:[eE][+-]?[0-9]+)?)(?:[fFdD])?\Z"
)
_STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"\Z')
_CHAR_LITERAL = re.compile(r"'(?:\\.|[^'\\])'\Z")
_METHOD_TAIL = re.compile(
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^(){};]*\)\s*"
    r"(?:throws\s+[\w.$,\s]+)?\Z"
)
_CONTROL = {"if", "for", "while", "switch", "catch", "synchronized", "new"}


def _masked_java(text: str) -> str:
    """Blank comments and literals while retaining offsets and line numbers."""
    out = list(text)
    state = "code"
    i = 0
    while i < len(text):
        c = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c in ('"', "'"):
                state = c
                out[i] = " "
        elif state == "line":
            if c == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block":
            if c == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                state = "code"
                i += 2
                continue
            if c != "\n":
                out[i] = " "
        else:
            if c == "\\" and nxt:
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == state:
                state = "code"
            if c != "\n":
                out[i] = " "
        i += 1
    return "".join(out)


def _matching_paren(masked: str, opening: int) -> int | None:
    depth = 0
    for i in range(opening, len(masked)):
        if masked[i] == "(":
            depth += 1
        elif masked[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _call_arguments(text: str, masked: str, opening: int) -> list[str]:
    end = _matching_paren(masked, opening)
    if end is None:
        return []
    parts: list[str] = []
    start = opening + 1
    depth = 0
    for i in range(start, end):
        if masked[i] in "([{":
            depth += 1
        elif masked[i] in ")]}":
            depth -= 1
        elif masked[i] == "," and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    parts.append(text[start:end].strip())
    return parts


def _default_literal(raw: str, kind: str) -> dict | None:
    """Keep the source token; do not evaluate identifiers or expressions."""
    token = raw.strip()
    if kind in ("int", "short", "byte", "long"):
        if _INT_LITERAL.fullmatch(token) and (kind == "long" or not token.lower().endswith("l")):
            return {"literal": token, "type": kind}
    elif kind in ("float", "double"):
        if _FLOAT_LITERAL.fullmatch(token) and (kind == "double" or
                                                 not token.lower().endswith("d")):
            return {"literal": token, "type": kind}
    elif kind == "bool":
        if token in ("true", "false"):
            return {"literal": token, "type": kind}
    elif kind in ("string", "char"):
        literal = _STRING_LITERAL if kind == "string" else _CHAR_LITERAL
        if literal.fullmatch(token):
            return {"literal": token, "type": kind}
    if token == "null" and kind in ("string", "parcelable", "serializable", "bundle",
                                    "string_array", "integer_array_list"):
        return {"literal": "null", "type": kind}
    return None


def _method_spans(masked: str) -> list[tuple[int, int]]:
    stack: list[int] = []
    spans: list[tuple[int, int]] = []
    for end, char in enumerate(masked):
        if char == "{":
            stack.append(end)
        elif char == "}" and stack:
            start = stack.pop()
            boundary = max(masked.rfind("{", 0, start), masked.rfind("}", 0, start),
                           masked.rfind(";", 0, start))
            head = masked[boundary + 1:start].strip()
            match = _METHOD_TAIL.search(head)
            if match and match.group("name") not in _CONTROL and not re.search(
                    r"\bnew\s+" + re.escape(match.group("name")) + r"\s*\(", head):
                spans.append((start, end))
    return spans


def _condition_kind(condition: str, variable: str) -> str | None:
    var = re.escape(variable)
    atom = rf"(?<![\w$.]){var}(?![\w$])"
    if re.search(rf"(?:{atom}\s*(?:==|!=)\s*null|null\s*(?:==|!=)\s*{atom})", condition):
        return "null_check"
    if re.search(rf"(?:TextUtils\.isEmpty\s*\(\s*{atom}\s*\)|{atom}\.is(?:Empty|Blank)\s*\()", condition):
        return "empty_check"
    if re.search(rf"{atom}\.(?:matches|startsWith|endsWith|contains)\s*\(", condition):
        return "value_check"
    if re.search(rf"{atom}\.length\s*\(\s*\)\s*(?:[<>=!]+)\s*\d+", condition):
        return "length_check"
    if re.search(rf"{atom}\s*(?:==|!=|<=?|>=?)\s*(?:-?\d+|true|false)", condition):
        return "value_check"
    return None


def _validation_evidence(text: str, masked: str, methods: list[tuple[int, int]],
                         offset: int, rel: str) -> list[dict]:
    enclosing = [(start, end) for start, end in methods if start < offset < end]
    if not enclosing:
        return []
    start, end = max(enclosing, key=lambda pair: pair[0])
    boundary = max(masked.rfind(";", start, offset), masked.rfind("{", start, offset),
                   masked.rfind("}", start, offset))
    prefix = masked[boundary + 1:offset]
    assigned = re.search(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*[\w$().]*\s*\Z",
                         prefix)
    if not assigned:
        return []
    variable = assigned.group(1)
    evidence: list[dict] = []
    for match in re.finditer(r"\bif\s*\(", masked[offset:end]):
        opening = offset + match.end() - 1
        closing = _matching_paren(masked, opening)
        if closing is None or closing > end:
            continue
        condition = masked[opening + 1:closing]
        kind = _condition_kind(condition, variable)
        if kind is None:
            continue
        # A later assignment breaks the direct link between this accessor and guard.
        between = masked[offset:opening]
        if re.search(rf"(?<![\w$.]){re.escape(variable)}\s*=(?!=)", between):
            break
        evidence.append({
            "check": kind,
            "source": rel,
            "line": text.count("\n", 0, offset + match.start()) + 1,
            "snippet": " ".join(text[offset + match.start():closing + 1].split())[:180],
            "scope": "same_method",
        })
        if len(evidence) >= 5:
            break
    return evidence


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
      by_component: {fully.qualified.Component: [{key, type, accessor, source,
                     default, validation_evidence, confidence, unknown_fields}, ...]}
      global_keys:  keys found anywhere (fallback set for components with none)

    Validation evidence means only that a check on the read value appears in
    the same method. It does not establish that the check is effective.
    """
    # Resolve only unambiguous names. Two classes can declare different EXTRA_URLs.
    constant_values: dict[str, set[str]] = {}
    files: list[tuple[str, str]] = []

    scanned = 0
    for java in tree.rglob("*.java"):
        scanned += 1
        if scanned > max_files:
            break
        try:
            text = java.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        matches = list(_CONST.finditer(text))
        if matches:
            masked = _masked_java(text)
            for m in matches:
                if masked[m.start()] != " ":
                    constant_values.setdefault(m.group("name"), set()).add(m.group("val"))
        if "Extra(" in text or "getExtras" in text:
            rel = java.relative_to(tree).as_posix()
            files.append((rel, text))

    consts = {name: next(iter(values)) for name, values in constant_values.items()
              if len(values) == 1}
    by_component: dict[str, list[dict]] = {}
    global_keys: dict[str, dict] = {}
    wanted = set(component_names or [])

    for rel, text in files:
        found: dict[str, dict] = {}
        masked = _masked_java(text)
        methods = _method_spans(masked)

        def remember(key: str | None, kind: str, accessor: str, offset: int,
                     *, token: str, bundle: bool = False) -> None:
            if key and _plausible(key):
                opening = masked.find("(", offset)
                arguments = _call_arguments(text, masked, opening) if opening >= 0 else []
                defaultable = (kind in ("int", "short", "byte", "long", "float",
                                        "double", "bool", "char")
                               or (bundle and kind == "string"))
                default = (_default_literal(arguments[1], kind)
                           if defaultable and len(arguments) > 1 else None)
                line = text.count("\n", 0, offset) + 1
                if default is not None:
                    default.update({"source": rel, "line": line})
                default_status = ("not_applicable" if not defaultable else
                                  "literal" if default is not None else "unknown")
                validation = (_validation_evidence(text, masked, methods, offset, rel)
                              if accessor != "hasExtra" else [])
                unknown = []
                if kind == "unknown":
                    unknown.append("type")
                if default_status == "unknown":
                    unknown.append("default")
                if not validation:
                    unknown.append("validation")
                found[key] = {
                    "key": key,
                    "type": kind,
                    "accessor": accessor,
                    "source": rel,
                    "line": line,
                    "default": default,
                    "default_status": default_status,
                    "validation_evidence": validation,
                    "validation_status": ("evidence_observed" if validation else
                                          "not_observed"),
                    "confidence": {
                        "key": "high" if _unquote(token) is not None else "medium",
                        "type": "unknown" if kind == "unknown" else "high",
                        "default": ("high" if default is not None else default_status),
                        "validation": "medium" if validation else "unknown",
                    },
                    "unknown_fields": unknown,
                }

        for m in _GET_EXTRA.finditer(text):
            if masked[m.start()] == " ":
                continue
            key = _resolve(m.group("key"), consts)
            remember(key, _ACCESSOR_TO_TYPE.get(m.group("kind"), "unknown"),
                     f"get{m.group('kind')}Extra", m.start(), token=m.group("key"))

        for m in _HAS_EXTRA.finditer(text):
            if masked[m.start()] == " ":
                continue
            key = _resolve(m.group("key"), consts)
            if key not in found:
                remember(key, "unknown", "hasExtra", m.start(), token=m.group("key"))

        if "getExtras" in text:
            for m in _BUNDLE_GET.finditer(text):
                if masked[m.start()] == " ":
                    continue
                key = m.group("key")
                if key not in found:
                    kind = m.group("kind")
                    remember(key, _ACCESSOR_TO_TYPE.get(kind, "unknown"),
                             f"get{kind or ''}", m.start(), token=f'"{key}"',
                             bundle=True)

        if not found:
            continue

        entries = [found[k] for k in sorted(found)]
        for key, entry in found.items():
            global_keys.setdefault(key, entry)

        comp = rel[:-5].replace("/", ".") if rel.endswith(".java") else rel
        if not wanted or comp in wanted:
            by_component[comp] = entries

    return {
        "by_component": by_component,
        "global_keys": [global_keys[k] for k in sorted(global_keys)],
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
