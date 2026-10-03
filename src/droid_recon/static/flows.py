"""Conservative local source-to-sink candidates in reachable Android components.

This is a lexical, same-method analysis of JADX Java output. It follows direct
arguments and simple local assignments; it does not prove exploitability or fully
model Java control flow. Every result is a STATIC_CANDIDATE for human review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..models import AttackSurface, Component

_NON_CODE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/', re.S)
_METHOD = re.compile(
    r"(?m)^[ \t]*(?:(?:public|private|protected|static|final|synchronized|native|abstract)\s+)*"
    r"[\w.$<>?,\[\]]+\s+(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*"
    r"(?:throws\s+[\w.$,\s]+)?\{"
)
_SOURCE = re.compile(
    r"\b(?:getIntent\s*\(\s*\)|intent)\s*\.\s*"
    r"(?:get(?:String|Int|Boolean|Long|Parcelable|Serializable|CharSequence|Bundle)Extra|"
    r"getDataString|getData|getExtras)\s*\(", re.I,
)
_ASSIGNMENT = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\s*=(?!=)\s*(?P<expr>[^;]+);"
)
_IDENTIFIER = re.compile(r"\b[A-Za-z_$][\w$]*\b")
_VALIDATION = (
    (re.compile(r"\bget(?:Scheme|Host)\s*\(\s*\).*?(?:equals|matches|==)|"
                r"(?:equals|matches)\s*\([^;]*?get(?:Scheme|Host)\s*\(", re.I),
     "URI scheme/host comparison"),
    (re.compile(r"\bsetPackage\s*\(|\bsetComponent\s*\("),
     "Intent destination restriction"),
    (re.compile(r"\b(?:enforceCallingPermission|checkCallingPermission|"
                r"enforceCallingOrSelfPermission)\s*\("),
     "caller permission check"),
    (re.compile(r"\b(?:allowlist|whitelist|isAllowed|isTrusted|validateUrl|sanitizeUrl)\s*\(", re.I),
     "named validation helper (implementation not checked)"),
)
_SINKS = (
    (re.compile(r"\.[ \t]*loadUrl\s*\("), "WebView.loadUrl"),
    (re.compile(r"\.[ \t]*evaluateJavascript\s*\("), "WebView.evaluateJavascript"),
    (re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("),
     "Runtime.exec"),
    (re.compile(r"\b(?:new\s+)?ProcessBuilder\s*\("), "ProcessBuilder"),
    (re.compile(r"\bstartActivit(?:y|ies)\s*\("), "startActivity"),
    (re.compile(r"\.(?:rawQuery|execSQL)\s*\("), "raw SQL"),
)
LIMITATIONS = [
    "Same-method lexical flow only; calls, fields, callbacks, Kotlin, native code, and reflection are not traced.",
    "Branches, sanitizers, aliases, and decompiler transformations may create false positives or missed flows.",
    "Nearby validation is listed for review; its correctness or reachability is not proved.",
    "A source-to-sink candidate is not a vulnerability without runtime reachability and effect evidence.",
]


@dataclass(frozen=True)
class _Source:
    line: int
    expression: str
    variable: str | None


def _mask_non_code(text: str) -> str:
    return _NON_CODE.sub(lambda match: re.sub(r"[^\n]", " ", match.group()), text)


def _method_regions(masked: str) -> list[tuple[str, int, int]]:
    regions = []
    for match in _METHOD.finditer(masked):
        opening = match.end() - 1
        depth = 1
        end = opening + 1
        while end < len(masked) and depth:
            if masked[end] == "{":
                depth += 1
            elif masked[end] == "}":
                depth -= 1
            end += 1
        if depth == 0:
            regions.append((match.group("name"), opening + 1, end - 1))
    return regions


def _call_args(masked: str, opening: int) -> str:
    depth = 1
    i = opening + 1
    while i < len(masked):
        if masked[i] == "(":
            depth += 1
        elif masked[i] == ")":
            depth -= 1
            if depth == 0:
                return masked[opening + 1:i]
        i += 1
    return ""


def _first_sql_argument(args: str) -> str:
    depth = 0
    for index, char in enumerate(args):
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
        elif char == "," and depth == 0:
            return args[:index]
    return args


def _nearby_checks(raw_lines: list[str], masked_lines: list[str], sink_idx: int,
                   first_line: int, tainted_names: set[str]) -> list[dict]:
    checks = []
    for index in range(max(0, sink_idx - 35), sink_idx):
        # Include earlier checks in the same method, including caller checks
        # before the source. A label means "seen nearby", not "effective".
        for pattern, label in _VALIDATION:
            if pattern.search(masked_lines[index]):
                if label != "caller permission check" and not (
                    set(_IDENTIFIER.findall(masked_lines[index])) & tainted_names
                ):
                    continue
                checks.append({"line": first_line + index, "kind": label,
                               "excerpt": raw_lines[index].strip()[:180]})
    return checks[:8]


def _scan_method(raw: str, masked: str, *, file: str, component: Component,
                 method: str, first_line: int) -> list[dict]:
    raw_lines = raw.splitlines()
    masked_lines = masked.splitlines()
    tainted: dict[str, _Source] = {}
    out = []
    depth = 0

    for offset, (raw_line, code_line) in enumerate(zip(raw_lines, masked_lines)):
        line_no = first_line + offset
        sources = list(_SOURCE.finditer(code_line))
        assignments = list(_ASSIGNMENT.finditer(code_line))
        for assignment in assignments:
            name, expression = assignment.group("name", "expr")
            source = next((m for m in sources if assignment.start("expr") <= m.start()
                           < assignment.end("expr")), None)
            if source:
                tainted[name] = _Source(line_no, raw_line.strip()[:200], name)
            else:
                inherited = next((tainted[token] for token in _IDENTIFIER.findall(expression)
                                  if token in tainted), None)
                if inherited:
                    tainted[name] = inherited
                elif name in tainted and depth == 0:
                    # A top-level overwrite is unconditional in this simple
                    # model. In a branch, retain taint because another path may
                    # still use the original value.
                    del tainted[name]

        for pattern, label in _SINKS:
            for match in pattern.finditer(code_line):
                call_text = "\n".join(masked_lines[offset:offset + 8])
                opening = match.end() - 1
                args = _call_args(call_text, opening)
                if label == "raw SQL":
                    args = _first_sql_argument(args)
                direct = _SOURCE.search(args)
                source_ref = (_Source(line_no, raw_line.strip()[:200], None)
                              if direct else next((tainted[token] for token in _IDENTIFIER.findall(args)
                                                   if token in tainted), None))
                if source_ref is None or line_no - source_ref.line > 120:
                    continue
                checks = _nearby_checks(raw_lines, masked_lines, offset, first_line,
                                        set(tainted))
                out.append({
                    "component": component.name,
                    "reachable_from": component.reachable_from,
                    "file": file,
                    "method": method,
                    "source": {"line": source_ref.line, "expression": source_ref.expression,
                               "variable": source_ref.variable},
                    "sink": {"line": line_no, "api": label, "expression": raw_line.strip()[:200]},
                    "nearby_validation": checks,
                    "review_bucket": "guard_seen" if checks else "no_guard_seen",
                    "result_state": "STATIC_CANDIDATE",
                    "limitation": "Local lexical flow; runtime effect and guard effectiveness unverified.",
                })

        depth += code_line.count("{") - code_line.count("}")
    return out


def analyze(tree: Path, surface: AttackSurface, *, max_candidates: int = 100) -> dict:
    """Trace simple input flows in source files backing third-party entry points."""
    files = {p.relative_to(tree).as_posix(): p for p in tree.rglob("*.java")}
    candidates: list[dict] = []
    missing: list[str] = []
    scanned = 0

    for component in surface.components:
        if component.reachable_from not in ("third_party_app", "browser"):
            continue
        implementation = component.target_activity or component.name
        suffix = implementation.replace(".", "/") + ".java"
        path = next((value for name, value in files.items() if name == suffix or
                     name.endswith("/" + suffix)), None)
        if path is None:
            missing.append(component.name)
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            missing.append(component.name)
            continue
        scanned += 1
        masked = _mask_non_code(raw)
        rel = path.relative_to(tree).as_posix()
        for method, start, end in _method_regions(masked):
            candidates.extend(_scan_method(raw[start:end], masked[start:end], file=rel,
                                           component=component, method=method,
                                           first_line=raw[:start].count("\n") + 1))

    deduped = []
    seen = set()
    for candidate in candidates:
        key = (candidate["component"], candidate["file"], candidate["source"]["line"],
               candidate["sink"]["line"], candidate["sink"]["api"])
        if key not in seen:
            seen.add(key)
            deduped.append(candidate)
    return {
        "summary": {
            "reachable_components": sum(c.publicly_reachable
                                        for c in surface.components),
            "components_scanned": scanned,
            "missing_source_files": len(missing),
            "candidates": len(deduped),
            "no_guard_seen": sum(c["review_bucket"] == "no_guard_seen" for c in deduped),
            "guard_seen": sum(c["review_bucket"] == "guard_seen" for c in deduped),
        },
        "missing_components": missing[:50],
        "candidates": deduped[:max(0, max_candidates)],
        "candidates_omitted": max(0, len(deduped) - max(0, max_candidates)),
        "limitations": LIMITATIONS,
    }
