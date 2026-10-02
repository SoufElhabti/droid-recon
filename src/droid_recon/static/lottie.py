"""Fingerprint Lottie stacks and their static delivery paths.

The class/package names of lottie-android are commonly obfuscated in production APKs.
Its parser/rendering error strings survive R8, however, so presence detection deliberately
uses those strings as first-class evidence rather than treating symbols as authoritative.

This module is intentionally a fingerprint and a small intra-method data-flow pass, not a
claim of exploitability.  A library or URL-capable wrapper being present only establishes
deployment.  ``attacker_influenced_delivery`` is set only when a Lottie load argument can
be traced locally to an Intent, an HTTP response body, or a ContentResolver read; even
then the report asks for dynamic confirmation.
"""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

SCHEMA_VERSION = 1
MAX_EVIDENCE = 24
MAX_CALL_SITES = 80
MAX_SOURCE_FILES = 60_000
MAX_TEXT_ASSET_BYTES = 8 * 1024 * 1024
MAX_TEXT_SCAN_BYTES = 64 * 1024 * 1024
MAX_BINARY_SCAN_BYTES = 256 * 1024 * 1024
MAX_NATIVE_SCAN_BYTES = 256 * 1024 * 1024
MAX_COVERAGE_NOTICES = 64

# These exact strings were verified in an obfuscated Discord APK whose dex contains no
# com/airbnb/lottie class namespace.  Keep them literal: they are the high-value R8-
# resistant signature described in the Lottie research handoff.
LOTTIE_ANDROID_STABLE_STRINGS: tuple[str, ...] = (
    "Unable to parse composition",
    "Unknown layer type",
    "You must set an images folder",
    "Unable to extract font",
    "data URL did not have correct base64",
)

_LOTTIE_AUXILIARY_STRINGS: tuple[str, ...] = (
    "Lottie only supports bodymovin >= 4.4.0",
)

_LOTTIE_SYMBOLS: tuple[str, ...] = (
    "com.airbnb.lottie",
    "com/airbnb/lottie/",
    "Lcom/airbnb/lottie/",
)

_DOTLOTTIE_MARKERS: tuple[str, ...] = (
    "DotLottie",
    "LottieZip",
    "sourceDotLottieURI",
)

# Telegram and downstream apps often rename the shared object (Discord ships rlottie
# inside ``libdsti.so``), so ``librlottie.so`` alone is not a sufficient fingerprint.
# These are exported Itanium C++ ABI symbols from the rlottie public API and survive the
# renamed-library packaging used by those forks.
_RLOTTIE_NATIVE_MARKERS: tuple[bytes, ...] = (
    b"_ZN7rlottie9Animation12loadFromData",
    b"_ZN7rlottie9Animation10renderSync",
)

_ELF_MAGIC = b"\x7fELF"

# The official dotlottie-android native player can be stripped and renamed, so neither
# the shared-object filename nor C++ RTTI is a reliable fingerprint.  Its exported C API
# and ThorVG expression property names do survive stripping.  Treat the expression
# engine as present only when both families occur in the *same* ELF: a lone
# ``propertyGroup`` string or a generic dotLottie format marker is not sufficient.
_DOTLOTTIE_NATIVE_API_MARKERS: tuple[bytes, ...] = (
    b"dotlottie_load_animation_data",
    b"dotlottie_load_dotlottie_data",
)
_THORVG_EXPRESSION_NATIVE_MARKERS: tuple[bytes, ...] = (
    b"$bm_rt",
    b"propertyGroup",
    b"toComp",
    b"valueAtTime",
)
# ThorVG's base64 data-URI decoder is a parse-time raw-byte heap write whose
# allocation size derives from ``strlen`` of the encoded body while the number of
# bytes written stops at ``=``/``.`` padding.  That decoupling turns it into an
# ASLR-independent partial pointer overwrite against any same-size-class object
# freed earlier in the load, because the untouched tail keeps the freed object's
# slide-bearing bytes.  Reported only alongside a confirmed native expression
# engine in the SAME ELF: these strings alone just mean the loader supports
# embedded fonts/images, which is ordinary.
_B64_RAW_WRITE_NATIVE_MARKERS: tuple[bytes, ...] = (
    b"data:font/",
    b";base64,",
    b"data:image",
)
_RLOTTIE_WRAPPER_METHODS: tuple[str, ...] = (
    "createWithJson", "getFrame", "replaceColors", "setLayerColor",
)

_EXPRESSION_MARKERS: tuple[str, ...] = ("ExpressionDelegate", "setExpression")
_DELEGATE_MARKERS: tuple[str, ...] = ("ImageAssetDelegate", "FontAssetDelegate")

_VERSION_ASSIGNMENT = re.compile(
    r"\b(?:VERSION_NAME|LIBRARY_VERSION|LOTTIE_VERSION)\s*=\s*"
    r'"(?P<version>\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z_.-]+)?)"'
)
_PROPERTY_VERSION = re.compile(
    r"(?m)^\s*version\s*=\s*(?P<version>\d+\.\d+(?:\.\d+)?"
    r"(?:[-+][0-9A-Za-z_.-]+)?)\s*$"
)
_PLAIN_VERSION = re.compile(
    r"^\s*(?P<version>\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z_.-]+)?)\s*$"
)

_LOADER_CALL = re.compile(
    r"(?P<receiver>(?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*)\s*\.\s*"
    r"(?P<method>setAnimationFromUrl|setSourceDotLottieURI|"
    r"fromJsonInputStream|fromJsonString|fromJsonReader|fromZipStream|"
    r"fromUrlSync|fromUrl|setAnimation)\s*\("
)
_LOADER_TOKEN = re.compile(
    r"setAnimation|setSourceDotLottieURI|fromUrl|"
    r"fromJson(?:InputStream|String|Reader)|fromZipStream"
)
_URL_LOADERS = {
    "setAnimationFromUrl", "setSourceDotLottieURI",
    "fromUrl", "fromUrlSync",
}
_WEBVIEW_CALL = re.compile(
    r"(?P<receiver>(?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*)\s*\.\s*"
    r"(?P<method>loadDataWithBaseURL|loadUrl)\s*\("
)
_DELEGATE_CALL = re.compile(r"\.\s*set(?P<kind>Image|Font)AssetDelegate\s*\(")
_EXPRESSION_CALL = re.compile(r"\.\s*setExpression\s*\(")
_DELEGATE_IMPL = re.compile(
    r"\b(?:implements|extends)\s+(?P<kind>ImageAssetDelegate|FontAssetDelegate)\b"
)
_EXPRESSION_IMPL = re.compile(r"\b(?:implements|extends)\s+ExpressionDelegate\b")

_INTENT_SOURCE = re.compile(
    r"\bgetIntent\s*\(|"
    r"\b(?:intent[\w$]*|[\w$]*Intent[\w$]*)\s*\.\s*"
    r"get(?:String|Int|Long|Float|Double|Boolean|Byte|Char|Short|"
    r"Parcelable|Serializable|CharSequence|StringArray|IntegerArrayList|Bundle)?"
    r"Extra\s*\(|"
    r"\b(?:intent[\w$]*|[\w$]*Intent[\w$]*)\s*\.\s*"
    r"get(?:Data|DataString|Extras)\s*\(",
    re.IGNORECASE,
)
_HTTP_SOURCE = re.compile(
    r"\b(?:ResponseBody|HttpResponse|okhttp3\s*\.\s*Response)\b|"
    r"\b(?:response|resp|responseBody|httpResponse)[\w$]*\s*\.\s*"
    r"(?:body|byteStream|bytes|string|source)\s*\(",
    re.IGNORECASE,
)
_PROVIDER_SOURCE = re.compile(
    r"\bContentResolver\b|\bgetContentResolver\s*\(|"
    r"\b(?:contentResolver|resolver)[\w$]*\s*\.\s*"
    r"(?:openInputStream|openFileDescriptor|query)\s*\(|content://",
    re.IGNORECASE,
)
_STATIC_URL = re.compile(r'^\s*"https?://', re.IGNORECASE)
_BUNDLED_INPUT = re.compile(r'^\s*(?:"[^"\n]*\.(?:json|lottie)"|\d+)\s*$', re.IGNORECASE)
_SIMPLE_REFERENCE = re.compile(r"^\s*(?:this\s*\.\s*)?(?P<name>[A-Za-z_$][\w$]*)\s*$")

# Java method declarations.  This is not a Java parser; it only provides a boundary so
# a getIntent() in one method cannot taint a Lottie call in another by co-occurrence.
_METHOD_DECL = re.compile(
    r"(?m)^[ \t]*(?:@[\w$.]+(?:\([^\n]*\))?\s*)*"
    r"(?:(?:public|protected|private|static|final|synchronized|native|abstract|default)\s+)*"
    r"(?:<[^{;\n]+>\s+)?[\w$.[\]<?,>]+\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*"
    r"(?:throws\s+[^{]+)?\{",
    re.DOTALL,
)


@dataclass
class _State:
    q1_evidence: list[dict] = field(default_factory=list)
    stable_strings: set[str] = field(default_factory=set)
    direct_symbols: set[str] = field(default_factory=set)
    versions: dict[str, list[dict]] = field(default_factory=dict)
    q3_evidence: list[dict] = field(default_factory=list)
    q4_evidence: list[dict] = field(default_factory=list)
    q5_evidence: list[dict] = field(default_factory=list)
    q6_evidence: list[dict] = field(default_factory=list)
    q6_api_markers: list[dict] = field(default_factory=list)
    q7_evidence: list[dict] = field(default_factory=list)
    q7_api_markers: list[dict] = field(default_factory=list)
    delegate_types: set[str] = field(default_factory=set)
    url_calls: list[dict] = field(default_factory=list)
    delivery_paths: list[dict] = field(default_factory=list)
    webview_calls: list[dict] = field(default_factory=list)
    web_assets: set[str] = field(default_factory=set)
    web_pages: set[str] = field(default_factory=set)
    dotlottie_assets: set[str] = field(default_factory=set)
    archive_errors: list[str] = field(default_factory=list)
    truncated: list[str] = field(default_factory=list)
    java_files_scanned: int = 0
    apk_files_scanned: int = 0
    archive_entries_scanned: int = 0
    archive_bytes_scanned: int = 0


def analyze(tree: Path, apks: Path | Iterable[Path], *, max_files: int = MAX_SOURCE_FILES) -> dict:
    """Answer prompt.md Phase-1 Q1-Q10 for a jadx tree and APK/split set.

    Returned evidence is deliberately bounded and JSON-serialisable.  Negative answers
    mean "not found by this static pass", never proof that a dynamically loaded stack or
    an inter-procedural/Hermes flow does not exist.
    """
    apk_list = [apks] if isinstance(apks, Path) else list(apks)
    apk_list = [Path(p) for p in apk_list]
    state = _State()

    _scan_archives(apk_list, state)
    _scan_sources(Path(tree), state, max_files=max_files)

    q1_present = bool(state.direct_symbols or state.stable_strings)
    q1_confidence = "not_found"
    if state.direct_symbols or len(state.stable_strings) >= 2:
        q1_confidence = "high"
    elif state.stable_strings:
        q1_confidence = "medium"

    versions = sorted(state.versions, key=_version_key)
    version_answer = versions[0] if len(versions) == 1 else None
    if len(versions) == 1:
        version_confidence = "high"
    elif len(versions) > 1:
        version_confidence = "conflicting"
    else:
        version_confidence = "unknown"

    q3_present = bool(state.q3_evidence)
    q4_present = bool(state.q4_evidence)
    q4_native = any(e.get("kind") in {"native_library", "native_symbol"}
                    for e in state.q4_evidence)
    q5_present = bool(state.q5_evidence)
    q6_enabled = bool(state.q6_evidence)
    q6_native = any(
        e.get("kind") == "native_dotlottie_thorvg_expression_engine"
        for e in state.q6_evidence
    )
    q7_custom = bool(state.q7_evidence)
    q8_urls = bool(state.url_calls)

    intent_paths = [p for p in state.delivery_paths if _has_source(p, "intent")]
    influenced_paths = [
        p for p in state.delivery_paths
        if any(s.get("type") in {"intent", "http_response", "content_provider"}
               for s in p.get("sources", []))
    ]

    q10_flows, q10_candidates = _webview_lottie_flows(state)
    q10_same_flow = bool(q10_flows)

    stacks: list[str] = []
    if q1_present:
        stacks.append("lottie-android")
    if q3_present:
        stacks.append("lottie-web")
    if q4_present:
        stacks.append("rlottie")
    if q5_present:
        stacks.append("dotlottie")
    if q6_native:
        stacks.append("dotlottie-native-thorvg-expressions")

    questions = {
        "q1_lottie_android": _answer(
            "Does it use lottie-android?", q1_present, q1_confidence, state.q1_evidence,
            stable_strings=sorted(state.stable_strings),
            symbol_markers=sorted(state.direct_symbols),
        ),
        "q2_lottie_android_version": _answer(
            "What lottie-android version is present?", version_answer,
            version_confidence,
            [e for version in versions for e in state.versions[version]][:MAX_EVIDENCE],
            versions=versions,
        ),
        "q3_lottie_web": _answer(
            "Does it use lottie-web?", q3_present,
            "high" if q3_present else "not_found", state.q3_evidence,
            assets=sorted(state.web_assets)[:MAX_EVIDENCE],
        ),
        "q4_rlottie": _answer(
            "Does it ship rlottie?", q4_present,
            "high" if q4_native else ("medium" if q4_present else "not_found"),
            state.q4_evidence,
        ),
        "q5_dotlottie": _answer(
            "Does it use dotLottie?", q5_present,
            "high" if q5_present else "not_found", state.q5_evidence,
            assets=sorted(state.dotlottie_assets)[:MAX_EVIDENCE],
        ),
        "q6_expressions": _answer(
            "Are expression APIs enabled?", q6_enabled,
            "high" if q6_native else ("medium" if q6_enabled else "not_found"),
            state.q6_evidence,
            api_markers=state.q6_api_markers,
        ),
        "q7_custom_asset_delegates": _answer(
            "Are custom image/font asset delegates installed?", q7_custom,
            "medium" if q7_custom else "not_found", state.q7_evidence,
            delegate_types=sorted(state.delegate_types),
            api_markers=state.q7_api_markers,
        ),
        "q8_url_loading": _answer(
            "Are Lottie animations loaded through URL-capable APIs?", q8_urls,
            "medium" if q8_urls else "not_found", state.url_calls,
        ),
        "q9_intent_loading": _answer(
            "Can a Lottie load argument be traced back to an Intent?", bool(intent_paths),
            _path_confidence(intent_paths), intent_paths,
        ),
        "q10_lottie_webview": _answer(
            "Is a lottie-web asset loaded by a WebView in the same static flow?",
            q10_same_flow, "high" if q10_same_flow else "not_demonstrated",
            q10_flows, candidates=q10_candidates,
        ),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "summary": {
            "stacks_present": stacks,
            "attacker_influenced_delivery": bool(influenced_paths),
            "delivery_path_count": len(state.delivery_paths),
            "attacker_influenced_path_count": len(influenced_paths),
            "needs_dynamic_confirmation": bool(
                state.delivery_paths or q10_flows or q10_candidates
            ),
        },
        "questions": questions,
        "delivery_paths": state.delivery_paths[:MAX_CALL_SITES],
        "coverage": {
            "java_files_scanned": state.java_files_scanned,
            "apk_files_scanned": state.apk_files_scanned,
            "archive_entries_scanned": state.archive_entries_scanned,
            "archive_bytes_scanned": state.archive_bytes_scanned,
            "truncated": state.truncated,
            "errors": state.archive_errors,
        },
        "notes": [
            "Library presence establishes deployment, not exploitability.",
            "Static delivery paths are local data-flow candidates and require runtime confirmation.",
            "A false answer means not found by this pass; reflection, native code, or Hermes may hide flows.",
        ],
    }


def brief(report: dict, *, evidence_per_question: int = 3,
          max_delivery_paths: int = 8) -> dict:
    """Bound a Lottie report for CLI/MCP output; the full block stays in the artifact."""
    questions = {}
    for key, value in (report.get("questions") or {}).items():
        questions[key] = {
            "answer": value.get("answer"),
            "confidence": value.get("confidence"),
            "evidence": (value.get("evidence") or [])[:evidence_per_question],
        }
    return {
        "summary": report.get("summary") or {},
        "questions": questions,
        "delivery_paths": (report.get("delivery_paths") or [])[:max_delivery_paths],
    }


def _answer(question: str, answer, confidence: str, evidence: list[dict], **extra) -> dict:
    out = {
        "question": question,
        "answer": answer,
        "confidence": confidence,
        "evidence": evidence[:MAX_EVIDENCE],
    }
    out.update(extra)
    return out


def _scan_sources(tree: Path, state: _State, *, max_files: int) -> None:
    tree_prefix = str(tree).rstrip("/\\") + "/"
    for java in tree.rglob("*.java"):
        if state.java_files_scanned >= max_files:
            _notice(state.truncated, f"java source scan stopped at {max_files} files")
            break
        state.java_files_scanned += 1
        try:
            text = java.read_text(errors="ignore")
        except OSError:
            continue
        java_name = str(java).replace("\\", "/")
        rel = java_name[len(tree_prefix):] if java_name.startswith(tree_prefix) else java.name

        found_stable = False
        for marker in LOTTIE_ANDROID_STABLE_STRINGS:
            pos = text.find(marker)
            if pos >= 0:
                found_stable = True
                state.stable_strings.add(marker)
                _append(state.q1_evidence, _source_evidence(
                    "stable_string", marker, rel, text, pos))
        for marker in _LOTTIE_AUXILIARY_STRINGS:
            pos = text.find(marker)
            if pos >= 0:
                _append(state.q1_evidence, _source_evidence(
                    "supporting_string", marker, rel, text, pos))
        found_symbol = False
        for marker in _LOTTIE_SYMBOLS:
            pos = text.find(marker)
            if pos >= 0:
                found_symbol = True
                state.direct_symbols.add(marker)
                _append(state.q1_evidence, _source_evidence(
                    "class_symbol", marker, rel, text, pos))
                break

        norm_rel = rel.lower()
        if "rlottie" in norm_rel:
            wrapper_methods = [m for m in _RLOTTIE_WRAPPER_METHODS if m in text]
            if " native " in f" {text} " and len(wrapper_methods) >= 2:
                _append(state.q4_evidence, {
                    "kind": "java_native_wrapper",
                    "value": Path(rel).name,
                    "file": rel,
                    "methods": wrapper_methods,
                })
        core_file = (
            norm_rel.startswith("com/airbnb/lottie/")
            or "/com/airbnb/lottie/" in norm_rel
            or found_stable
            or found_symbol
        )

        if core_file or "lottie" in norm_rel:
            for match in _VERSION_ASSIGNMENT.finditer(text):
                _record_version(state, match.group("version"), {
                    "kind": "build_config",
                    "value": match.group("version"),
                    "file": rel,
                    "line": _line(text, match.start()),
                })

        for marker in _DOTLOTTIE_MARKERS:
            pos = text.find(marker)
            if pos >= 0:
                _append(state.q5_evidence, _source_evidence(
                    "dotlottie_symbol", marker, rel, text, pos))
        extension = None
        if any(token in text for token in (".lottie", ".Lottie", ".LOTTIE")):
            extension = re.search(
                r'["\'][^"\'\n]*\.lottie(?:[?#][^"\'\n]*)?["\']', text,
                re.IGNORECASE,
            )
        if extension:
            _append(state.q5_evidence, _source_evidence(
                "dotlottie_string", extension.group(0)[:160], rel, text, extension.start()))

        has_expression_marker = any(marker in text for marker in _EXPRESSION_MARKERS)
        has_delegate_marker = any(marker in text for marker in _DELEGATE_MARKERS)
        has_loader_token = bool(_LOADER_TOKEN.search(text))
        has_webview_token = (
            ("WebView" in text or "android.webkit" in text)
            and ("loadUrl" in text or "loadDataWithBaseURL" in text)
        )
        if not (has_expression_marker or has_delegate_marker
                or has_loader_token or has_webview_token):
            continue

        # Masking and method-boundary recovery are the expensive part of this pass.  Do
        # them only for files carrying a relevant API token; a large app can have 10k+
        # unrelated decompiled source files.
        masked = _mask_non_code(text)

        if has_expression_marker:
            for marker in _EXPRESSION_MARKERS:
                pos = text.find(marker)
                if pos >= 0:
                    _append(state.q6_api_markers, _source_evidence(
                        "expression_api_marker", marker, rel, text, pos))
        if not core_file:
            for match in _EXPRESSION_CALL.finditer(masked):
                _append(state.q6_evidence, _call_evidence(
                    "expression_api_call", "setExpression", rel, text, match.start()))
            for match in _EXPRESSION_IMPL.finditer(masked):
                _append(state.q6_evidence, _call_evidence(
                    "expression_delegate", "ExpressionDelegate", rel, text, match.start()))

        if has_delegate_marker:
            for marker in _DELEGATE_MARKERS:
                pos = text.find(marker)
                if pos >= 0:
                    _append(state.q7_api_markers, _source_evidence(
                        "delegate_api_marker", marker, rel, text, pos))
        if not core_file:
            for match in _DELEGATE_CALL.finditer(masked):
                kind = f"{match.group('kind')}AssetDelegate"
                state.delegate_types.add(kind)
                _append(state.q7_evidence, _call_evidence(
                    "delegate_install", f"set{kind}", rel, text, match.start()))
            for match in _DELEGATE_IMPL.finditer(masked):
                kind = match.group("kind")
                state.delegate_types.add(kind)
                _append(state.q7_evidence, _call_evidence(
                    "delegate_implementation", kind, rel, text, match.start()))

        has_loader_call = has_loader_token and bool(_LOADER_CALL.search(masked))
        has_webview_call = has_webview_token and bool(_WEBVIEW_CALL.search(masked))
        method_ranges = _method_ranges(masked) if has_loader_call or has_webview_call else []
        if not core_file and has_loader_call:
            file_lottie_context = (
                "lottie" in text.lower()
                or any(marker in text for marker in _DOTLOTTIE_MARKERS)
                or bool(re.search(
                    r"\.\s*(?:setAnimationFromUrl|setSourceDotLottieURI|"
                    r"fromJsonInputStream|fromJsonString|fromJsonReader|fromZipStream)\s*\(",
                    masked,
                ))
            )
            _collect_lottie_calls(
                rel, text, masked, method_ranges, state,
                file_lottie_context=file_lottie_context,
            )
        if has_webview_call:
            _collect_webview_calls(rel, text, masked, method_ranges, state)


def _scan_archives(apks: list[Path], state: _State) -> None:
    binary_budget = MAX_BINARY_SCAN_BYTES
    native_budget = MAX_NATIVE_SCAN_BYTES
    text_budget = MAX_TEXT_SCAN_BYTES
    binary_markers = {
        *(s.encode() for s in LOTTIE_ANDROID_STABLE_STRINGS),
        *(s.encode() for s in _LOTTIE_AUXILIARY_STRINGS),
        *(s.encode() for s in _LOTTIE_SYMBOLS),
        *(s.encode() for s in _DOTLOTTIE_MARKERS),
        *(s.encode() for s in _EXPRESSION_MARKERS),
        *(s.encode() for s in _DELEGATE_MARKERS),
    }

    for apk in apks:
        try:
            with zipfile.ZipFile(apk) as archive:
                state.apk_files_scanned += 1
                for info in archive.infolist():
                    state.archive_entries_scanned += 1
                    name = info.filename.replace("\\", "/")
                    low = name.lower()
                    archive_file = f"{apk}:{name}"
                    is_shared_object = low.startswith("lib/") and low.endswith(".so")
                    is_native_elf = (
                        is_shared_object
                        and _archive_entry_starts_with(archive, info, _ELF_MAGIC)
                    )

                    if (Path(name).name.lower() == "librlottie.so"
                            and is_native_elf):
                        _append(state.q4_evidence, {
                            "kind": "native_library", "value": "librlottie.so",
                            "file": archive_file,
                        })

                    if is_shared_object:
                        # Do not let an arbitrary `.so`-named member claim native
                        # evidence or consume the bounded scan budget ahead of real ELFs.
                        if not is_native_elf:
                            continue
                        if native_budget <= 0:
                            _notice(state.truncated,
                                f"native Lottie engine scan skipped: {archive_file}")
                        else:
                            native_markers = {
                                *_RLOTTIE_NATIVE_MARKERS,
                                *_DOTLOTTIE_NATIVE_API_MARKERS,
                                *_THORVG_EXPRESSION_NATIVE_MARKERS,
                                *_B64_RAW_WRITE_NATIVE_MARKERS,
                            }
                            found, consumed, was_truncated = _stream_find_markers(
                                archive, info, native_markers, native_budget)
                            native_budget -= consumed
                            state.archive_bytes_scanned += consumed
                            if was_truncated:
                                _notice(state.truncated,
                                    f"partial native symbol scan: {archive_file}")
                            for marker in sorted(
                                    found.intersection(_RLOTTIE_NATIVE_MARKERS)):
                                _append(state.q4_evidence, {
                                    "kind": "native_symbol",
                                    "value": marker.decode(errors="replace"),
                                    "file": archive_file,
                                })

                            dotlottie_api = found.intersection(
                                _DOTLOTTIE_NATIVE_API_MARKERS)
                            expression_api = found.intersection(
                                _THORVG_EXPRESSION_NATIVE_MARKERS)
                            for marker in sorted(dotlottie_api):
                                _append(state.q5_evidence, {
                                    "kind": "native_dotlottie_api",
                                    "value": marker.decode(errors="replace"),
                                    "file": archive_file,
                                })
                            b64_sink = found.intersection(
                                _B64_RAW_WRITE_NATIVE_MARKERS)
                            if (dotlottie_api and
                                    len(expression_api) >= 3):
                                evidence: dict[str, object] = {
                                    "kind": "native_dotlottie_thorvg_expression_engine",
                                    "value": "dotLottie native player with ThorVG expressions",
                                    "file": archive_file,
                                    "dotlottie_api_markers": sorted(
                                        m.decode(errors="replace") for m in dotlottie_api),
                                    "expression_markers": sorted(
                                        m.decode(errors="replace") for m in expression_api),
                                }
                                if b64_sink:
                                    evidence["b64_raw_write_sink"] = sorted(
                                        m.decode(errors="replace") for m in b64_sink)
                                    evidence["b64_partial_overwrite_reachable"] = True
                                _append(state.q6_evidence, evidence)

                    if low.endswith(".lottie"):
                        state.dotlottie_assets.add(archive_file)
                        _append(state.q5_evidence, {
                            "kind": "dotlottie_archive", "value": name,
                            "file": str(apk),
                        })

                    is_asset_text = low.startswith("assets/") and low.endswith(
                        (".js", ".mjs", ".html", ".htm"))
                    name_is_lottie_web = low.startswith("assets/") and (
                        "lottie.min.js" in low or "lottie-web" in low or
                        "bodymovin" in Path(low).name
                    )
                    if name_is_lottie_web:
                        rel_asset = name[len("assets/"):]
                        state.web_assets.add(rel_asset)
                        _append(state.q3_evidence, {
                            "kind": "web_asset_name", "value": name,
                            "file": str(apk),
                        })

                    if is_asset_text:
                        data, consumed = _read_small_entry(
                            archive, info, state, text_budget)
                        text_budget -= consumed
                        if data is not None:
                            lower_data = data.lower()
                            web_marker = next((m for m in (
                                b"bodymovin", b"lottie.loadanimation", b"lottie-web",
                                b"lottie-player", b"lottie.min.js", b"lottie.js",
                            ) if m in lower_data), None)
                            if web_marker:
                                rel_asset = name[len("assets/"):]
                                state.web_assets.add(rel_asset)
                                _append(state.q3_evidence, {
                                    "kind": "web_asset_content",
                                    "value": web_marker.decode(errors="replace"),
                                    "file": archive_file,
                                })
                                if low.endswith((".html", ".htm")):
                                    state.web_pages.add(rel_asset)

                    if "lottie" in low and low.endswith(("pom.properties", ".version")):
                        data, consumed = _read_small_entry(
                            archive, info, state, text_budget)
                        text_budget -= consumed
                        if data is not None:
                            decoded = data.decode(errors="ignore")
                            match = _PROPERTY_VERSION.search(decoded) or _PLAIN_VERSION.match(decoded)
                            if match:
                                version = match.group("version")
                                _record_version(state, version, {
                                    "kind": "archive_metadata", "value": version,
                                    "file": archive_file,
                                })

                    if low.startswith("classes") and low.endswith(".dex"):
                        if binary_budget <= 0:
                            if str(apk) not in state.truncated:
                                _notice(state.truncated,
                                    f"dex string scan stopped after {MAX_BINARY_SCAN_BYTES} bytes")
                            continue
                        found, consumed, was_truncated = _stream_find_markers(
                            archive, info, binary_markers, binary_budget)
                        binary_budget -= consumed
                        state.archive_bytes_scanned += consumed
                        if was_truncated:
                            _notice(state.truncated,
                                    f"partial dex string scan: {archive_file}")
                        _record_binary_markers(state, found, archive_file)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            _notice(state.archive_errors, f"{apk}: {type(exc).__name__}: {exc}")


def _read_small_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo,
                      state: _State, budget: int) -> tuple[bytes | None, int]:
    if budget <= 0:
        _notice(state.truncated,
                f"archive text scan stopped after {MAX_TEXT_SCAN_BYTES} bytes")
        return None, 0
    if info.file_size > MAX_TEXT_ASSET_BYTES:
        _notice(state.truncated, f"large archive text entry skipped: {info.filename}")
        return None, 0
    if info.file_size > budget:
        _notice(state.truncated,
                f"archive text budget insufficient; skipped: {info.filename}")
        return None, 0
    try:
        with archive.open(info) as fh:
            data = fh.read(min(MAX_TEXT_ASSET_BYTES, budget) + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return None, 0
    consumed = min(len(data), budget)
    state.archive_bytes_scanned += consumed
    if len(data) > budget or len(data) > MAX_TEXT_ASSET_BYTES:
        _notice(state.truncated, f"oversized archive text entry skipped: {info.filename}")
        return None, consumed
    return data, consumed


def _archive_entry_starts_with(archive: zipfile.ZipFile, info: zipfile.ZipInfo,
                               prefix: bytes) -> bool:
    """Check an archive member's actual prefix, not a matching byte run later in it."""
    try:
        with archive.open(info) as fh:
            return fh.read(len(prefix)) == prefix
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return False


def _stream_find_markers(archive: zipfile.ZipFile, info: zipfile.ZipInfo,
                         markers: set[bytes], budget: int) -> tuple[set[bytes], int, bool]:
    found: set[bytes] = set()
    longest = max(map(len, markers), default=1)
    consumed = 0
    tail = b""
    try:
        with archive.open(info) as fh:
            while consumed < budget:
                chunk = fh.read(min(1024 * 1024, budget - consumed))
                if not chunk:
                    break
                consumed += len(chunk)
                haystack = tail + chunk
                for marker in markers - found:
                    if marker in haystack:
                        found.add(marker)
                tail = haystack[-(longest - 1):] if longest > 1 else b""
                if found == markers:
                    break
    except (OSError, RuntimeError, zipfile.BadZipFile):
        pass
    return found, consumed, consumed >= budget and consumed < info.file_size


def _record_binary_markers(state: _State, markers: set[bytes], archive_file: str) -> None:
    decoded = {m.decode(errors="replace") for m in markers}
    for marker in sorted(decoded):
        if marker in LOTTIE_ANDROID_STABLE_STRINGS:
            state.stable_strings.add(marker)
            _append(state.q1_evidence, {
                "kind": "dex_stable_string", "value": marker, "file": archive_file,
            })
        elif marker in _LOTTIE_AUXILIARY_STRINGS:
            _append(state.q1_evidence, {
                "kind": "dex_supporting_string", "value": marker, "file": archive_file,
            })
        elif marker in _LOTTIE_SYMBOLS:
            state.direct_symbols.add(marker)
            _append(state.q1_evidence, {
                "kind": "dex_class_symbol", "value": marker, "file": archive_file,
            })
        elif marker in _DOTLOTTIE_MARKERS:
            _append(state.q5_evidence, {
                "kind": "dex_dotlottie_marker", "value": marker, "file": archive_file,
            })
        elif marker in _EXPRESSION_MARKERS:
            _append(state.q6_api_markers, {
                "kind": "dex_expression_api_marker", "value": marker, "file": archive_file,
            })
        elif marker in _DELEGATE_MARKERS:
            _append(state.q7_api_markers, {
                "kind": "dex_delegate_api_marker", "value": marker, "file": archive_file,
            })


def _collect_lottie_calls(rel: str, text: str, masked: str,
                          methods: list[tuple[int, int, str]], state: _State, *,
                          file_lottie_context: bool) -> None:
    for match in _LOADER_CALL.finditer(masked):
        if len(state.delivery_paths) >= MAX_CALL_SITES:
            return
        method_name = match.group("method")
        if method_name in {"setAnimation", "fromUrl", "fromUrlSync"} and not file_lottie_context:
            continue
        args, _ = _call_arguments(text, match.end() - 1)
        if not args:
            continue
        argument_index = 1 if method_name in {"fromUrl", "fromUrlSync"} and len(args) > 1 else 0
        argument = args[argument_index].strip()
        start, end, enclosing_name = _enclosing_method(methods, match.start(), len(text))
        prefix = text[start:match.start()]
        prefix_masked = masked[start:match.start()]
        sources = _trace_sources(argument, prefix, prefix_masked)
        if not sources:
            if _STATIC_URL.match(argument):
                sources = [{"type": "static_url", "expression": _short(argument), "depth": 0}]
            elif _BUNDLED_INPUT.match(argument):
                sources = [{"type": "bundled_resource", "expression": _short(argument),
                            "depth": 0}]

        call = {
            "kind": "lottie_load_call",
            "loader": method_name,
            "receiver": re.sub(r"\s+", "", match.group("receiver"))[-100:],
            "file": rel,
            "line": _line(text, match.start()),
            "method": enclosing_name,
            "argument": _short(argument),
            "sources": sources,
            "confidence": "local_data_flow" if sources else "call_site_only",
        }
        state.delivery_paths.append(call)
        if method_name in _URL_LOADERS:
            _append(state.url_calls, call, limit=MAX_CALL_SITES)


def _collect_webview_calls(rel: str, text: str, masked: str,
                           methods: list[tuple[int, int, str]], state: _State) -> None:
    # Requiring a WebView type/import in the file avoids treating every unrelated
    # object's loadUrl method as Android WebView.
    if "WebView" not in text and "android.webkit" not in text:
        return
    for match in _WEBVIEW_CALL.finditer(masked):
        if len(state.webview_calls) >= MAX_CALL_SITES:
            return
        args, _ = _call_arguments(text, match.end() - 1)
        if not args:
            continue
        start, end, enclosing_name = _enclosing_method(methods, match.start(), len(text))
        argument = args[0].strip()
        literal = _trace_literal(argument, text[start:match.start()],
                                 masked[start:match.start()])
        scope = masked[start:end]
        state.webview_calls.append({
            "kind": "webview_load",
            "loader": match.group("method"),
            "file": rel,
            "line": _line(text, match.start()),
            "method": enclosing_name,
            "argument": _short(argument),
            "resolved_literal": literal,
            "javascript_bridge": bool(re.search(r"\.\s*addJavascriptInterface\s*\(", scope)),
        })


def _webview_lottie_flows(state: _State) -> tuple[list[dict], list[dict]]:
    flows: list[dict] = []
    candidates: list[dict] = []
    if not state.q3_evidence:
        return flows, candidates

    known = {p.lower().lstrip("/") for p in state.web_assets | state.web_pages}
    for call in state.webview_calls:
        literal = call.get("resolved_literal") or ""
        target = _android_asset_target(literal)
        if target and target.lower().lstrip("/") in known:
            flow = dict(call)
            flow["kind"] = "webview_lottie_asset_flow"
            flow["asset"] = target
            _append(flows, flow)
        else:
            _append(candidates, call)
    return flows, candidates[:MAX_EVIDENCE]


def _android_asset_target(value: str) -> str | None:
    match = re.match(r"file:/+(?:android_asset)/(?P<path>[^?#]+)", value,
                     re.IGNORECASE)
    return match.group("path") if match else None


def _trace_sources(expression: str, prefix: str, prefix_masked: str,
                   *, depth: int = 0, seen: set[str] | None = None) -> list[dict]:
    seen = set() if seen is None else seen
    out: list[dict] = []
    masked_expression = _mask_non_code(expression)
    for source_type, pattern in (
        ("intent", _INTENT_SOURCE),
        ("http_response", _HTTP_SOURCE),
        ("content_provider", _PROVIDER_SOURCE),
    ):
        if pattern.search(masked_expression):
            _append(out, {
                "type": source_type,
                "expression": _short(expression),
                "depth": depth,
            }, limit=12)

    if depth >= 5:
        return out
    simple = _SIMPLE_REFERENCE.match(expression)
    if not simple:
        return out
    name = simple.group("name")
    if name in seen:
        return out
    seen.add(name)
    for rhs in _assignments_for(name, prefix, prefix_masked):
        for source in _trace_sources(rhs, prefix, prefix_masked, depth=depth + 1,
                                     seen=set(seen)):
            _append(out, source, limit=12)
    return out


def _trace_literal(expression: str, prefix: str, prefix_masked: str,
                   *, depth: int = 0, seen: set[str] | None = None) -> str | None:
    literal = _java_string(expression)
    if literal is not None:
        return literal
    if depth >= 5:
        return None
    simple = _SIMPLE_REFERENCE.match(expression)
    if not simple:
        return None
    name = simple.group("name")
    seen = set() if seen is None else seen
    if name in seen:
        return None
    seen.add(name)
    for rhs in _assignments_for(name, prefix, prefix_masked):
        value = _trace_literal(rhs, prefix, prefix_masked, depth=depth + 1, seen=set(seen))
        if value is not None:
            return value
    return None


def _assignments_for(name: str, prefix: str, prefix_masked: str) -> list[str]:
    pattern = re.compile(
        rf"(?<![\w$=!<>])(?:this\s*\.\s*)?{re.escape(name)}\s*=\s*(?!=)"
        rf"(?P<rhs>[^;]{{1,2000}});",
        re.DOTALL,
    )
    matches = list(pattern.finditer(prefix_masked))
    if not matches:
        return []
    # This is a bounded straight-line approximation, not a control-flow graph. Following
    # older overwritten values creates a much worse failure mode: a safely replaced
    # Intent/HTTP value is still reported as attacker-influenced. Use only the latest
    # reaching textual definition and leave branch-sensitive cases for runtime tracing.
    match = matches[-1]
    return [prefix[match.start("rhs"):match.end("rhs")].strip()]


def _method_ranges(masked: str) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for match in _METHOD_DECL.finditer(masked):
        opening = match.end() - 1
        closing = _matching_delimiter(masked, opening, "{", "}")
        if closing is not None:
            ranges.append((opening + 1, closing, match.group("name")))
    return ranges


def _enclosing_method(ranges: list[tuple[int, int, str]], pos: int,
                      text_len: int) -> tuple[int, int, str | None]:
    candidates = [r for r in ranges if r[0] <= pos <= r[1]]
    if not candidates:
        return max(0, pos - 4000), min(text_len, pos + 4000), None
    return min(candidates, key=lambda r: r[1] - r[0])


def _call_arguments(text: str, opening: int) -> tuple[list[str], int | None]:
    closing = _matching_delimiter(text, opening, "(", ")")
    if closing is None:
        return [], None
    body = text[opening + 1:closing]
    args: list[str] = []
    start = 0
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    for i, char in enumerate(body):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif stack and char == stack[-1]:
            stack.pop()
        elif char == "," and not stack:
            args.append(body[start:i])
            start = i + 1
    args.append(body[start:])
    return args, closing


def _matching_delimiter(text: str, opening: int, left: str, right: str) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    i = opening
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char == "/" and nxt == "/":
            line_comment = True
            i += 1
        elif char == "/" and nxt == "*":
            block_comment = True
            i += 1
        elif char in {'"', "'"}:
            quote = char
        elif char == left:
            depth += 1
        elif char == right:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _mask_non_code(text: str) -> str:
    """Replace string/comment contents with spaces while preserving offsets/newlines."""
    chars = list(text)
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    i = 0
    while i < len(chars):
        char = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            else:
                chars[i] = " "
        elif block_comment:
            if char == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                block_comment = False
                i += 1
            elif char != "\n":
                chars[i] = " "
        elif quote:
            if escaped:
                if char != "\n":
                    chars[i] = " "
                escaped = False
            elif char == "\\":
                chars[i] = " "
                escaped = True
            elif char == quote:
                quote = None
            elif char != "\n":
                chars[i] = " "
        elif char == "/" and nxt == "/":
            chars[i] = chars[i + 1] = " "
            line_comment = True
            i += 1
        elif char == "/" and nxt == "*":
            chars[i] = chars[i + 1] = " "
            block_comment = True
            i += 1
        elif char in {'"', "'"}:
            quote = char
        i += 1
    return "".join(chars)


def _java_string(expression: str) -> str | None:
    stripped = expression.strip()
    if not (len(stripped) >= 2 and stripped[0] == stripped[-1] == '"'):
        return None
    try:
        value = json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, str) else None


def _record_version(state: _State, version: str, evidence: dict) -> None:
    bucket = state.versions.setdefault(version, [])
    _append(bucket, evidence)


def _version_key(version: str) -> tuple:
    parts = re.split(r"[.+-]", version)
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in parts)


def _has_source(path: dict, source_type: str) -> bool:
    return any(s.get("type") == source_type for s in path.get("sources", []))


def _path_confidence(paths: list[dict]) -> str:
    if not paths:
        return "not_found"
    depths = [s.get("depth", 99) for p in paths for s in p.get("sources", [])
              if s.get("type") == "intent"]
    return "high" if depths and min(depths) == 0 else "medium"


def _source_evidence(kind: str, value: str, rel: str, text: str, pos: int) -> dict:
    return {"kind": kind, "value": value, "file": rel, "line": _line(text, pos)}


def _call_evidence(kind: str, value: str, rel: str, text: str, pos: int) -> dict:
    return {"kind": kind, "value": value, "file": rel, "line": _line(text, pos)}


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _short(value: str, limit: int = 220) -> str:
    return " ".join(value.split())[:limit]


def _append(bucket: list[dict], item: dict, *, limit: int = MAX_EVIDENCE) -> None:
    if len(bucket) < limit and item not in bucket:
        bucket.append(item)


def _notice(bucket: list[str], message: str) -> None:
    """Deduplicate and bound coverage warnings from hostile/very large archives."""
    if message in bucket:
        return
    if len(bucket) < MAX_COVERAGE_NOTICES:
        bucket.append(message)
    elif len(bucket) == MAX_COVERAGE_NOTICES:
        bucket.append("additional coverage notices omitted")


# --------------------------------------------------------------------------
# Batch triage
# --------------------------------------------------------------------------
# Answers "which of these APKs ship the exploitable Lottie stack" without jadx.
# The Q1-Q10 archive pass alone is enough for a go/no-go, so a whole corpus can
# be swept in seconds; only the survivors are worth a full `code` run.

#: Verdicts, most severe first.  Ordering is the ranking used by `scan_many`.
SCAN_VERDICTS: tuple[str, ...] = (
    "dotlottie_native_expressions_b64",   # RCE preconditions structurally present
    "dotlottie_native_expressions",       # expression engine, no raw-byte sink seen
    "dotlottie",                          # dotLottie present, no native expression engine
    "rlottie",
    "lottie_android",
    "lottie_web",
    "none",
)


def _verdict(report: dict) -> str:
    q = report["questions"]
    q6 = q["q6_expressions"]
    native_expr = any(
        e.get("kind") == "native_dotlottie_thorvg_expression_engine"
        for e in q6["evidence"]
    )
    b64 = any(e.get("b64_partial_overwrite_reachable") for e in q6["evidence"])
    if native_expr and b64:
        return "dotlottie_native_expressions_b64"
    if native_expr:
        return "dotlottie_native_expressions"
    if q["q5_dotlottie"]["answer"]:
        return "dotlottie"
    if q["q4_rlottie"]["answer"]:
        return "rlottie"
    if q["q1_lottie_android"]["answer"]:
        return "lottie_android"
    if q["q3_lottie_web"]["answer"]:
        return "lottie_web"
    return "none"


def scan_one(apks: Path | Iterable[Path], *, label: str | None = None) -> dict:
    """Fingerprint a single APK or split set without decompiling.

    ``analyze`` needs a jadx tree for the source-level questions; the archive
    pass that answers Q1/Q3/Q4/Q5/Q6 does not.  Passing a non-existent tree is
    deliberate — it yields "not found by this static pass" for the source-only
    questions, which is exactly the right answer for a triage sweep.
    """
    apk_list = [apks] if isinstance(apks, Path) else [Path(p) for p in apks]
    report = analyze(Path("/nonexistent-triage-tree"), apk_list)
    verdict = _verdict(report)
    return {
        "label": label or apk_list[0].name,
        "apks": [str(p) for p in apk_list],
        "verdict": verdict,
        "exploitable_stack": verdict == "dotlottie_native_expressions_b64",
        "stacks_present": report["summary"]["stacks_present"],
        "artifact_hint": "run `code` on this target for delivery-path evidence",
    }


def scan_many(targets: Mapping[str, Iterable[Path]] | Iterable[Path]) -> dict:
    """Sweep a corpus and rank by how exploitable the Lottie stack is.

    ``targets`` is either a mapping of label -> APK paths (a split set per
    label), or a flat iterable of single APKs.
    """
    if isinstance(targets, Mapping):
        items = [(label, list(paths)) for label, paths in targets.items()]
    else:
        items = [(Path(p).name, [Path(p)]) for p in targets]

    results: list[dict] = []
    errors: list[dict] = []
    for label, paths in items:
        try:
            results.append(scan_one(paths, label=label))
        except Exception as exc:                      # a hostile archive must not end the sweep
            errors.append({"label": label, "error": f"{type(exc).__name__}: {exc}"})

    order = {v: i for i, v in enumerate(SCAN_VERDICTS)}
    results.sort(key=lambda r: (order.get(r["verdict"], len(order)), r["label"]))
    candidates = [r for r in results if r["exploitable_stack"]]
    return {
        "scanned": len(results),
        "errors": errors,
        "candidates": [r["label"] for r in candidates],
        "counts": {v: sum(1 for r in results if r["verdict"] == v)
                   for v in SCAN_VERDICTS if any(r["verdict"] == v for r in results)},
        "results": results,
    }
