"""OWASP MASVS/MASWE/MASTG references for checks droid-recon actually runs.

The catalog is a cross-reference, never a certification result. A recorded stage
or a static candidate must not be described as passing or failing an OWASP test.
The live OWASP pages linked here were checked on 2026-10-01.
"""

from __future__ import annotations

from dataclasses import dataclass

CATALOG_VERSION = "2026-10-01-owasp-mas-v2"
CHECKED_ON = "2026-10-01"
UPSTREAM_VERSIONS = {
    "MASVS": "v2 controls",
    "MASWE": "live online catalog",
    "MASTG": "v2 current test IDs",
}


@dataclass(frozen=True)
class Reference:
    id: str
    title: str
    url: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "title": self.title, "url": self.url}


_REFERENCES = {
    "MASVS-PLATFORM-1": Reference(
        "MASVS-PLATFORM-1", "The app uses IPC mechanisms securely",
        "https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/"),
    "MASVS-PLATFORM-2": Reference(
        "MASVS-PLATFORM-2", "The app uses WebViews securely",
        "https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/"),
    "MASVS-CODE-4": Reference(
        "MASVS-CODE-4", "The app validates and sanitizes all untrusted inputs",
        "https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/"),
    "MASWE-0018": Reference(
        "MASWE-0018", "Lack of Authentication or Authorization on App Components",
        "https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/"),
    "MASWE-0029": Reference(
        "MASWE-0029", "Insecure Deep Links",
        "https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/"),
    "MASWE-0032": Reference(
        "MASWE-0032", "Insecure Intents",
        "https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/"),
    "MASWE-0034": Reference(
        "MASWE-0034", "WebViews Allow Access to Local Resources with Untrusted Content",
        "https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/"),
    "MASWE-0035": Reference(
        "MASWE-0035", "WebViews Loading Untrusted Content",
        "https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/"),
    "MASWE-0050": Reference(
        "MASWE-0050", "Unsafe Handling of Untrusted Data",
        "https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/"),
    "MASTG-TEST-0252": Reference(
        "MASTG-TEST-0252", "References to Local File Access in WebViews",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0252/"),
    "MASTG-TEST-0355": Reference(
        "MASTG-TEST-0355", "References to Unauthorized Database Access through Content Providers",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0355/"),
    "MASTG-TEST-0364": Reference(
        "MASTG-TEST-0364", "Exported And Unprotected Activities That Expose Sensitive Functionality",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0364/"),
    "MASTG-TEST-0365": Reference(
        "MASTG-TEST-0365", "Exported And Unprotected Services That Expose Sensitive Functionality",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0365/"),
    "MASTG-TEST-0366": Reference(
        "MASTG-TEST-0366", "Exported And Unprotected Broadcast Receivers That Expose Sensitive Functionality",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0366/"),
    "MASTG-TEST-0394": Reference(
        "MASTG-TEST-0394", "Missing Input Validation in Custom URL Scheme Handlers",
        "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0394/"),
}


@dataclass(frozen=True)
class Mapping:
    check_id: str
    actual_check: str
    relationship: str
    masvs: tuple[str, ...]
    maswe: tuple[str, ...]
    mastg: tuple[str, ...]
    limitation: str

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "actual_check": self.actual_check,
            "relationship": self.relationship,
            "masvs": [_REFERENCES[id_].to_dict() for id_ in self.masvs],
            "maswe": [_REFERENCES[id_].to_dict() for id_ in self.maswe],
            "mastg": [_REFERENCES[id_].to_dict() for id_ in self.mastg],
            "limitation": self.limitation,
            "catalog_version": CATALOG_VERSION,
            "checked_on": CHECKED_ON,
            "verified_control": False,
        }


_MAPPINGS = {
    "manifest.activity": Mapping(
        "manifest.activity", "Enumerate manifest-declared activity exports and permissions",
        "supports_test", ("MASVS-PLATFORM-1",), ("MASWE-0018",),
        ("MASTG-TEST-0364",),
        "Export and permission metadata alone do not show sensitive behavior or effective authorization."),
    "manifest.service": Mapping(
        "manifest.service", "Enumerate manifest-declared service exports and permissions",
        "supports_test", ("MASVS-PLATFORM-1",), ("MASWE-0018",),
        ("MASTG-TEST-0365",),
        "Bound-service interfaces and runtime caller checks require separate review."),
    "manifest.receiver": Mapping(
        "manifest.receiver", "Enumerate manifest-declared receiver exports and permissions",
        "supports_test", ("MASVS-PLATFORM-1",), ("MASWE-0018",),
        ("MASTG-TEST-0366",),
        "Context-registered receivers and sensitive onReceive behavior are not fully covered."),
    "manifest.provider": Mapping(
        "manifest.provider", "Inspect exported provider authorities and read/write permissions",
        "supports_test", ("MASVS-PLATFORM-1",), ("MASWE-0018",),
        ("MASTG-TEST-0355",),
        "Permission presence does not establish protection level or whether provider data is sensitive."),
    "manifest.deeplink": Mapping(
        "manifest.deeplink", "Enumerate browsable deep-link declarations and probeable URI shapes",
        "preparatory", ("MASVS-PLATFORM-1",), ("MASWE-0029",),
        ("MASTG-TEST-0394",),
        "Enumeration does not assess handler validation; the cited MASTG test applies to custom schemes."),
    "dynamic.component_probe": Mapping(
        "dynamic.component_probe", "Launch or query a manifest component through ADB and record its response",
        "partial_observation", ("MASVS-PLATFORM-1",), ("MASWE-0018",), (),
        "ADB shell privileges differ from an ordinary app; a response does not prove third-party reachability."),
    "dynamic.ordinary_caller": Mapping(
        "dynamic.ordinary_caller", "Launch or query a component from a separate app UID with no requested permissions",
        "partial_observation", ("MASVS-PLATFORM-1",), ("MASWE-0018",), (),
        "OS access from one ordinary caller does not prove a sensitive effect or full authorization coverage."),
    "code.webview_file_access": Mapping(
        "code.webview_file_access", "Find WebView file-origin access setting references in decompiled Java",
        "partial_observation", ("MASVS-PLATFORM-2",), ("MASWE-0034",),
        ("MASTG-TEST-0252",),
        "A regex hit does not identify a WebView instance, runtime settings, local content, or exploitability."),
    "flow.webview": Mapping(
        "flow.webview", "Trace an external Intent value to loadUrl/evaluateJavascript in one Java method",
        "static_candidate", ("MASVS-PLATFORM-2", "MASVS-CODE-4"),
        ("MASWE-0035",), (),
        "Lexical flow and nearby checks do not prove control of the rendered content or ineffective validation."),
    "flow.intent": Mapping(
        "flow.intent", "Trace an external nested Intent to startActivity in one Java method",
        "static_candidate", ("MASVS-PLATFORM-1",), ("MASWE-0032",), (),
        "The forwarded destination, flags, caller identity, and runtime effect require review."),
    "flow.untrusted_input": Mapping(
        "flow.untrusted_input", "Trace an external Intent value to a command or SQL sink in one Java method",
        "static_candidate", ("MASVS-CODE-4",), ("MASWE-0050",), (),
        "The scanner is not a Java taint engine; parameterization, branching, and runtime behavior need review."),
}


def metadata() -> dict:
    return {
        "catalog_version": CATALOG_VERSION,
        "checked_on": CHECKED_ON,
        "upstream_versions": dict(UPSTREAM_VERSIONS),
        "source": "https://mas.owasp.org/",
        "scope": "Cross-reference for implemented checks; no control or test is verified by mapping alone.",
    }


def check_ids() -> tuple[str, ...]:
    return tuple(_MAPPINGS)


def for_check(check_id: str) -> dict:
    """Return references for one implemented check; fail closed on unknown IDs."""
    return _MAPPINGS[check_id].to_dict()


def annotate_coverage(entry: dict, check_id: str) -> dict:
    """Attach references without changing tested/skipped or evidence-state claims."""
    return {**entry, "standards": for_check(check_id)}


def flow_check_id(candidate: dict) -> str | None:
    """Select a mapping from the concrete sink recognized by flows.analyze."""
    api = (candidate.get("sink") or {}).get("api")
    if api in ("WebView.loadUrl", "WebView.evaluateJavascript"):
        return "flow.webview"
    if api == "startActivity":
        return "flow.intent"
    if api in ("Runtime.exec", "ProcessBuilder", "raw SQL"):
        return "flow.untrusted_input"
    return None


def annotate_flow_candidate(candidate: dict) -> dict:
    """Attach relevant references, leaving unknown sink types unclassified."""
    check_id = flow_check_id(candidate)
    return annotate_coverage(candidate, check_id) if check_id else dict(candidate)
