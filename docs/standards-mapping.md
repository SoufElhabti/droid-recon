# OWASP mapping for implemented checks

Checked against the live OWASP Mobile Application Security site on **2026-10-01**.
This catalog uses MASVS v2 controls and current MASTG v2 test IDs. The site is
updated independently of this project, so the checked date is part of every
machine-readable mapping.

**A mapping is a pointer for review, not a test result.** A stage marked `tested`
means that droid-recon ran its check. It does not mean the app passes a MASVS
control or an entire MASTG test. Static flow results remain `STATIC_CANDIDATE`.

| droid-recon check | OWASP references | What remains to verify |
|---|---|---|
| `manifest.activity` | [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/), [MASTG-TEST-0364](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0364/) | Sensitive behavior and effective authorization. |
| `manifest.service` | [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/), [MASTG-TEST-0365](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0365/) | Bound-service APIs and runtime caller checks. |
| `manifest.receiver` | [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/), [MASTG-TEST-0366](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0366/) | Context-registered receivers and sensitive `onReceive` actions. |
| `manifest.provider` | [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/), [MASTG-TEST-0355](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0355/) | Effective permission protection and sensitivity of returned data. |
| `manifest.deeplink` | [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASWE-0029](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0029/), [MASTG-TEST-0394](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0394/) | Enumeration only supports the custom-scheme test; handler validation is not determined. |
| `dynamic.component_probe` | [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/) | ADB shell has different privileges from an ordinary app; a response is not proof of reachability. |
| `code.webview_file_access` | [MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/), [MASWE-0034](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/), [MASTG-TEST-0252](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0252/) | Regex references do not establish the combined WebView settings, content trust, or runtime effect required by the test. |
| `flow.webview` | [MASVS-PLATFORM-2](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/), [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/), [MASWE-0035](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/) | Local lexical flow; actual URL control and validation must be reviewed. |
| `flow.intent` | [MASVS-PLATFORM-1](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/), [MASWE-0032](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0032/) | Destination, flags, identity and runtime effect. |
| `flow.untrusted_input` | [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/), [MASWE-0050](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/) | Local lexical flow is not a complete taint analysis or injection proof. |

The catalog intentionally omits a MASTG ID for generic WebView, Intent forwarding,
command, and SQL flow candidates where the available current test has a narrower
scope. For example, [MASTG-TEST-0339](https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0339/)
is specifically about SQL injection in **content providers**; a generic `rawQuery`
candidate in an activity does not satisfy it. Likewise,
[MASTG-TEST-0393](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0393/)
requires evaluating App Link verification, which this manifest model does not yet do.

The Python API in `droid_recon.standards` exposes `metadata()`, `for_check(id)`,
`annotate_coverage(entry, id)`, and `annotate_flow_candidate(candidate)`.
