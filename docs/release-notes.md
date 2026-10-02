# Development snapshot: broader surface and clearer evidence

**Date:** 2026-10-01  
**Package version:** `0.3.0` in `pyproject.toml`; this is a development snapshot and has not been published as a release.

This snapshot expands APK intake and review coverage while making the strength and limits of each observation explicit. The Python test suite and an eight-case Java fixture corpus exercise these features. A developer-owned synthetic APK completed a live deep-audit smoke run on an Android 14/API 34 emulator. Device-specific behavior still needs confirmation on the intended Android build and target app.

## Added

| Area | Change |
| --- | --- |
| APK input | Analyze a base APK with feature and configuration splits from one directory; retain per-APK hashes and component provenance. |
| Code inputs | Extract Intent extra keys, accessor types, source references, directly observed compatible literal defaults, and nearby same-method validation evidence from JADX output. Mark unknown fields and confidence explicitly. Reuse keys/types for payloads only when the report matches the APK identity. |
| Flow review | Show conservative, same-method Java source-to-sink candidates for exported components, including lines and nearby validation calls. All remain `STATIC_CANDIDATE`. |
| Ordinary caller | Use a separate, unprivileged companion app UID for component reachability checks. Record accepted, denied, and inconclusive outcomes. Explicit `--provider-method` enables selected `ContentProvider.call()` checks; they are never auto-sent by the ordinary caller. The wheel includes buildable companion source; the separately supplied release APK is trusted by exact SHA-256. Unknown custom APKs remain inconclusive even if their manifest requests no permissions. |
| Evidence | Save APK SHA-256, signing certificate fingerprint when available, app version, target/device SDK, WebView/device context, execution context, and non-secret audit options. |
| Coverage | Record tested, skipped, unsupported, and failed checks with reasons; distinguish static candidates, observations, confirmations, inconclusive outcomes, blocks, and untested work. |
| Standards | Add dated, sourced MASVS v2 / MASWE / MASTG v2 review references for implemented checks. A reference does not claim control verification. |
| Provider surface | Report read, write, and `call()` reachability separately, including providers whose read operation is guarded but another operation is reachable. |
| Release comparison | Compare exported components, permissions, deep links, SDK/security settings, and packaged code/library hashes with `diff`. |
| Repeatability | Archive old session artifacts and checkpoint completed phases. `audit --resume` checks APK hashes, tracked coverage options, a supplied companion APK's hash, and the bound device serial. |
| Setup | Add read-only `doctor` capability inventory for Python, Android SDK, and optional tooling. |
| Agent and MCP | Allow an optional local loopback OpenAI-compatible model, bound model input, redact common secrets, preview outbound context, and apply approval policy to model tool calls. Direct MCP use is read-only by default until the operator opts in to device-changing tools. |

## How to use the additions

```text
droid-recon doctor
droid-recon static ./app-splits/
droid-recon code ./app-splits/
droid-recon verify-caller ./app-splits/
droid-recon diff ./old-splits/ ./new-splits/ --output ./surface-diff.json
droid-recon audit ./app-splits/ --deep
droid-recon audit ./app-splits/ --deep --resume
```

`verify-caller`, `audit --deep`, and the optional device workflows require an authorized attached device or emulator. `code` needs JADX. `doctor` only checks the host; it does not execute a trial audit. See the [guide](../GUIDE.md) for prerequisites and artifact interpretation.

## Validation and limitations

- The source-to-sink benchmark has four deliberately vulnerable and four corrected Java snippets. At the benchmark's `no_guard_seen` threshold it reports 4 true positives, 4 true negatives, 0 false positives, and 0 false negatives **on those fixtures only**. This is not a real-app accuracy estimate.
- The lexical flow analyzer does not track interprocedural, Kotlin, callback, reflection, or native paths. Nearby validation is displayed for review, not verified. Intent defaults are limited to directly observed compatible literals; computed defaults and effective validation are not inferred.
- An ordinary UID result establishes only the companion app's observed ability or inability to issue a request under the tested OS conditions. Dispatch without acknowledgement and `null` provider cursors stay inconclusive.
- ADB shell effects, manifest-declared reachability, source candidates, and confirmed findings are different evidence classes. The report's `coverage.jsonl` and evidence states preserve those differences.
- Android behavior can vary with device API level, app `targetSdkVersion`, user-approved App Links, and WebView version. The report includes context and caveats where available; manifest data cannot prove App Links approval or actual exploit effect.
- `diff` sees packaged binary changes but does **not** identify the exact third-party dependency or its version.
- The setup checker inventories host capabilities; a separate smoke run verified an Android 14/API 34 emulator, synthetic APK installation, logs, screenshots, ordinary-UID activity and deep-link reachability, limited UI exploration, and a duplicate-free completed resume. Network interception, Frida, and Ghidra still need their own local checks.
- The optional agent's redaction is heuristic. Inspect `/preview` before sending sensitive APK-derived text or logs to a remote model. The MCP server blocks device-changing tools by default; enabling them requires `mcp --allow-mutating-tools` or `DROID_RECON_MCP_ALLOW_MUTATIONS=1`, and a client may add its own restrictions.
