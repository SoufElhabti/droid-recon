# droid-recon usage guide

This guide describes the current development snapshot. Use droid-recon only on apps and devices you own or are authorized to test. The new version has automated tests, a small fixture benchmark, and a live smoke audit of a developer-owned synthetic APK on an Android 14/API 34 emulator. Treat behavior on other apps and devices as unverified until tested in their environment.

## 1. Install and inspect your host

Python 3.11 or later is required. Install from the project directory:

```text
python -m pip install -e ".[dev]"
python -m pytest tests -q
droid-recon doctor
```

On Windows, use `py -3.11` in place of `python` if necessary. On macOS or Linux, activate your virtual environment first if you use one. The Python runtime itself has no third-party package dependencies; `pytest` is only for the development test suite. Set `DROID_RECON_JADX_CACHE` to a writable directory if the default cache under your home directory lacks space; apktool's resource cache is stored alongside it.

`doctor` reports which host tools it can find: Android SDK manifest tools, ADB and emulator, JADX, apktool, Frida, mitmdump, and Ghidra. It checks paths and reports stage availability. It does **not** launch an emulator, validate the APK, or prove a stage will work on a particular device. Install and configure the Android SDK and the optional tools required for the stages you intend to use. Host support, especially for device and instrumentation workflows on Windows, should be validated locally.

## 2. Start with the APK

The input can be one APK or a directory containing a base APK and split APKs from the same app:

```text
droid-recon static ./targets/app.apk
droid-recon code ./targets/app.apk
droid-recon static ./targets/app-splits/
droid-recon code ./targets/app-splits/
```

`static` reads the manifest, merges components from base and feature APKs, and records which APK supplied each component. It reports explicit and inferred exported state, permissions, actions, deep links, authorities, FileProvider paths when resource decoding succeeds, and a `reachable_from` classification. Provider read, write, and `call()` reachability are reported separately, so a write-only or call-reachable provider still appears in the surface even when reads are guarded. Package identity and split structure are checked before analysis. `--no-resources` skips apktool-backed resource work and records that coverage gap.

`code` uses JADX. It records code hits and provider paths, then extracts Intent extra keys, accessor types, source lines, and associated components where it can resolve them. For directly observed compatible literal defaults, it records the literal and its source; otherwise it marks the default unknown or not applicable. It also lists nearby same-method `if` checks after a direct assigned extra read as **validation evidence**, without deciding whether the check is effective. Per-field confidence and unknown-field markers make partial extraction visible. Dynamic payload generation uses extracted keys and types only when the code report matches the exact APK set; otherwise it falls back to generic guesses. A missing extracted key or type is **unknown**, not proof that the app accepts no input.

The code report also includes source-to-sink **candidates** for exported components. Each candidate points to source and sink lines and lists nearby checks such as URI host comparisons or permission calls. This is a same-method, lexical Java analysis of JADX output. It does not trace arbitrary calls, fields, callbacks, Kotlin, reflection, or native code; it does not decide whether nearby validation is effective. Every such result remains `STATIC_CANDIDATE` until separately tested.

## 3. Test on a device

For a device you control, attach it with ADB or start a configured AVD:

```text
droid-recon device list
droid-recon device up --avd your_avd
droid-recon dynamic ./targets/app.apk --screenshots --traversal
droid-recon exploit ./targets/app.apk --max-payloads 10
droid-recon verify-caller ./targets/app.apk
```

`dynamic` installs the APK set unless `--no-install` is given, then probes IPC entry points and records observations. `exploit` sends selected payloads and checks effects with its oracle. Neither a successful ADB command nor a static source-to-sink match is a confirmed vulnerability. Shell probes execute with the ADB shell's privileges, which may differ from those of an ordinary app.

`verify-caller` builds or accepts a small companion APK and runs IPC requests from that companion's separate, unprivileged UID. ADB launches the companion, but the target IPC call originates from the companion process. The Python wheel includes its Java/Gradle source, not a prebuilt APK. It can build offline with a suitable Android SDK and JDK; use `--companion-apk /path/to/companion.apk` if local build tools are unavailable. The supplied release APK is recognized by its exact SHA-256. Other supplied APKs must declare the expected package with no permissions or shared UID, and their results remain **inconclusive** because their code identity is unverified. `--type activity` or `--limit 10` can narrow the check. Its result describes **reachability**, not data exposure or exploit impact. Broadcast dispatch and some activity launches have no reliable acknowledgement and stay inconclusive. A provider `null` cursor is also inconclusive. Results are stored in `ordinary_results.jsonl`, and unsupported build prerequisites are recorded in coverage.

For an authorized provider `ContentProvider.call()` method, pass `--provider-method METHOD` to `verify-caller` or `audit --deep`. The flag can be repeated for multiple methods. Ordinary UID `call()` requests are not sent automatically because methods can have side effects; choose methods you are authorized to invoke. A successful dispatch still needs effect and impact review.

For the coordinated pipeline:

```text
droid-recon audit ./targets/app.apk
droid-recon audit ./targets/app.apk --deep --screenshots
droid-recon audit ./targets/app.apk --deep --resume
```

The ordinary `audit` runs static and code analysis, device IPC probing, triage, and reporting. `--deep` adds targeted payloads, ordinary UID verification, UI exploration, and chain building. `--explore` requests UI exploration without the full deep pass. Optional test account inputs are `--credentials`, or `--username` and `--password`; use only accounts provided for testing. `--reset-app-data` clears app state before probing a new run. Network interception and native analysis are separate explicit commands, so a normal or deep audit records them as skipped.

`audit --resume` checks the same APK hashes and tracked coverage options as the active run. If a companion APK was supplied, it checks that file's hash; once runtime work binds a device, resuming on another serial is rejected. It reuses completed phases; a fresh `audit` archives previous session contents under `sessions/<package>/runs/<run-id>/`. The run configuration records reproducibility settings and omits passwords and API keys. There is no automatic emulator reset between all individual cases; use a clean device state when comparing runs.

## 4. Compare releases

```text
droid-recon diff ./releases/old/ ./releases/new/ --output ./surface-diff.json
```

`diff` requires the same package on both sides. It compares components and reachability, exported state, guards, deep links, app-level SDK and security settings, permissions, and the hashes of packaged DEX, native, JAR, and bundle files. It highlights newly reachable components. A changed packaged binary indicates a change; **it does not identify the exact dependency or dependency version**, and a difference is not itself a vulnerability verdict.

## 5. Read and share evidence

`droid-recon report com.example.app` writes a bounded `report.md` and `report.json` under `sessions/<package>/`. `--format json` prints the JSON summary. The report links the full artifacts when a detail is omitted from its short view.

| Artifact | Purpose |
| --- | --- |
| `attack_surface.json` | Merged manifest surface and per-component reachability |
| `code_report.json` | Code hits, Intent input extraction, provider paths, flow candidates |
| `evidence_manifest.json` | APK SHA-256, certificate fingerprint when `apksigner` is available, app version, SDK/device/WebView context, execution contexts, non-secret configuration |
| `coverage.jsonl` | Append-only stage, check, and component status, reason, result state, and evidence IDs where recorded |
| `observations.jsonl` | Individual probes, including low-confidence signals; these are not findings |
| `ordinary_results.jsonl` | Companion app reachability checks, when run |
| `exploits.jsonl` | Payload attempts and oracle evidence, when run |
| `findings.jsonl` / `triage_candidates.json` | Promoted findings and items needing manual review |
| `run_manifest.json` / `state.json` | Audit identity, options, and completed phases |

The evidence manifest records a reason when the certificate fingerprint cannot be read. It includes the device API level, app `targetSdkVersion`, and WebView package when available. These values matter: Android export, App Links, storage, and Intent redirection behavior varies by OS and target SDK. The report adds version caveats, but it cannot infer App Links user approval or turn manifest settings alone into runtime proof.

Coverage uses two separate fields. `status` says whether a check was `tested`, `skipped`, `unsupported`, or `failed`; non-tested work has a reason. `result_state` describes the evidence:

| State | Meaning |
| --- | --- |
| `STATIC_CANDIDATE` | Source or configuration suggests a possible issue; no runtime effect established |
| `OBSERVED` | Runtime signal seen; reachability, impact, or chain still unproven |
| `CONFIRMED` | Reachable entry point, effect, and source-to-sink chain supported by evidence IDs |
| `INCONCLUSIVE` | Check ran but evidence does not support a conclusion |
| `BLOCKED` | A prerequisite or execution failure prevented completion |
| `NOT_TESTED` | Check was skipped or unsupported |

The coverage matrix summarizes **recorded checks only**. An empty stage is not a pass. The report may attach [OWASP MASVS, MASWE, and MASTG references](docs/standards-mapping.md) to checks and flow candidates. Those references are review pointers; running a check does not verify a MASVS control. The catalog stores its mapping version, review date, sources, and limitations.

## 6. Triage findings

The main rule is: **the manifest establishes possible reachability; probes establish effect**. `reachable_from=browser` or `third_party_app` can make a component eligible for review. `shell` and guarded `none` cannot be promoted solely because ADB invoked them. The separate UID result adds evidence about another app's actual reachability, subject to its inconclusive cases.

An observation becomes a finding only after the triage gates support caller reachability, a real effect, and a coherent source-to-sink story. `Status: ok`, a screen opening, or a decompiler hit alone does not meet those gates. Read `triage_candidates.json` for rejected or unresolved leads and the reason they were not promoted. Recheck any finding on the Android version and app build named in the evidence manifest.

## 7. Optional tools and model

The existing `net`, `frida`, `native`, `ghidra`, `ui`, and `chains` commands remain available for focused follow-up work. They need their own tools and device prerequisites. For example:

```text
droid-recon net status
droid-recon net capture com.example.app --duration 30
droid-recon native libs com.example.app
droid-recon ui state com.example.app
droid-recon chains com.example.app
```

Use each command's `--help` for its current options. A normal `audit` does not run network interception or native analysis automatically. An MCP client can start `droid-recon mcp` as a stdio server by pointing its server configuration at the installed executable and passing `mcp` as the argument. The server exposes only read-only tools by default and blocks a device-changing call even if a client requests it. An operator who wants those tools in MCP must start `droid-recon mcp --allow-mutating-tools` or set `DROID_RECON_MCP_ALLOW_MUTATIONS=1`. The client's own permission policy can add another gate.

An optional interactive model can drive the tool interface:

```text
droid-recon agent --check
droid-recon agent
droid-recon agent "audit ./targets/app.apk"
```

The default remote endpoint uses DeepSeek and requires `DEEPSEEK_API_KEY`. A local OpenAI-compatible endpoint can be selected with `--base-url http://127.0.0.1:PORT` and `--model`; loopback can run without a key. Remote endpoints require HTTPS and a key. The model is not used by the ordinary static or audit commands.

The agent bounds tool output and redacts common secret fields and credential patterns before model requests and saved transcripts. In its interactive session, `/preview` shows a redacted preview of the context, `/save` saves the redacted transcript, and `/approval auto|suggest|full-auto` controls model-initiated device changes. Heuristic redaction cannot promise to catch every secret, so review the preview before using a remote model with sensitive APKs or logs. APK strings and tool output are untrusted input. The agent's approval policy applies to its own tool calls; the MCP server has a separate, default read-only gate for direct clients.

## 8. Current limits and validation

- A synthetic APK completed a deep audit on an Android 14/API 34 x86_64 emulator: manifest and code analysis, IPC probes, ordinary-UID checks, limited UI exploration, evidence reporting, and a duplicate-free completed resume. This is a smoke test, not a real-app accuracy estimate. Network interception, Frida, and Ghidra were not exercised in that run.
- The source-to-sink benchmark contains eight small Java fixtures: four vulnerable and four corrected examples. It measures that corpus only, not accuracy on real apps. Static candidates may be false positives or miss multi-method and non-Java flows. Intent defaults are limited to directly observed compatible literals, and listed validation checks may be ineffective or irrelevant.
- Split APK support merges declared components and code inputs. It does not reconstruct every Play delivery or runtime feature-install condition.
- Ordinary UID checks distinguish accepted, denied, and inconclusive cases. They do not prove a vulnerability, and the companion may be unavailable without Android build tools or a supplied APK.
- `diff` reports packaged binary changes but cannot name exact third-party dependencies or their versions.
- UI exploration is heuristic and may miss authenticated, gesture-heavy, CAPTCHA, biometric, or WebView-rendered flows.
- The [WebView lab report](docs/example-report-webviewlab.md) is a historical example from an earlier developer-owned run. Its device evidence was not reproduced for this version.
