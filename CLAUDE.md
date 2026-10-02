# droid-recon operator and orchestrator guide

This is the operational contract for the **0.4.0.dev1 development candidate**. `prompt.md` records the original vision; use the implemented commands and evidence rules here when the two differ. Device-specific claims from earlier developer-owned lab runs are labeled as historical below and must not be generalized to another target or Android build.

Use the tool only on applications and devices you own or are authorized to assess. See [GUIDE.md](GUIDE.md) for installation and the command walkthrough, and [docs/release-notes.md](docs/release-notes.md) for changes and limits.

## Reachability and effect are separate

> **The manifest gives a possible caller path. A probe shows an effect under its actual caller identity.**

An `adb shell` probe runs under the shell UID, which can have access an ordinary app lacks. A command returning `Status: ok` says only that the command was accepted. `reachable_from` is a manifest classification, never inferred from that exit code:

| `reachable_from` | Interpretation | Triage handling |
| --- | --- | --- |
| `browser` | Exported, BROWSABLE entry in the manifest | Eligible for review; real browser/App Links behavior still needs testing |
| `third_party_app` | Exported with no guard or a potentially obtainable guard | Eligible for review; check effective caller permissions |
| `shell` | Not exported to ordinary apps | Do not promote a shell-only probe |
| `none` | Exported but guarded by signature or privileged permission | Do not promote without evidence that the caller can satisfy the guard |

`verify-caller` supplies a stronger, separate reachability check: its companion APK makes IPC calls from its own unprivileged UID. ADB starts the companion, but the target call happens in the companion process. The wheel includes buildable Java/Gradle companion source, not a prebuilt APK; an operator can supply the separately delivered release APK with `--companion-apk` when local Android SDK/JDK build tools are unavailable. Its exact SHA-256 is recognized. Other supplied APKs are checked for package, permissions, and shared UID, but their results remain inconclusive because their code identity is unverified. An accepted call is still only a reachability observation. Broadcast dispatch, some activity launches, and a provider `null` cursor can be inconclusive. The tool does not read out provider row values through this companion.

Ordinary UID `ContentProvider.call()` requests require an explicit, repeatable `--provider-method METHOD` on `verify-caller` or `audit --deep`. The companion does not auto-call discovered methods because they may have side effects. Choose method names only within the authorized test scope.

**An unexported activity opened by `adb shell am start` is not a vulnerability.** Triage rejects shell-only reachability. Android version, target SDK, App Links approval, and app-specific checks can further narrow actual access.

## Recommended workflow

1. Run `droid-recon doctor` to see host capabilities. It is read-only and does not validate a device or APK.
2. Run `static` on an APK or a directory containing its base and split APKs. Review exported state, permissions, deep links, component provenance, per-operation provider read/write/`call()` reachability, and the manifest verdict.
3. Run `code` when JADX is available. Review the Intent key/type/source inventory, provider paths, and source-to-sink candidates. Candidates are review leads, not findings.
4. Run `dynamic` on an authorized device for IPC observations. Give provider paths from code analysis priority when the manifest lists providers.
5. Run `verify-caller` for sensitive or disputed entry points, or use `audit --deep` to include it in the coordinated pass. Keep inconclusive results explicit.
6. Run `exploit` for selected payloads, then `triage` and `report`. Examine the rejected and candidate queues before describing impact.
7. Use `diff` between releases to find newly exposed components or changed settings. It reports packaged binary changes, but it cannot identify exact dependency names or versions.

```text
python -m pip install -e ".[dev]"
droid-recon doctor
droid-recon static ./targets/app.apk
droid-recon code ./targets/app.apk
droid-recon dynamic ./targets/app.apk --type provider
droid-recon verify-caller ./targets/app.apk --type provider
droid-recon triage com.example.app
droid-recon report com.example.app
```

`audit ./targets/app.apk` coordinates static, code, device IPC, triage, and report work. `--deep` also runs selected payloads, ordinary UID checks, UI exploration, and chains. Network and native work are separate explicit commands. When a device is unavailable, `audit` returns a static report and marks the device work incomplete. `audit --resume` checks the same APK hashes and tracked coverage options, a supplied companion APK's hash, and the selected device serial once runtime work has bound it; a fresh audit archives the previous session under `runs/`. `--reset-app-data` can clear target state before probing a new run. There is no automatic clean emulator reset between every individual case.

The CLI accepts a single APK or a directory of APK splits. The code report can feed extracted Intent keys and types into payload generation when its APK hashes match the current target. The Intent inventory records directly observed compatible literal defaults with source references, or marks them unknown/not applicable. It lists nearby same-method `if` checks after directly assigned extra reads as validation evidence; it does not establish whether those checks work. Per-field confidence and unknown markers should guide manual review. Static flow candidates are separate same-method lexical Java matches with source and sink lines plus nearby validation calls; they cannot prove a vulnerability.

## Triage gates

An IPC observation is promoted only when the triage code can support:

1. A manifest path classified `browser` or `third_party_app`.
2. A meaningful effect such as returned rows or bytes, an attributed crash, or credential-shaped material in app logs. A launch status alone is not an effect.
3. A source-to-sink story for the effect.

An observation that passes the first two gates but lacks the story goes to `triage_candidates.json` for human review. Rejected observations retain a reason. Triage deduplicates findings by component, probe kind, and signal. Platform shared-UID packages receive a caveat and reduced confidence because exported platform APIs may be intentional. The operator still needs to verify the actual caller, sensitivity, Android build, and impact; a triage entry is not automatically a confirmed security report.

The payload oracle compares before and after signals such as logcat, UI state, process liveness, traffic, and canaries. A platform denial outranks positive-looking noise. Command echoes are excluded from canary evidence, and simply landing on the requested activity is the null result. An auth wall is not an auth bypass.

## Artifacts and evidence states

Current-session artifacts live under `sessions/<package>/`; older audit sessions are retained under `sessions/<package>/runs/<run-id>/` when a new audit starts.

| Artifact | Meaning |
| --- | --- |
| `attack_surface.json` | Merged manifest surface, including APK/split provenance |
| `code_report.json` | Code hits, provider paths, Intent inputs, and static flow candidates |
| `evidence_manifest.json` | APK hashes, signer fingerprint if available, app/SDK/device/WebView context, execution contexts, and non-secret options |
| `coverage.jsonl` | Append-only recorded checks, statuses, reasons, evidence states, and evidence IDs where available |
| `observations.jsonl` | Append-only probes; high recall, not findings |
| `ordinary_results.jsonl` | Companion UID results when run; accepted, denied, or inconclusive |
| `exploits.jsonl` | Payload attempts and oracle results when run |
| `findings.jsonl` | **Current triage output.** Re-running triage replaces it atomically; it is not an append-only history |
| `triage_candidates.json` | Manual queue and rejected observations with reasons |
| `run_manifest.json`, `state.json` | Input identity, reproducibility options, and completed phases |
| `report.md`, `report.json` | Bounded digest with links to full evidence and Android version caveats |

Coverage `status` is `tested`, `skipped`, `unsupported`, or `failed`; skipped, unsupported, and failed checks carry reasons. Its `result_state` is one of `STATIC_CANDIDATE`, `OBSERVED`, `CONFIRMED`, `INCONCLUSIVE`, `BLOCKED`, or `NOT_TESTED`. `CONFIRMED` requires evidence IDs and a supported entry point, effect, and chain. The matrix summarizes **recorded checks only**. An absent or skipped check cannot be interpreted as a pass.

The report adds dated [OWASP MASVS, MASWE, and MASTG mappings](docs/standards-mapping.md) as pointers for review. A completed tool check does not verify an entire OWASP control or test. Its Android version caveats use device API and app `targetSdkVersion` where available. The manifest cannot establish App Links user approval or runtime exploit impact.

## MCP and optional model

The project provides an MCP stdio server: launch the installed executable with the `mcp` argument from your client configuration. Use an absolute path appropriate to **your** host. It returns bounded summaries and artifact paths; open the full artifact only when needed. `session_status` shows current work. The number of MCP tools is taken from the live registry, so avoid hard-coded counts in client instructions. The server hides and blocks device-changing tools by default. An operator must pass `mcp --allow-mutating-tools` or set `DROID_RECON_MCP_ALLOW_MUTATIONS=1` to enable them; the MCP client's own permissions can impose an additional gate.

`droid-recon agent` is an optional in-process model loop over the same tool registry. It defaults to DeepSeek with `DEEPSEEK_API_KEY`, and can use a local loopback OpenAI-compatible endpoint with `--base-url` and `--model`. A remote endpoint requires HTTPS and an API key; ordinary CLI analysis needs neither. Read-only model tool calls run without prompts by default, while device-changing calls ask. `--approval suggest` prevents those changes; `--full-auto` permits them.

The agent redacts common credential shapes, bounds tool output, offers `/preview` for the outbound model context, and saves a redacted transcript with `/save`. Redaction is heuristic. APK strings, source, and tool output are untrusted input; review `/preview` before sending sensitive material to a remote model. The agent's approval policy does not govern a separate MCP client's direct tool calls, which use the MCP server's default read-only gate and any client policy.

## Optional device stages

`net`, `frida`, `native`, `ghidra`, `ui`, and `chains` are focused follow-up tools. They depend on local Android SDK, Java, mitmproxy, Frida, or Ghidra setup as appropriate. `doctor` reports the host tools it sees; it cannot certify a live setup. `ui explore` is heuristic and can miss WebView-rendered content, CAPTCHA, OTP, biometrics, and gesture-heavy flows. Chain replay does not automatically revalidate every traffic or native signal. A WebView URL positive control from the original lab was not reproduced by the historical automated payload path; do not claim this snapshot has validated that path.

The source-to-sink fixture benchmark has eight tiny Java examples (four vulnerable and four corrected). It produced 4 true positives, 4 true negatives, 0 false positives, and 0 false negatives at the `no_guard_seen` threshold **on that fixture corpus only**. It is not a real-app false-positive or false-negative rate. APK-to-APK `diff` also cannot name an exact third-party dependency from a binary hash change.

## Historical lessons from the original author's lab

The following measurements and false-positive examples came from developer-owned Android lab runs and earlier droid-recon versions. They were **not** rerun for every 0.4.0.dev1 change. The [WebView lab report](docs/example-report-webviewlab.md) is a historical example whose underlying device evidence bundle is not included here.

- On that lab's Android 14 image, a live Conscrypt APEX trust-store overlay required correct file labels and app mount namespaces. The earlier run reported 135 certificates after adding the test CA and a captured app HTTPS request. These counts and steps depend on the image; they are not current host prerequisites or validation.
- The earlier lab measured about 2.7 seconds for static manifest work, about 15 seconds for JADX on an 18 MB APK, and about 23 seconds for a headless emulator boot. Do not use these as runtime promises.
- An intent URI containing a shell-sensitive separator once caused the device shell to reject the command and echo the canary. The oracle now quotes device arguments and checks command errors first.
- Launching a requested activity once looked like a payload-induced transition. The oracle treats that landing as the null result.
- An instrumentation `uiautomator` exception once looked like a target crash. Crash attribution now checks the fatal thread and stack.
- Framework log tokens once looked like credential leaks. Attribution and value-shape checks reduce that false-positive class.

The original `prompt.md` suggested using `mobilerun`, counting a root-launched unexported activity as a finding, and relying on an obsolete `/system/etc/security/cacerts` write on Android 14. This implementation uses its own Python package, MCP server, optional agent, manifest reachability model, and device-version-aware reporting instead. Historical lab results remain useful as examples, but current findings need a fresh evidence bundle.

## Repository conventions

Python 3.11+, `src/` package layout, stdlib runtime, dataclasses, and argparse. Bound subprocess calls with timeouts. Keep APK strings and device/tool output as untrusted data. Add focused tests for security-significant classification, evidence, and parser behavior; do not use a static candidate as a confirmed-finding test. Run the suite with `python -m pytest tests -q` in the project environment. The manifest reachability fixtures and `tests/test_manifest.py` are a key regression gate when changing export or permission logic.
