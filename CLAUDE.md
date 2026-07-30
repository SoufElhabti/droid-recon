# droid-recon — operator & orchestrator guide

Android offensive-security audit engine. Static attack-surface mapping + dynamic IPC
probing against an emulator, with a triage gate that exists to stop you filing
non-findings.

`prompt.md` is the original vision document. **This file is the operational contract**;
where the two disagree, this one is right (see "Where the spec was wrong", below).

---

## The one rule that matters

> **The manifest establishes reachability. Probes only establish effect.**

`adb shell` runs as the shell UID and holds `START_ANY_ACTIVITY`. It can launch any
activity — exported or not — and query providers that no third-party app could touch.

So a probe that "succeeds" tells you *what happens*, never *who can make it happen*.
Every `Observation` and `Finding` carries `reachable_from`, computed from manifest facts
(`exported`, `permission`, `readPermission`, `protectionLevel`, BROWSABLE) and **never**
from a probe's exit code:

| `reachable_from` | Meaning | Can it be a finding? |
|---|---|---|
| `browser` | Exported + BROWSABLE — triggerable from a web page | **Yes**, highest value |
| `third_party_app` | Exported, no guard or a `normal`/`dangerous` guard | **Yes** |
| `shell` | Not exported. Only adb/root can reach it | **Never** |
| `none` | Exported but `signature`/`privileged` guarded | **Never** (without the signing key) |

**"Unexported activity launched via `adb shell am start`" is not a bug.** It works on
every Android device ever shipped. `triage` rejects it by construction, and there is a
regression test (`tests/test_triage.py::test_launching_an_unexported_activity_is_not_a_finding`)
that keeps it that way.

---

## Quick start

```bash
# one-time
uv venv --python 3.12 .venv && uv pip install -e ".[dev]"

# boot the emulator (~25s cold, headless, then adb root)
.venv/bin/droid-recon device up --avd webview_lab

# full pipeline on a target
.venv/bin/droid-recon audit /path/to/target.apk --screenshots --traversal

# or step by step
droid-recon static  target.apk          # manifest -> attack surface   (~1-3s, no device)
droid-recon code    target.apk          # jadx + sink sweep + provider paths (~15s/18MB)
droid-recon dynamic target.apk --type provider --traversal
droid-recon triage  com.target.app      # observations -> findings (3 gates)
droid-recon report  com.target.app      # bounded digest, markdown or json
```

Accepts a single `.apk` **or a directory holding a split set** (`base.apk` +
`config.*.apk`) — splits are detected and installed with `install-multiple`.

## Getting a target when you have none

The emulator's own system apps are real, multi-component targets with no download:

```bash
droid-recon device packages                       # what's installed
droid-recon device pull com.android.settings --out ./targets
droid-recon audit ./targets/SettingsGoogle.apk --no-install --type provider
```

---

## Orchestrator workflow (Claude Code driving this)

Every subcommand prints **JSON to stdout** and human progress to **stderr**, all top-N
bounded. There is no MCP server and no LLM inside this process — you are the orchestrator.

1. **`static`** first, always. It is 1-3 s and needs no device. Read `verdict`:
   - `SKIP — no exported components` → stop, record a dead end, move on.
   - `LOW — …all signature-guarded` → stop unless you have the signing key.
   - `INVESTIGATE — N third-party-reachable, …` → continue.
2. **`code`** to recover provider paths. This is what makes provider probing work at all:
   `dumpsys` gives you *authorities*, never *paths*, and `content query` on a bare
   authority errors out. `droid_recon/static/urimatcher.py` pulls
   `addURI("auth","notes",1)` literals out of the jadx tree. Verified working — it
   recovered `cards`, `BatteryUsageState`, `settings_manager/*` from Settings.
3. **`dynamic`** with `--type provider` first (providers return *data*, so they yield
   findings; activities mostly yield `Status: ok`, which is not evidence).
4. **`triage`** applies the three gates. Read `triage_candidates.json` too — `candidates`
   are things that passed reachability + effect but had no auto-derivable chain. **That
   file is your queue**; adjudicate those by hand.
5. **`report`** last. It is bounded to ~45 k chars; the raw data stays on disk behind the
   `artifacts` pointers. Read those only when the digest points you somewhere.

**Screenshots:** `--screenshots` writes PNGs to `sessions/<pkg>/screenshots/`. Read them
directly with the Read tool — that is the vision layer. No vision model or API key needed.

---

## The three triage gates

An observation becomes a finding only if **all three** hold:

1. **Reachability** — `reachable_from ∈ {third_party_app, browser}`. From the manifest.
2. **Effect** — `rows_returned` / `bytes_returned` / `crash`, or credential-shaped
   material in logcat. `Status: ok` alone is not an effect.
3. **Story** — a source → sink → chain can be stated. Mirrors the required fields in
   `android-privesc-hunt/prompts/findings-schema.json`; it is the best FP filter we have.

Pass 1+2 but not 3 → **candidate**, for you to adjudicate. Fail 1 or 2 → **rejected**,
with the reason recorded.

Two more precision rules, both learned from real output:

- **Dedup.** One misconfigured provider queried across six paths is *one* finding with
  six PoCs, not six findings.
- **Platform caveat.** A package under `sharedUserId=android.uid.system` is part of the
  OS and signed with the platform key; its exported surface is often *documented API*
  (`content://settings/{system,secure,global}` is world-readable by design). Such
  findings are still reported, but severity drops one notch, confidence halves, and the
  report carries an explicit ⚠️ warning. **Do not file an AOSP design decision as a bug.**

---

## Artifacts (`sessions/<package>/`)

| File | What it is |
|---|---|
| `attack_surface.json` | Every component, `exported`, `exported_source`, `reachable_from`, issues |
| `code_report.json` | Sink/source hits, `focused` view, recovered provider paths, storage scan |
| `observations.jsonl` | Append-only. Every probe. High recall, low precision. **Not findings.** |
| `findings.jsonl` | Append-only. Triage output only. |
| `triage_candidates.json` | Your manual queue + every rejection with its reason |
| `dead-ends.md` | Approaches that yielded nothing — so the next run doesn't repeat them |
| `state.json` | Resumable: phase, `steps_done`, counts. Re-run to continue. |
| `screenshots/`, `storage/`, `session.log` | Evidence |

---

## Frida (opt-in, fails soft)

```bash
droid-recon frida setup                                  # push + start matching frida-server
droid-recon frida run com.target.app --script ssl_unpin  # ssl_unpin | crypto_logger | webview_hooks
```

Everything here degrades to a warning + dead-end note rather than aborting the audit
(development rule 9). If frida-server won't start under SELinux, `setenforce 0` may be
required — **and if you do that, say so in the report**, because it changes the security
model of every result obtained afterwards.


---

## Using it from Claude Code / Codex (MCP)

droid-recon is an MCP stdio server exposing **29 tools**. Register it:

```jsonc
// Claude Code: .mcp.json   |   Codex: ~/.codex/config.toml equivalent
{ "mcpServers": {
    "droid-recon": {
      "command": "/Users/soufianeelhabti/andagent/.venv/bin/droid-recon",
      "args": ["mcp"]
    }}}
```

Transport is **newline-delimited JSON-RPC 2.0**, the MCP stdio standard — *not* LSP
`Content-Length` framing. (The prior-art server in `android-privesc-hunt/mcp/` uses LSP
framing and will not talk to an MCP client; do not copy it.)

Every tool returns a bounded summary plus an `artifact` path. Read the artifact only when
the summary points somewhere. Call `session_status` any time to see what has been done
and what to run next.

**Suggested autonomous loop:**

```
device_up -> static_analyze -> code_analyze
  -> probe_ipc -> exploit_campaign
  -> network_setup -> network_capture
  -> [native] list_native_libs -> native_trace(jni) -> ghidra_analyze
  -> [authed] app_authenticate -> explore_app -> network_capture again
  -> build_chains(verify=true) -> triage -> get_report
```

## Capability map

| Layer | Tools | What it establishes |
|---|---|---|
| Static | `static_analyze`, `code_analyze` | Who can reach what; sinks; **provider paths + call() methods from `UriMatcher.addURI`** |
| Native | `list_native_libs`, `native_trace`, `ghidra_analyze`, `ghidra_decompile` | JNI entry points (incl. dynamically-registered ones invisible to jadx), dangerous imports, embedded secrets |
| IPC | `probe_ipc`, `send_payload`, `exploit_campaign`, `provider_sqli` | Whether a crafted payload actually lands, verified by the oracle |
| Network | `network_setup`, `network_capture` | Decrypted HTTPS; cleartext, credentials in traffic, IDOR candidates |
| UI | `app_authenticate`, `explore_app`, `ui_state`, `tap`, `input_text` | Post-login features that no unauthenticated probe can reach |
| Synthesis | `build_chains`, `triage`, `get_report` | Cross-layer chains, re-verified by replay |

## The verification oracle

`am start` returns `Status: ok` for almost anything, so "the command ran" is not evidence.
Each payload declares an expectation up front; the oracle snapshots before/after and
compares across five sources — logcat, UI tree, process liveness, captured traffic, and a
per-payload **canary** string.

Verdicts: `confirmed` (our canary provably reached a sink, the canary host was fetched, or
an expected crash occurred) · `probable` (expected transition or string) · `none`.

Three rules that stop it lying:

1. **A platform denial beats every positive signal.** `Permission Denial` ends the story.
2. **The command's own echo is stripped before searching.** `am` prints
   `Starting: Intent {...}` and ActivityManager logs the launch — finding your canary
   there is your own string handed back, not app behaviour.
3. **An auth wall is not an auth bypass.** Landing on a gated activity that renders a
   login form is reported as *not* a bypass, however cleanly `am start` returned.

## Network interception on Android 14

`network_setup` does what the spec's approach cannot. The live trust store on API 34 is
`/apex/com.android.conscrypt/cacerts` (read-only ext4 from the conscrypt APEX); writing to
`/system/etc/security/cacerts` changes a directory nothing reads.

The working sequence, all verified on this device:

1. Copy the 134 existing certs to staging, mount a **tmpfs over the APEX cacerts dir**,
   restore them plus the mitmproxy CA.
2. Label everything `u:object_r:system_security_cacerts_file:s0`. **This is the step that
   silently breaks everything if wrong** — a fresh tmpfs gives files `appdomain_tmpfs`,
   and Conscrypt then ignores a certificate that is present, readable, and correctly
   hashed, failing with `CertPathValidatorException: Trust anchor ... not found`.
3. `nsenter` into **zygote's** mount namespace (and every running app's) and repeat,
   including the relabel. Apps do not share the shell's namespace; without this the store
   looks patched from `adb shell` and is unchanged for every app.

Measured: 135 certs, overlay active, 78 namespaces patched, and a real
`HttpsURLConnection` from inside an app decrypted end-to-end with zero handshake failures.

If a capture is empty, `interpretation` says which of the three preconditions failed
(proxy not reached / CA not trusted / certificate pinned) rather than reporting a bare zero.
`handshake_failures > 0` with zero flows means pinning — run
`frida_run(script="ssl_unpin")` first.

## Credentials

`app_authenticate` takes `--credentials <json>` or `DROID_RECON_USER`/`DROID_RECON_PASS`,
finds the login form by class/resource-id/hint, fills it, submits, and **verifies** we left
the login screen with no error text. Credential values are redacted from every artifact.

`explore_app` then crawls breadth-first with a structural signature per screen, skipping
destructive controls (logout, delete, purchase) by design.

## Extra keys come from code, not guesses

`code_analyze` mines `getStringExtra("EXTRA_URL")` / `getIntExtra(K, 0)` literals and
their constants out of the jadx tree (`static/intents.py`), per component, **with the
accessor type**. Payloads are then sent with the real key and the right `am` flag.

This is not a refinement — it is the difference between finding the bug and not. On
`ma.poneglyph.webviewlab`, `StockWebViewActivity` does
`webView.loadUrl(getIntent().getStringExtra(MainActivity.EXTRA_URL))`. The key is
literally `"EXTRA_URL"`; a generator guessing `url`/`link`/`target_url` sends seven
payloads, lands none, and reports a clean run against a direct injection sink. Same
lesson as provider paths.

## Known limits (v0.2) — measured, not assumed

- **The WebView positive control did not reproduce.** Sending the correct code-derived
  `EXTRA_URL` with a canary URL, with the emulator booted through `-http-proxy` and the
  CA installed, did not produce a captured canary request. Other traffic captured fine in
  the same session, so the plumbing works; the WebView path specifically is unverified.
  Treat `webview_url_injection` results as **untested** until this control passes — the
  oracle is trustworthy on crashes and providers, not yet proven on WebView sinks.
- **Android WebView ignores the runtime proxy setting.** `settings put global http_proxy`
  is honoured by ordinary HTTP stacks but not by WebView's Chromium network stack. Use
  `device up --http-proxy 10.0.2.2:8080` (boot-time) if you need WebView traffic. The
  emulator must be restarted for this to apply.
- Probes still run as the **shell UID**. `reachable_from` remains a manifest inference; an
  unprivileged attacker APK making the same calls is still the missing proof step.
- `explore_app` is heuristic. It will miss flows behind captchas, OTP, biometrics, or
  custom gesture UIs.
- `native_trace(exports)` needs the app running and its `.so` loaded; on a spawn use `jni`.
- Ghidra whole-library decompile is not exposed — only per-function, because it is slow.
- Chain verification replays adb PoCs only; traffic- and native-anchored chains are built
  but not re-verified automatically.


## False positives this oracle has already produced (and now blocks)

Every one of these was observed on a real run and is pinned by a regression test. They
are listed because the pattern generalises: **an automated exploit oracle's default
failure mode is confirming its own artefacts.**

| Observed | Cause | Fix |
|---|---|---|
| 14/14 payloads "CONFIRMED" | The intent URI's `;` was split by the *device* shell, `am` threw `No intent supplied`, and the exception echoed our canary back. | Quote every argument for the device shell (`shell._device_quote`); bail on `command_error` before looking for evidence. |
| 3/14 "probable" | `am start -n pkg/.Foo` moves focus to Foo every time; that was read as "the payload caused a transition". | Landing on the *requested* component is the null result — only a landing elsewhere counts (`landed_on_requested_component`). |
| Every probe "crashed" | Our own `uiautomator dump` threw `UiAutomationService ... already registered`. | Filter instrumentation crashes by stack **and** by `FATAL EXCEPTION:` thread name. |
| 3 "credential leak" findings | `errorCallbackToken=null` / `RemoteToken{...}` from WindowManager. | Whole-word key matching + value-shape checks + package attribution + framework-tag exclusion. |
| Canary "confirmed" from the tool's own echo | `am` prints `Starting: Intent {...}`; ActivityManager logs the launch. | Strip echo lines before searching for canaries. |

The honest current state on `ma.poneglyph.webviewlab` (13 exported activities, an
intentionally vulnerable WebView lab): **0 confirmed hits from 16 payloads.** That is the
correct answer for the payloads sent — not a claim the app is secure.

---

## Where the spec (`prompt.md`) was wrong

Verified against this machine; these are the deliberate deviations:

| `prompt.md` | Reality |
|---|---|
| Built on `mobilerun` (:7) | Its PostHog telemetry is **on by default and ships the raw goal string** (which contains the target package). Also hard-depends on arize-phoenix + a SaaS SDK, pins `llama-index==0.14.23`, requires Python <3.14, and auto-downloads a proprietary Portal APK onto the device under test. Dropped entirely. |
| `extra_tools_module` (:188) | **Does not exist.** The delivery mechanism for the whole 18-row tool table (:141-164) is fiction. Custom tools are Python-API-only. |
| Opus/Kimi orchestration (:172-186, :429-438) | No LLM API key exists on this machine, and those model IDs aren't valid. Claude Code is the orchestrator; this process has no LLM in it. |
| "Unexported activity via root `am start`" as the flagship finding (:248, :259) | Not a finding. Shell holds `START_ANY_ACTIVITY` on every device. |
| Cert into `/system/etc/security/cacerts` + reboot (:119-131) | **Broken on API 34** — the store moved to the read-only conscrypt APEX. mitmproxy isn't installed either. Deferred. |
| Emulator snapshots (:163, :402-409) | `-writable-system` copies are destroyed at emulator exit and frida's `adb forward` goes stale across load. `uninstall` + `install -g -r` + `pm clear` gets 90% of it in ~2 s. |
| `logcat -d --pid=$(pidof pkg)` (:154) | The pid is gone after a crash — exactly when the log matters. We clear the buffer, probe, then dump and filter by text. |
| Ghidra `analyzeHeadless` (:464-468) | Not on PATH (GUI-only install). Deferred. |
| Flat `droid_recon/` package (:508) | `src/` layout + hatchling, matching the operator's convention. |
| Finding schema (:240-261) | Weaker than `android-privesc-hunt/prompts/findings-schema.json` — it has no source/sink/chain requirement. We use the stronger one, plus `reachable_from`. |

## Measured on this machine

| | |
|---|---|
| `static` on an 18 MB APK | **2.7 s** (`apkanalyzer manifest print` is 0.73 s; jadx is not needed) |
| `code` (jadx) on 18 MB / 9891 classes | **15 s** — cached by APK sha256; exit code 3 = *partial*, which is normal and usable |
| Emulator cold boot, headless | **~23 s** to `sys.boot_completed`, then `adb root` succeeds (userdebug image) |
| AVD | `webview_lab` — pixel_7, android-34, `google_apis`, arm64, SELinux **Enforcing** |

## Conventions

Zero third-party runtime dependencies. `from __future__ import annotations`; dataclasses
with explicit `to_dict`/`from_dict` (no pydantic); argparse (no click); bracket-tag prints
(no `logging`). **Every subprocess call must pass a timeout** — macOS has no `timeout`
binary and `adb shell` against a wedged device blocks forever.

```bash
.venv/bin/python -m pytest tests/ -q     # 143 tests
```

The correctness gate is `tests/fixtures.py` — a hand-built manifest where every component
is named for what it should classify as, asserted exactly in `tests/test_manifest.py`.
If you change reachability logic, that is the file that must stay green.
