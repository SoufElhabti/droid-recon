# CLAUDE.md — Android Offensive Security Agent (macOS)

## Project Identity

**Codename**: `droid-recon`
**Purpose**: An AI-native Android emulator agent for offensive security research on macOS. The agent autonomously installs, explores, instruments, and audits Android APKs — finding vulnerabilities through dynamic interaction, runtime instrumentation, and static analysis cross-referencing.
**Foundation**: Built on top of [Mobilerun](https://github.com/droidrun/mobilerun) (MIT, Python 3.11+), the open-source LLM-driven mobile automation framework.
**License target**: Proprietary (Poneglyph SARL). Mobilerun MIT base stays attributed.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR LAYER                     │
│              Claude Opus (reasoning/decision)             │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Goal Planner│  │ Skeptic/     │  │ Finding        │  │
│  │ (decomposes │  │ Validator    │  │ Classifier     │  │
│  │ audit tasks)│  │ (challenges  │  │ (severity,     │  │
│  │             │  │  findings)   │  │  dedup, triage)│  │
│  └─────────────┘  └──────────────┘  └────────────────┘  │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│                   EXECUTOR LAYER                          │
│           Kimi K2 / Claude Sonnet (high-volume)           │
│  ┌───────────────┐  ┌─────────────┐  ┌───────────────┐  │
│  │ UI Explorer   │  │ Frida       │  │ Network       │  │
│  │ (navigate,    │  │ Injector    │  │ Inspector     │  │
│  │  screenshot,  │  │ (hook,      │  │ (mitmproxy,   │  │
│  │  interact)    │  │  trace,     │  │  cert pin     │  │
│  │              │  │  bypass)    │  │  bypass)      │  │
│  └───────────────┘  └─────────────┘  └───────────────┘  │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│                  DEVICE CONTROL LAYER                     │
│             Mobilerun + Custom ADB Extensions             │
│  ┌──────────────┐  ┌────────────┐  ┌─────────────────┐  │
│  │ Mobilerun    │  │ ADB Bridge │  │ Emulator        │  │
│  │ Agent Runtime│  │ (extended  │  │ Manager         │  │
│  │ (UI tree,    │  │  security  │  │ (AVD lifecycle, │  │
│  │  vision,     │  │  commands) │  │  snapshot,      │  │
│  │  gestures)   │  │            │  │  restore)       │  │
│  └──────────────┘  └────────────┘  └─────────────────┘  │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│                  ANDROID RUNTIME                          │
│        AVD ARM64 (userdebug, API 34, rooted)             │
│  ┌──────────────┐  ┌────────────┐  ┌─────────────────┐  │
│  │ Target APK   │  │ frida-     │  │ mitmproxy       │  │
│  │              │  │ server     │  │ cert installed   │  │
│  │              │  │ (listening)│  │ (system store)  │  │
│  └──────────────┘  └────────────┘  └─────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

---

## Phase 0 — Environment Bootstrap (macOS)

### Prerequisites

```bash
# Core tools
brew install --cask android-commandlinetools   # or full Android Studio
brew install python@3.12 uv node              # runtime
brew install mitmproxy                         # TLS interception
pip install frida-tools objection --break-system-packages

# Mobilerun
uv tool install mobilerun
# With Anthropic support:
uv tool install 'mobilerun[anthropic]'
```

### AVD Setup (Apple Silicon, ARM64 native)

```bash
# Accept licenses
sdkmanager --licenses

# Install ARM64 system image (userdebug for root)
sdkmanager "system-images;android-34;google_apis;arm64-v8a"
sdkmanager "platform-tools" "emulator" "platforms;android-34"

# Create AVD
avdmanager create avd \
  -n droid-recon \
  -k "system-images;android-34;google_apis;arm64-v8a" \
  -d pixel_7

# Launch (headless for CI, windowed for dev)
emulator -avd droid-recon -no-audio -gpu swiftshader_indirect &

# Verify ADB
adb wait-for-device
adb root   # requires userdebug/eng build
```

### Frida Server on Emulator

```bash
# Get frida-server matching your frida-tools version
FRIDA_VERSION=$(frida --version)
ARCH=android-arm64
curl -LO "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-${ARCH}.xz"
xz -d frida-server-*.xz
adb push frida-server-* /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &"
```

### mitmproxy Certificate Injection (System Store)

```bash
# Generate and push cert for TLS interception
mitmproxy  # first run generates ~/.mitmproxy/mitmproxy-ca-cert.cer
CERT_HASH=$(openssl x509 -inform PEM -subject_hash_old \
  -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem "${CERT_HASH}.0"

adb root
adb remount
adb push "${CERT_HASH}.0" /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${CERT_HASH}.0
adb reboot
```

---

## Phase 1 — Mobilerun Integration & Custom Tool Extensions

### 1.1 Extend Mobilerun with Security Tools

Mobilerun's architecture is tool-based — it exposes tools to the LLM agent that map to device actions. We extend this with offensive security tools.

**File**: `droid_recon/tools/security_tools.py`

Create custom Mobilerun-compatible tools for:

| Tool Name | Description | ADB/Frida Command |
|---|---|---|
| `install_apk` | Install target APK, grant all permissions | `adb install -g -r <path>` |
| `list_activities` | Enumerate all exported/unexported activities | `adb shell dumpsys package <pkg> \| grep Activity` |
| `list_content_providers` | Enumerate content providers + URIs | `adb shell dumpsys package <pkg> \| grep provider` |
| `query_provider` | Query a content provider URI | `adb shell content query --uri content://<uri>` |
| `launch_deeplink` | Fire an intent with arbitrary deep link | `adb shell am start -a android.intent.action.VIEW -d <uri>` |
| `launch_activity` | Start any activity (incl. unexported via root) | `adb shell am start -n <pkg>/<activity>` |
| `broadcast_intent` | Send a broadcast with arbitrary extras | `adb shell am broadcast -a <action> --es key val` |
| `dump_logcat` | Capture logcat filtered by package (last N lines) | `adb shell logcat -d --pid=$(pidof <pkg>) \| tail -n <N>` |
| `frida_hook` | Inject a Frida script and return output | `frida -U -f <pkg> -l <script.js> --no-pause` |
| `frida_trace` | Trace method calls matching a pattern | `frida-trace -U -f <pkg> -j '<class>.<method>'` |
| `objection_explore` | Run objection command (SSL pinning bypass, etc.) | `objection -g <pkg> explore -c "<command>"` |
| `capture_traffic` | Start/stop mitmproxy capture, return HAR | mitmdump session management |
| `take_heap_dump` | Dump process memory for analysis | `adb shell am dumpheap <pid> /data/local/tmp/heap.hprof` |
| `check_permissions` | List runtime permissions and protection levels | `adb shell dumpsys package <pkg> \| grep permission` |
| `read_shared_prefs` | Read SharedPreferences XML files (root) | `adb shell cat /data/data/<pkg>/shared_prefs/*.xml` |
| `read_databases` | Pull SQLite databases for analysis | `adb pull /data/data/<pkg>/databases/` |
| `snapshot_save` | Save emulator snapshot (clean state) | `adb emu avd snapshot save <name>` |
| `snapshot_load` | Restore emulator to clean state | `adb emu avd snapshot load <name>` |

### 1.2 Mobilerun Agent Configuration

```python
# droid_recon/agent_config.py

MOBILERUN_CONFIG = {
    # Orchestrator — Claude Opus for reasoning, planning, finding validation
    "orchestrator_model": "claude-opus-4-6",
    "orchestrator_provider": "anthropic",

    # Executor — Kimi K2 for high-volume enumeration, repetitive tasks
    # Falls back to Claude Sonnet for tasks needing Anthropic tool use
    "executor_model": "kimi-k2",
    "executor_fallback": "claude-sonnet-4-6",

    # Mobilerun reasoning mode ON — manager-executor pattern
    "reasoning": True,

    # Vision mode ON — screenshot analysis for UI understanding
    "vision": True,

    # Custom tools registered
    "extra_tools_module": "droid_recon.tools.security_tools",
}
```

### 1.3 App Cards (Mobilerun Feature)

Mobilerun supports "App Cards" — app-specific guidance files that tell the agent how to navigate a particular app. For security research, create generic cards:

**File**: `app_cards/generic_audit.yaml`

```yaml
name: "Generic APK Security Audit"
package: "*"  # applies to any target
guidance: |
  You are performing a security audit of this Android application.
  Your goals in priority order:
  1. Map the attack surface: activities, services, content providers, broadcast receivers
  2. Identify exported components and test them for unauthorized access
  3. Check for hardcoded secrets in SharedPreferences, databases, and logcat
  4. Test deep links and intent handlers for injection/bypass
  5. Intercept network traffic and look for: plaintext credentials, API keys,
     broken TLS pinning, sensitive data in URLs
  6. Use Frida to hook authentication/authorization methods and test bypass
  7. Check file permissions and world-readable storage
  8. Test for WebView vulnerabilities (JS injection, file:// access)

  After each finding, classify severity (Critical/High/Medium/Low/Info) and
  write to findings.jsonl before continuing.
```

---

## Phase 2 — Autonomous Audit Loop

### 2.1 Audit Session Contract

Each audit session operates as a self-contained research loop with the following contract:

**Inputs**:
- `target.apk` — the APK file to audit
- `scope.md` — optional scope constraints (e.g., "focus on authentication flows only")
- `prior_findings.jsonl` — optional prior findings to avoid duplicating work

**Outputs** (mandatory, written continuously):
- `findings.jsonl` — one JSON object per finding (schema below)
- `dead-ends.md` — approaches attempted that yielded nothing (prevent loops)
- `session.log` — full tee'd log of all commands and agent reasoning
- `traffic_capture.har` — network traffic capture (if applicable)
- `screenshots/` — timestamped screenshots at key decision points

**Finding Schema** (`findings.jsonl`):

```json
{
  "id": "DROID-001",
  "timestamp": "2026-07-30T14:23:00Z",
  "severity": "High",
  "category": "exported-activity-bypass",
  "title": "Unexported admin activity accessible via root am start",
  "component": "com.target.app/.AdminPanelActivity",
  "reproduction": [
    "adb shell am start -n com.target.app/.AdminPanelActivity"
  ],
  "impact": "Bypasses authentication gate, grants access to admin panel",
  "evidence": {
    "screenshot": "screenshots/2026-07-30_142300_admin_panel.png",
    "logcat_snippet": "...",
    "frida_output": null
  },
  "confidence": "confirmed",
  "cwe": "CWE-926",
  "notes": "Activity is not exported in manifest but accessible on rooted device. Real-world impact depends on device root status."
}
```

### 2.2 Audit Phases (Agent Workflow)

The orchestrator (Claude Opus) drives the following phases. Each phase produces findings and dead-ends before proceeding.

#### Phase A: Static Recon (Pre-Install)
```
1. jadx decompile APK → extract manifest, source (if not obfuscated)
2. Parse AndroidManifest.xml:
   - All components (activities, services, receivers, providers)
   - Exported vs unexported
   - Intent filters and deep link schemes
   - Permissions declared and used
   - android:debuggable, android:allowBackup, android:networkSecurityConfig
3. Grep for hardcoded:
   - API keys, tokens, secrets (regex patterns)
   - Firebase URLs, AWS credentials
   - Embedded certificates/private keys
4. Identify native libraries (.so files) → flag for deeper analysis
5. Output: attack_surface.json summarizing all components and entry points
```

#### Phase B: Dynamic Surface Mapping (Post-Install)
```
1. snapshot_save "clean" — baseline state
2. install_apk with all permissions granted
3. Launch main activity, take screenshot, dump UI tree
4. Systematically navigate: tap every visible element, explore every screen
   - Use Mobilerun's UI tree + vision to understand app structure
   - Build app_map.json: screen → elements → transitions
5. For each activity from manifest:
   - launch_activity directly
   - Record if it's accessible without authentication
   - Screenshot + classify
6. For each content provider:
   - query_provider with common URIs
   - Test path traversal: content://authority/../../../etc/passwd
7. For each deep link scheme:
   - launch_deeplink with crafted URIs
   - Test for open redirect, injection, auth bypass
8. dump_logcat — check for sensitive data leakage
```

#### Phase C: Runtime Instrumentation
```
1. SSL pinning bypass:
   - objection_explore "android sslpinning disable"
   - Start mitmproxy capture
2. Authentication hooks:
   - frida_hook: intercept login/auth methods
   - Test: can we bypass auth by returning true?
   - Test: can we escalate privileges by modifying role checks?
3. Crypto analysis:
   - frida_hook: intercept javax.crypto.* calls
   - Log encryption keys, algorithms, IVs
   - Check for ECB mode, hardcoded keys, weak algorithms
4. Storage analysis:
   - read_shared_prefs — check for tokens, credentials in plaintext
   - read_databases — check for sensitive data, SQL injection in queries
   - Check /sdcard/ for world-readable files created by the app
5. WebView audit (if applicable):
   - frida_hook WebView.loadUrl, evaluateJavascript
   - Test for JS bridge exposure, file:// protocol access
   - Test for XSS in WebView content
```

#### Phase D: Network Analysis
```
1. With mitmproxy running and SSL pinning bypassed:
   - Exercise all app functionality (login, browse, transact)
   - Capture all API calls
2. Analyze traffic:
   - Authentication tokens: how generated, where stored, rotation policy?
   - Authorization: IDOR tests (change user IDs in requests)
   - Sensitive data: PII in URLs/query params? Unencrypted payloads?
   - API versioning: old endpoints still accessible?
   - Rate limiting: absent on sensitive endpoints?
3. Replay attacks: capture auth token, use in raw curl after logout
```

#### Phase E: Finding Validation & Report
```
1. Skeptic pass: Claude Opus re-reads each finding and challenges it
   - Is this actually exploitable in a real-world scenario?
   - What's the realistic attack chain?
   - Is this a duplicate or variant of another finding?
2. Severity calibration per CVSS 3.1
3. Generate final report: findings.jsonl + executive summary
4. snapshot_load "clean" — restore emulator to baseline
```

---

## Phase 3 — Session Management & Persistence

### 3.1 State Persistence (Long-Running Sessions)

Adopt the same pattern as cloud IAM research loops:

```json
// state.json — persisted after each agent action
{
  "session_id": "audit-com.target.app-20260730",
  "target_package": "com.target.app",
  "current_phase": "B",
  "current_step": "B.4",
  "screens_visited": ["MainActivity", "LoginActivity", "SettingsActivity"],
  "activities_tested": 12,
  "activities_total": 23,
  "providers_tested": 3,
  "providers_total": 5,
  "findings_count": 4,
  "dead_ends_count": 7,
  "last_screenshot": "screenshots/2026-07-30_143200.png",
  "last_ui_tree_hash": "a3f4b2...",
  "rate_limit_hits": 0,
  "total_llm_tokens": 45230,
  "elapsed_seconds": 1847
}
```

### 3.2 Rate Limit Handling

```bash
# Same pattern as cloud research: detect, sleep, retry
MAX_RETRIES=5
RETRY_DELAY=60

for attempt in $(seq 1 $MAX_RETRIES); do
  result=$(run_agent_step)
  if echo "$result" | grep -q "rate_limit\|429\|overloaded"; then
    echo "[$(date)] Rate limited, sleeping ${RETRY_DELAY}s (attempt $attempt/$MAX_RETRIES)"
    sleep $RETRY_DELAY
    RETRY_DELAY=$((RETRY_DELAY * 2))
  else
    break
  fi
done
```

### 3.3 Emulator Snapshot Strategy

- **"clean"** — fresh install, no target APK, baseline state
- **"installed"** — target APK installed, permissions granted, before first launch
- **"authenticated"** — logged into the app (if test credentials available)
- **"post-recon"** — after Phase B completes, before instrumentation

Snapshots allow restarting from any phase without re-doing prior work.

---

## Phase 4 — Model Routing

### Decision Matrix

| Task Type | Model | Rationale |
|---|---|---|
| Audit planning, phase transitions | Claude Opus | Complex reasoning about attack surface |
| Finding validation, severity triage | Claude Opus | Needs skeptical adversarial reasoning |
| UI navigation, screen-by-screen exploration | Kimi K2 / Sonnet | High-volume, repetitive, fast |
| Frida script generation | Claude Opus | Needs deep knowledge of Android internals |
| Screenshot analysis (what's on screen?) | Claude Sonnet (vision) | Fast, good enough for UI recognition |
| Logcat/traffic pattern analysis | Kimi K2 | Large context window for log analysis |
| Report generation | Claude Opus | Quality writing, proper severity language |

### Routing Implementation

```python
def route_to_model(task_type: str) -> str:
    OPUS_TASKS = {
        "plan", "validate", "triage", "frida_script",
        "report", "severity", "exploit_chain"
    }
    if task_type in OPUS_TASKS:
        return "claude-opus-4-6"
    return "kimi-k2"  # default to high-volume executor
```

---

## Phase 5 — Integration with Existing Toolchain

### 5.1 jadx Integration (Static Analysis Pre-Flight)

Before the agent touches the emulator, run jadx to decompile and extract:

```bash
jadx --deobf --export-gradle \
  --output-dir /tmp/jadx_output \
  target.apk

# Feed manifest and key files to orchestrator for attack surface planning
cat /tmp/jadx_output/AndroidManifest.xml | \
  python -c "import sys; from droid_recon.parsers import parse_manifest; \
  parse_manifest(sys.stdin.read())" > attack_surface.json
```

### 5.2 Ghidra Integration (Native Library Analysis)

For APKs with native .so libraries:

```bash
# Headless Ghidra analysis
analyzeHeadless /tmp/ghidra_project project_name \
  -import /tmp/jadx_output/lib/arm64-v8a/*.so \
  -postScript ExportFunctions.java \
  -scriptPath /path/to/scripts
```

### 5.3 Output Compatibility

All outputs follow the same schema as cloud IAM research:
- `findings.jsonl` — append-only, one finding per line
- `dead-ends.md` — markdown list of failed approaches with reasoning
- `session.log` — full tee'd output of everything
- `state.json` — resumable state for long-running sessions

---

## Non-Functional Requirements

### Performance
- Agent loop cycle time target: < 5 seconds per action (screenshot + reason + act)
- Full APK audit target: 30-60 minutes for a medium-complexity app
- Emulator boot to ready: < 30 seconds from snapshot

### Reliability
- Agent must handle: app crashes, ANR dialogs, permission prompts, system dialogs
- Auto-dismiss system dialogs that block progress
- Detect and break infinite navigation loops (visited-screen tracking)
- Graceful degradation if Frida/mitmproxy fail — continue with available tools

### Security
- All research runs in emulator isolation — never on host
- No target app network traffic touches production systems
- API keys (Anthropic, Kimi) in environment variables, never in code
- Emulator network sandboxed to mitmproxy for full capture

---

## Directory Structure

```
droid-recon/
├── CLAUDE.md                    # This file
├── pyproject.toml               # uv/pip project config
├── droid_recon/
│   ├── __init__.py
│   ├── main.py                  # CLI entry point
│   ├── orchestrator.py          # Opus-driven audit planner
│   ├── executor.py              # Kimi/Sonnet action executor
│   ├── model_router.py          # Task → model routing
│   ├── emulator_manager.py      # AVD lifecycle, snapshots
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── security_tools.py    # Custom Mobilerun tools (table above)
│   │   ├── frida_tools.py       # Frida script injection/tracing
│   │   ├── network_tools.py     # mitmproxy integration
│   │   └── static_tools.py      # jadx/Ghidra wrappers
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── manifest_parser.py   # AndroidManifest.xml → attack_surface.json
│   │   ├── logcat_parser.py     # Logcat → structured findings
│   │   └── traffic_parser.py    # HAR → analyzed endpoints
│   ├── schemas/
│   │   ├── finding.py           # Finding dataclass/pydantic model
│   │   ├── state.py             # Session state model
│   │   └── attack_surface.py    # Attack surface model
│   └── app_cards/
│       ├── generic_audit.yaml
│       └── webview_audit.yaml
├── scripts/
│   ├── bootstrap_emulator.sh    # Phase 0 automation
│   ├── install_frida.sh         # Frida server setup
│   └── inject_mitm_cert.sh      # mitmproxy cert injection
├── frida_scripts/
│   ├── ssl_pinning_bypass.js
│   ├── auth_bypass.js
│   ├── crypto_logger.js
│   └── webview_hooks.js
├── sessions/                    # Per-target audit sessions
│   └── com.target.app/
│       ├── state.json
│       ├── findings.jsonl
│       ├── dead-ends.md
│       ├── session.log
│       ├── attack_surface.json
│       └── screenshots/
└── tests/
    ├── test_tools.py
    ├── test_manifest_parser.py
    └── test_finding_schema.py
```

---

## Quick Start (After Bootstrap)

```bash
# 1. Bootstrap emulator (one-time)
./scripts/bootstrap_emulator.sh

# 2. Run audit on a target APK
python -m droid_recon.main \
  --target ./targets/com.target.app.apk \
  --scope "full" \
  --orchestrator-model claude-opus-4-6 \
  --executor-model kimi-k2 \
  --output-dir ./sessions/com.target.app/ \
  --resume  # picks up from state.json if exists

# 3. Quick single-task mode (use Mobilerun CLI directly)
mobilerun run "Install the APK at /tmp/target.apk and explore all screens" \
  --vision --reasoning
```

---

## Development Rules

1. **Every tool must be idempotent** — running a tool twice with the same input must not corrupt state
2. **Every agent action must be logged** — append to session.log before executing
3. **Findings are append-only** — never edit findings.jsonl, only append new lines
4. **Dead-ends are valuable** — every failed approach gets documented with reasoning
5. **Screenshots at decision points** — before and after every significant state change
6. **State persistence after every step** — state.json updated after each action completes
7. **Emulator is disposable** — assume it can be restored from snapshot at any time
8. **No hardcoded paths** — everything configurable via env vars or CLI args
9. **Fail open on non-critical tools** — if Frida fails, continue without it; if mitmproxy fails, note it and continue
10. **Rate limit awareness** — detect 429s from LLM APIs and back off with exponential delay
