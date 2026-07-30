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
.venv/bin/python -m pytest tests/ -q     # 97 tests
```

The correctness gate is `tests/fixtures.py` — a hand-built manifest where every component
is named for what it should classify as, asserted exactly in `tests/test_manifest.py`.
If you change reachability logic, that is the file that must stay green.
