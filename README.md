# droid-recon

Android offensive-security audit engine for macOS. Maps an APK's attack surface from its
manifest and code, probes the live IPC surface on an emulator, and applies a triage gate
designed to stop you filing non-findings.

Zero third-party runtime dependencies. No LLM, no API key, no telemetry.

```bash
uv venv --python 3.12 .venv && uv pip install -e ".[dev]"
.venv/bin/droid-recon device up --avd webview_lab
.venv/bin/droid-recon audit /path/to/target.apk --screenshots --traversal
```

**Read [CLAUDE.md](CLAUDE.md)** — it is the operational contract: the reachability rule
that everything depends on, the three triage gates, the artifact layout, and the places
where the original spec (`prompt.md`) was wrong.

The one thing to know before using this:

> The manifest establishes reachability. Probes only establish effect.

`adb shell` holds `START_ANY_ACTIVITY` and runs as the shell UID, so it can trigger
components no real attacker could reach. Every observation's `reachable_from` is computed
from manifest facts, never from a probe's exit code.
