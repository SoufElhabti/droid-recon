# droid-recon

Android APK attack-surface analysis and evidence-led testing for applications you are authorized to assess. The tool maps exported components and deep links, examines decompiled code, and can probe an emulator or attached device. Static candidates, shell observations, ordinary-app reachability checks, and confirmed findings are kept distinct.

The Python package requires Python 3.11+ and has no third-party runtime dependencies. Android SDK tools and other external programs are needed for particular stages; run `doctor` to see what is available on your host.

## Quick start

From this checkout:

```text
python -m pip install -e ".[dev]"
droid-recon doctor
droid-recon static /path/to/app.apk
droid-recon code /path/to/app.apk
```

On Windows, `py -3.11 -m pip install -e ".[dev]"` can select the required Python version. Use an APK file or a directory containing a base APK and its split APKs. The first two analysis commands do not require a device. `code` needs JADX; manifest analysis needs Android SDK manifest tooling.

With an authorized emulator or attached device:

```text
droid-recon audit /path/to/app.apk --deep --screenshots
droid-recon report com.example.app
```

`audit` runs static and code analysis, IPC probes, triage, and reporting. `--deep` adds targeted payloads, a companion app running under an ordinary UID, UI exploration, and chain building. Network interception and native analysis remain explicit commands. If no device is available, `audit` reports the static work and marks the device-dependent work as incomplete. This snapshot passed a live smoke audit of a developer-owned synthetic APK on an Android 14/API 34 emulator; behavior on other apps and devices remains unverified.

## What this version adds

- Base and split APK handling, including provenance for components from feature splits.
- Code-derived Intent extra names, types, observed literal defaults, source locations, nearby validation evidence, and conservative source-to-sink candidates for exported components.
- An ordinary UID companion app to check whether another app can actually reach a component. Ambiguous launches and broadcasts remain inconclusive. The wheel includes buildable companion source; the separately supplied release APK is recognized by its exact SHA-256.
- Provider discovery that reports read, write, and `call()` reachability separately, plus an evidence manifest with APK hashes, signing fingerprint when tooling is present, app/device/WebView context, and recorded execution context.
- A coverage ledger with tested, skipped, unsupported, and failed checks, plus explicit evidence states and OWASP reference mappings.
- `diff` for release-to-release surface changes, `audit --resume` for matching interrupted runs, and `doctor` for host capabilities.
- Optional DeepSeek or loopback OpenAI-compatible agent with bounded, redacted model input and a preview of outbound context. The MCP server exposes only read-only tools until the operator explicitly enables device-changing tools.

See the [usage guide](GUIDE.md) for commands and report interpretation, [development snapshot notes](docs/release-notes.md) for the change list and validation limits, and the [OWASP mapping catalog](docs/standards-mapping.md) for check references. [CLAUDE.md](CLAUDE.md) describes the original reachability and triage rules.

## Evidence rule

An exported manifest entry is a possible entry point; `adb shell` success does not prove an ordinary app can use it. A flow candidate is a review lead, not a vulnerability. Check `report.md` and the linked artifacts for the observed effect, caller context, Android version, and any missing checks before drawing a conclusion.

The included [WebView lab report](docs/example-report-webviewlab.md) is a historical sample from an earlier, developer-owned lab run. Its device evidence was not reproduced as part of this development snapshot.
