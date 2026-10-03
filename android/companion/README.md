# Ordinary-app reachability companion

This small Android app makes IPC calls from its own application UID. It requests no
Android permissions and contains no network code. Use it on an Android emulator with
an app you are authorized to test. The shell UID only launches the companion and
reads its result log; the target call runs inside the companion process.

## Build and install

Install JDK 17 or newer, Android SDK platform 36 and build tools. Gradle 8.9 or newer
is optional. Set `ANDROID_HOME` or `ANDROID_SDK_ROOT`, then use the Python builder:

```python
from droid_recon.device import ordinary

build = ordinary.build_companion()
print(build.status, build.apk, build.message)
```

When Gradle is unavailable, this uses `aapt2`, `javac`, D8, `zipalign`, and
`apksigner` from the local SDK/JDK, entirely offline. Intermediate files and the
signed APK are written under the workspace's `work/companion-build` directory for
source checkouts, or a writable temporary directory for installed packages.
Alternatively, build from this directory with Gradle:

```sh
gradle :app:assembleDebug
adb -s emulator-5554 install -r app/build/outputs/apk/debug/app-debug.apk
```

The Python API can also install the APK:

```python
from droid_recon.device import ordinary

if build.status == "built":
    installed = ordinary.install_companion(build.apk, serial="emulator-5554")
```

The project deliberately has no checked-in Gradle wrapper binary. The SDK build path
has been verified locally. A live run needs an Android emulator, which was unavailable
in this repository's test environment.

## Probe protocol

`ordinary.run_probe(ProbeRequest(...), serial="emulator-5554")` starts
`org.droidrecon.companion/.ProbeActivity` with a base64url JSON payload and reads a
nonce-matched `DroidReconCompanion` logcat result. Each call has a 12-second in-app
deadline and a configurable host deadline. The Python wrapper refuses physical
devices by checking `ro.kernel.qemu`.

Supported operations:

| Operation | Call made by companion | Evidence meaning |
|---|---|---|
| `activity` | Explicit `startActivity` | Android accepted or denied the launch; no target effect is inferred. |
| `deeplink` | Package-scoped `ACTION_VIEW` | Android resolved and accepted the link, or rejected it. |
| `service` | Explicit `startService` | Android returned a component or an error. |
| `broadcast` | Explicit `sendBroadcast` | The call was dispatched; receiver delivery is **unconfirmed**. |
| `provider_query` | Read-only `ContentResolver.query` | Query returned a cursor, denied access, or failed. Only row presence and column count are logged. |
| `provider_call` | `ContentResolver.call(authority, method, null, null)` | An explicitly named method was accepted or denied. Only whether a Bundle was returned is logged. |

`accepted_by_os` and `queried` establish ordinary-app access in that tested
environment. They are reachability observations, not vulnerability findings.
`dispatched_unconfirmed`, a null cursor, timeouts, missing results, and platform
background-service blocks remain inconclusive. The companion never reads provider
row values or performs provider insert, update, or delete operations. A target-defined
`provider_call` method may have side effects, so this operation must be requested
explicitly with a method recovered during analysis; the default provider probe is
`provider_query`.

The result includes `caller_uid` and `caller_package`. The Python wrapper marks an
ordinary UID as observed only when the package matches this companion, the UID is
in Android's application range, and the APK is a known source build or an exact
allowlisted release APK. `install_companion` rejects APKs with a different package,
requested permissions, or a shared user ID. A custom prebuilt APK with a safe manifest
can run but yields inconclusive caller evidence because its code could fabricate result
logs. Pass `trusted_source=installed.verified_build` to `run_probe`; a fresh bundled
build and installation provides that verification.
