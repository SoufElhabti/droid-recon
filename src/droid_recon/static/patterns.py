"""Source / sink / server regex tables for the decompiled-code sweep.

Ported verbatim from android-privesc-hunt/scripts/pre-analyze.sh:199-234, then extended.
These encode the attack classes in the operator's own methodology (intent redirection,
Dirty Stream, PendingIntent hijack, WebView file:// access, dynamic code loading).
"""

from __future__ import annotations

import re

# (pattern, label). A SINK is where attacker-controlled data lands dangerously.
SINKS: list[tuple[str, str]] = [
    (r"\.loadUrl\s*\(", "WebView.loadUrl"),
    (r"\.evaluateJavascript\s*\(", "WebView.evaluateJavascript"),
    (r"\.loadDataWithBaseURL\s*\(", "WebView.loadDataWithBaseURL"),
    (r"Intent\.parseUri\s*\(", "Intent.parseUri"),
    (r"startActivit(y|ies)\s*\(.*getParcelableExtra", "startActivity(getParcelableExtra) — intent redirect"),
    (r"setResult\s*\(.*getIntent\s*\(\)", "setResult(getIntent()) — echo bug"),
    (r"openInputStream\s*\(", "ContentResolver.openInputStream"),
    (r"openFileDescriptor\s*\(", "ContentResolver.openFileDescriptor"),
    (r"getLastPathSegment\s*\(", "Uri.getLastPathSegment (decode risk)"),
    (r"Runtime\.getRuntime\(\)\.exec\s*\(", "Runtime.exec — command injection"),
    (r"ProcessBuilder\s*\(", "ProcessBuilder"),
    (r"DexClassLoader\s*\(", "DexClassLoader — dynamic code"),
    (r"PathClassLoader\s*\(", "PathClassLoader — dynamic code"),
    (r"System\.load(Library)?\s*\(", "System.load/loadLibrary"),
    (r"Class\.forName\s*\(", "Class.forName — reflection"),
    (r"PendingIntent\.(getActivity|getBroadcast|getService|getForegroundService)\s*\(", "PendingIntent creation"),
    (r"\.send\s*\(.*PendingIntent", "PendingIntent.send"),
    (r"addJavascriptInterface\s*\(", "WebView.addJavascriptInterface"),
    (r"setAllowFileAccessFromFileURLs\s*\(\s*true", "setAllowFileAccessFromFileURLs(true)"),
    (r"setAllowUniversalAccessFromFileURLs\s*\(\s*true", "setAllowUniversalAccessFromFileURLs(true)"),
    (r"setWebContentsDebuggingEnabled\s*\(\s*true", "setWebContentsDebuggingEnabled(true)"),
    (r"SplitInstallManager|SplitCompat", "SplitInstallManager/SplitCompat"),
    (r"DISPLAY_NAME|OpenableColumns", "DISPLAY_NAME usage (Dirty Stream signal)"),
    # --- extensions beyond the original table ---
    (r"rawQuery\s*\(|execSQL\s*\(", "raw SQL — injection surface"),
    (r"MODE_WORLD_(READ|WRITE)ABLE", "MODE_WORLD_* file mode"),
    (r"setJavaScriptEnabled\s*\(\s*true", "WebView JavaScript enabled"),
    (r"\.setData\s*\(.*getIntent\s*\(\)", "setData(getIntent()) — intent reuse"),
    (r"checkCallingOrSelfPermission|checkCallingPermission", "caller permission check (verify it is enforced)"),
    (r"getCallingPackage\s*\(\)|getCallingUid\s*\(\)", "caller identity lookup"),
]

# A SOURCE is where attacker-controlled data enters the process.
SOURCES: list[tuple[str, str]] = [
    (r"getIntent\s*\(\)\.get(String|Int|Parcelable|Serializable|Boolean|Data)Extra\s*\(", "getIntent().getXExtra"),
    (r"getIntent\s*\(\)\.getData\s*\(", "getIntent().getData"),
    (r"intent\.get(String|Parcelable|Serializable)Extra\s*\(", "intent.getXExtra"),
    (r"onNewIntent\s*\(", "onNewIntent (UXSS surface)"),
    (r"onReceive\s*\(\s*Context", "BroadcastReceiver.onReceive"),
    (r"public\s+Cursor\s+query\s*\(", "ContentProvider.query"),
    (r"public\s+Bundle\s+call\s*\(", "ContentProvider.call"),
]

SERVERS: list[tuple[str, str]] = [
    (r"NanoHTTPD|extends\s+NanoHTTPD", "NanoHTTPD local server"),
    (r"ServerSocket\s*\(", "ServerSocket"),
    (r"HttpServer\.create\s*\(", "HttpServer"),
]

# Hardcoded-secret patterns. Deliberately narrow — broad entropy scans are pure noise.
SECRETS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key"),
    (r"ghp_[0-9A-Za-z]{36}", "GitHub personal access token"),
    (r"sk_live_[0-9A-Za-z]{24,}", "Stripe live secret key"),
    (r"xox[abprs]-[0-9A-Za-z-]{10,}", "Slack token"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "embedded private key"),
    (r"https://[a-z0-9-]+\.firebaseio\.com", "Firebase RTDB URL"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT literal"),
]

# Third-party namespaces. Hits here are almost always library noise, not the app's bug.
LIB_PREFIXES: tuple[str, ...] = (
    "android/", "androidx/", "com/google/", "kotlin/", "kotlinx/", "org/jetbrains/",
    "com/squareup/", "okhttp3/", "okio/", "retrofit2/", "io/reactivex/", "rx/",
    "com/facebook/", "com/bumptech/", "org/apache/", "org/json/", "com/airbnb/lottie/",
    "com/adjust/", "com/appsflyer/", "io/branch/", "com/amplitude/", "com/segment/",
    "com/crashlytics/", "io/sentry/", "j$/", "org/chromium/", "dagger/", "javax/",
    "com/unity3d/", "org/koin/", "coil/", "io/grpc/", "com/onesignal/", "org/slf4j/",
)


def is_library_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    return norm.startswith(LIB_PREFIXES)


def compile_table(table: list[tuple[str, str]]) -> list[tuple[re.Pattern[str], str]]:
    return [(re.compile(pat), label) for pat, label in table]


SINKS_RE = compile_table(SINKS)
SOURCES_RE = compile_table(SOURCES)
SERVERS_RE = compile_table(SERVERS)
SECRETS_RE = compile_table(SECRETS)
