"""Logcat capture windowed around a probe.

The spec's `logcat -d --pid=$(pidof pkg)` (prompt.md:154) has a fatal flaw: after a
crash the pid is gone, so the filter matches nothing — precisely when the log matters
most. We clear the buffer, run the probe, then dump the whole window and filter by text.

CREDENTIAL DETECTION IS DELIBERATELY STRICT
-------------------------------------------
A naive `/token|secret|password/i` sweep over logcat is a false-positive machine. The
Android framework logs `errorCallbackToken=null`, `RemoteToken{...}`, `triggerTask`, and
`WindowContainerToken` on every single activity transition — so every probe would
"discover" a credential leak. Three rules kill that:

  1. The keyword must be a whole word, not a substring of `errorCallbackToken`.
  2. It must be followed by an assignment AND a value that actually looks like a secret
     (long enough, not `null`/`false`/`0`).
  3. The line must be attributable to the target package — framework tags emitting
     transition noise are excluded outright.
"""

from __future__ import annotations

import re

# Lines worth keeping in the excerpt regardless of who emitted them.
_INTERESTING = re.compile(
    r"FATAL EXCEPTION|AndroidRuntime|SecurityException|Permission Denial|"
    r"E/SQLiteLog|StrictMode",
    re.IGNORECASE,
)

# Framework components that log token/task noise on every transition. A "credential"
# found only on one of these lines belongs to the platform, not to the target app.
_NOISE_TAGS = re.compile(
    r"\b(WindowManager|WindowManagerShell|ActivityManager|ActivityTaskManager|"
    r"ViewRootImpl|InputDispatcher|InputReader|Choreographer|SurfaceFlinger|"
    r"ActivityThread|ImeTracker|InsetsController|WindowOnBackDispatcher|"
    r"BufferQueue|OpenGLRenderer|libEGL|Parcel|ziparchive|ResourcesCompat)\b",
    re.IGNORECASE,
)

# Whole-word credential keys. `(?<![A-Za-z])` + `(?![A-Za-z])` stops `errorCallbackToken`
# and `RemoteToken` from matching, while `access_token` / `api-key` still do.
_KEY = (
    r"(?<![A-Za-z])"
    r"(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|auth[_-]?token|bearer|authorization|credential|session[_-]?id|"
    r"private[_-]?key|client[_-]?secret)"
    r"(?![A-Za-z])"
)

# key <sep> value, where the value is long enough and not an obvious non-secret.
_ASSIGNED = re.compile(
    _KEY + r"\s*[:=]\s*[\"']?(?P<value>[^\s\"',;<>}\]]{8,})",
    re.IGNORECASE,
)

# Values that are structurally never secrets, however they are named.
_NOT_A_SECRET = re.compile(
    r"^(null|nil|none|true|false|0|1|-1|\{\}|\[\]|undefined|empty|"
    r"0x[0-9a-f]{1,8}|@[0-9a-f]+|<[^>]*>)$",
    re.IGNORECASE,
)

# High-confidence literals: these are secrets regardless of the surrounding key name.
_SECRET_LITERAL = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"  # JWT
    r"|AKIA[0-9A-Z]{16}"                                              # AWS key id
    r"|AIza[0-9A-Za-z_\-]{35}"                                        # Google API key
    r"|gh[pousr]_[0-9A-Za-z]{20,}"                                    # GitHub token
    r"|Bearer\s+[A-Za-z0-9._~+/-]{20,}"                               # Bearer header
)


def clear(serial: str | None = None, *, agent=None) -> None:
    if agent:
        agent.exec(["logcat", "-c"], timeout=30)
    else:
        from .. import shell
        shell.adb("logcat", "-c", serial=serial, timeout=30)


def dump(serial: str | None = None, *, lines: int = 400, agent=None) -> str:
    if agent:
        proc = agent.exec(["logcat", "-d", "-v", "brief", "-t", str(lines)], timeout=60)
    else:
        from .. import shell
        proc = shell.adb("logcat", "-d", "-v", "brief", "-t", str(lines), serial=serial, timeout=60)
    return proc.stdout


def window(package: str, serial: str | None = None, *, lines: int = 400,
           max_chars: int = 4000, agent=None) -> str:
    """Dump since the last clear(), keeping lines about `package` or generally notable."""
    raw = dump(serial, lines=lines, agent=agent)
    kept = [ln.rstrip() for ln in raw.splitlines()
            if package in ln or _INTERESTING.search(ln)]
    text = "\n".join(kept)
    return text[-max_chars:] if len(text) > max_chars else text


def _line_belongs_to(line: str, package: str) -> bool:
    """Is this log line plausibly from the target app rather than the framework?"""
    if _NOISE_TAGS.search(line):
        return False
    return package in line or _SECRET_LITERAL.search(line) is not None


def has_sensitive(text: str, package: str = "") -> list[str]:
    """Credential-shaped material actually attributable to `package`.

    Returns the distinct evidence strings found — empty when nothing survives the
    three rules above, which is the common and correct answer.
    """
    found: set[str] = set()
    for line in text.splitlines():
        if package and not _line_belongs_to(line, package):
            continue

        for m in _SECRET_LITERAL.finditer(line):
            found.add(m.group(0)[:60])

        for m in _ASSIGNED.finditer(line):
            value = m.group("value")
            if _NOT_A_SECRET.match(value):
                continue
            # A value that is just another identifier-ish word is usually a field name.
            if value.isalpha() and len(value) < 12:
                continue
            found.add(f"{m.group(1).lower()}={value[:40]}")

    return sorted(found)


def crashed(text: str) -> bool:
    return "FATAL EXCEPTION" in text or "Process crashed" in text


def crash_origin(text: str, package: str, component: str | None = None) -> str:
    """Attribute a fatal stack before treating it as a component failure.

    A freshly started app installs its providers and creates its Application before
    Android dispatches the requested activity, receiver, or service. A failure in
    that phase is observable during the probe, but says nothing about the probed
    component or its Intent handling. The last fatal stack is used because a prior
    process can finish crashing inside the next probe's logcat window.
    """
    if not crashed(text):
        return "none"
    fatal = text.rfind("FATAL EXCEPTION")
    stack = text[fatal:] if fatal >= 0 else text
    process = re.search(r"\bProcess:\s*([\w.:-]+)", stack)
    if process and package and not (process.group(1) == package or
                                    process.group(1).startswith(package + ":")):
        return "other_process"

    provider = re.search(r"Unable to get provider\s+([\w.$]+)", stack)
    if provider and provider.group(1) != component:
        return "app_initialization"
    if re.search(r"Unable to create application\b", stack):
        return "app_initialization"

    if component:
        target_frame = re.search(r"\bat\s+" + re.escape(component)
                                 + r"\.[\w$<>]+\s*\(", stack)
        target_launch = ("ComponentInfo{" in stack and
                         re.search(r"(?:Unable to start|Unable to instantiate)\s+"
                                   r"(?:activity|receiver|service)\b", stack,
                                   re.IGNORECASE) and component in stack)
        if target_frame or target_launch:
            return "target_component"
    return "unattributed"


def denied(text: str) -> bool:
    return "Permission Denial" in text or "SecurityException" in text
