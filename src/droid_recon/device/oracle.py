"""Exploit verification oracle.

The hard question in automated exploitation is not "did the command run" — `am start`
returns `Status: ok` for almost anything — but **"did the thing I was trying to cause
actually happen?"**

This module answers that by taking a before/after snapshot of everything observable and
diffing it. Five independent signal sources, because any one of them lies:

  logcat        the app's own account of what it did (noisy, but where stack traces live)
  UI            what is actually on screen afterwards (the strongest single signal —
                a screen the attacker should not be able to reach IS the exploit)
  process       did it crash, did the pid change
  traffic       did our canary URL get fetched (proves data reached a network sink)
  filesystem    did a file we can see appear or change

A verdict requires a *specific* expectation to be met, stated by the payload up front.
"Something changed" is not a verdict — apps change constantly on their own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import shell
from ..log import say
from . import logcat, payloads, screen


@dataclass
class Snapshot:
    """Observable device state at a point in time."""

    focus: str = ""
    pid: str = ""
    ui_texts: list[str] = field(default_factory=list)
    ui_activity: str = ""
    file_marker: str = ""

    def to_dict(self) -> dict:
        return {
            "focus": self.focus,
            "pid": self.pid,
            "ui_activity": self.ui_activity,
            "ui_text_count": len(self.ui_texts),
        }


def snapshot(package: str, serial: str | None = None, *, with_ui: bool = True) -> Snapshot:
    snap = Snapshot()
    snap.focus = screen.current_focus(serial)
    snap.pid = shell.adb_shell(["pidof", package], serial=serial, timeout=20).stdout.strip()
    if with_ui:
        xml = screen.ui_tree_xml(serial)
        if xml:
            items = screen.ui_summary(xml, max_items=120)
            snap.ui_texts = [i["text"] or i["desc"] or i["resource_id"] for i in items if
                             (i["text"] or i["desc"] or i["resource_id"])]
            snap.ui_activity = snap.focus
    return snap


@dataclass
class Verdict:
    """Did the payload achieve its stated effect?"""

    hit: bool
    confidence: str  # confirmed | probable | none
    signals: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "hit": self.hit,
            "confidence": self.confidence,
            "signals": self.signals,
            "evidence": self.evidence,
        }


def evaluate(
    payload: payloads.Payload,
    before: Snapshot,
    after: Snapshot,
    *,
    package: str,
    log_text: str = "",
    traffic_hosts: list[str] | None = None,
    stdout: str = "",
    target_component: str = "",
) -> Verdict:
    """Compare expectation against observed change. Conservative by design."""
    expect = payload.expect or {}
    signals: list[str] = []
    evidence: dict = {}
    traffic_hosts = traffic_hosts or []

    # --- 0. did the command even run? ---
    #
    # A malformed payload makes `am` throw before the app is involved at all, and the
    # exception message quotes the arguments back — including our canary. Searching that
    # for evidence turns every broken payload into a "confirmed exploit". Bail first.
    if _command_failed(stdout):
        signals.append("command_error")
        evidence["command_error"] = _error_line(stdout)
        return Verdict(False, "none", signals, evidence)

    # --- 1. canary reached a sink (strongest: proves OUR data flowed) ---
    #
    # Search only OUTSIDE the command's own echo. `am` prints
    # `Starting: Intent { ... dat=<uri> }`, and ActivityManager logs the launch. If the
    # canary is echoed back by the tooling, finding it proves nothing about the app —
    # it is our own string handed back to us. Verified on API 34 that `am` truncates the
    # data URI and logs only "(has extras)", but that is version-specific, so strip the
    # echo rather than depend on it.
    seen_canaries = (payloads.extract_canaries(_strip_echo(log_text))
                     + payloads.extract_canaries(_strip_echo(stdout)))
    if seen_canaries:
        signals.append("canary_in_logs")
        evidence["canaries"] = sorted(set(seen_canaries))

    # --- 2. canary URL fetched (proves our string reached a NETWORK sink) ---
    #
    # Matched on the canary token appearing in a captured request URL, not merely on the
    # host: the host alone is shared with unrelated traffic, whereas the token is unique
    # to this payload. This is the strongest signal the oracle has — the app took our
    # input and made an outbound request with it.
    fetched = [u for u in traffic_hosts if payloads.CANARY_PREFIX in u]
    if fetched:
        signals.append("canary_host_fetched")
        evidence["canary_urls"] = sorted(set(fetched))[:5]
    elif expect.get("traffic_host") and any(
            expect["traffic_host"] in h for h in traffic_hosts):
        signals.append("canary_host_contacted")
        evidence["traffic_host"] = expect["traffic_host"]

    # --- 3. crash ---
    #
    # Exclude crashes caused by our OWN instrumentation. Taking a UI snapshot runs
    # `uiautomator dump`, which registers a UiAutomationService; doing that repeatedly
    # (or while another automation client is attached) throws
    # `IllegalStateException: UiAutomationService ... already registered!`. Attributing
    # that to the payload makes the measurement apparatus manufacture its own findings —
    # observed producing a "crash" verdict on every probe until filtered.
    crashed = logcat.crashed(log_text)
    if crashed and _self_inflicted(log_text):
        signals.append("instrumentation_crash")
        evidence["instrumentation_crash"] = _first_stack(log_text, 4)
        crashed = False
    elif crashed:
        signals.append("crash")
        evidence["crash_excerpt"] = _first_stack(log_text)
    pid_died = bool(before.pid) and not after.pid
    if pid_died and not crashed:
        signals.append("process_died")

    # --- 4. UI transition ---
    #
    # Landing on the component we explicitly launched is the NULL result, not evidence.
    # `am start -n pkg/.Foo` moves focus to Foo every single time; counting that as
    # "the payload caused a transition" marks every launch a success. Only a landing
    # somewhere OTHER than the requested component indicates the app redirected us —
    # which is the thing an intent-redirection payload is actually testing for.
    if before.focus != after.focus and after.focus:
        landed_elsewhere = bool(target_component) and not _same_component(
            after.focus, target_component
        )
        if landed_elsewhere or not target_component:
            signals.append("activity_changed")
            evidence["focus_before"] = before.focus
            evidence["focus_after"] = after.focus
            if landed_elsewhere:
                evidence["redirected_to"] = after.focus
        else:
            signals.append("landed_on_requested_component")
            evidence["focus_after"] = after.focus

    new_ui = _new_text(before.ui_texts, after.ui_texts)
    if new_ui:
        signals.append("ui_content_changed")
        evidence["new_ui_text"] = new_ui[:15]

    # --- 5. explicit string expectations ---
    for needle in expect.get("logcat_any", []) or []:
        if needle and (needle in log_text or needle in stdout):
            signals.append("expected_string_in_logs")
            evidence.setdefault("matched_strings", []).append(needle[:80])

    # --- 6. denial: the platform refused, which is a NEGATIVE result ---
    if logcat.denied(log_text) or "Permission Denial" in stdout:
        signals.append("denied")
        evidence["denied"] = True

    return _verdict_from(expect, signals, evidence)


def _verdict_from(expect: dict, signals: list[str], evidence: dict) -> Verdict:
    """Map signals to a verdict. A denial always beats a positive signal."""
    if "denied" in signals:
        return Verdict(False, "none", signals, evidence)

    # Confirmed: our own marker provably reached a sink, or the exact host was fetched.
    if "canary_host_fetched" in signals:
        return Verdict(True, "confirmed", signals, evidence)
    if "canary_in_logs" in signals:
        return Verdict(True, "confirmed", signals, evidence)

    if expect.get("crash") and "crash" in signals:
        return Verdict(True, "confirmed", signals, evidence)

    # Probable: the app sent us somewhere we did NOT request (redirection worked).
    if expect.get("activity_changed") and "activity_changed" in signals:
        return Verdict(True, "probable", signals, evidence)
    if "expected_string_in_logs" in signals:
        return Verdict(True, "probable", signals, evidence)

    # A crash we didn't ask for is still worth surfacing.
    if "crash" in signals:
        return Verdict(True, "probable", signals, evidence)

    return Verdict(False, "none", signals, evidence)


# Lines that are the tooling repeating our own request back at us. A canary found on
# one of these is not evidence the app did anything.
_ECHO_LINE = re.compile(
    r"^\s*(Starting: Intent|Broadcasting: Intent|Starting service: Intent"
    r"|Intent \{|Warning: Activity not started)"
    r"|ActivityManager:\s+START\b"
    r"|ActivityTaskManager:\s+START\b",
)


# Crash signatures produced by droid-recon's own instrumentation rather than by the
# payload. These must never be reported as findings.
_SELF_INFLICTED = re.compile(
    r"UiAutomationService.*already registered"
    r"|UiAutomationConnection"
    r"|androidx\.test\.uiautomator"
    r"|android\.app\.UiAutomation"
    r"|Could not get idle state"
    r"|frida|gum_|gadget",
    re.IGNORECASE,
)


# `FATAL EXCEPTION: <thread>` — these thread names belong to instrumentation, not the app.
_SELF_THREAD = re.compile(r"FATAL EXCEPTION:\s*(UiAutomation\w*|Instr\w*|frida\w*)",
                          re.IGNORECASE)


def _self_inflicted(log_text: str) -> bool:
    """Is this crash our measurement apparatus rather than the app under test?

    Checked two ways because either alone misses cases: the stack contents (e.g.
    `UiAutomationService ... already registered`) AND the crashing thread name (e.g.
    `FATAL EXCEPTION: UiAutomation` with a generic `Bad file descriptor` body, which
    matches no stack pattern at all).
    """
    stack = _first_stack(log_text, 25)
    return bool(_SELF_INFLICTED.search(stack) or _SELF_THREAD.search(stack))


def _same_component(focus: str, component: str) -> bool:
    """Is `focus` (pkg/fully.qualified.Name) the same component we asked for?"""
    if not focus or not component:
        return False
    focus_cls = focus.split("/")[-1].lstrip(".")
    want = component.split("/")[-1].lstrip(".")
    return focus_cls == want or focus_cls.endswith("." + want.split(".")[-1]) and (
        want.split(".")[-1] == focus_cls.split(".")[-1]
    )


def _strip_echo(text: str) -> str:
    return "\n".join(ln for ln in (text or "").splitlines() if not _ECHO_LINE.search(ln))


# `am` / `content` failing to even parse the request. These mean the payload never
# reached the app, so nothing observed afterwards is attributable to it.
_COMMAND_ERROR = re.compile(
    r"Exception occurred while executing"
    r"|java\.lang\.IllegalArgumentException"
    r"|java\.lang\.SecurityException: Permission Denial"
    r"|Error: Activity class .* does not exist"
    r"|Error: Intent .* not"
    r"|No intent supplied"
    r"|Bad component name"
    r"|usage: am\b"
    r"|Exception in thread",
)


def _command_failed(stdout: str) -> bool:
    return bool(_COMMAND_ERROR.search(stdout or ""))


def _error_line(stdout: str) -> str:
    for line in (stdout or "").splitlines():
        if _COMMAND_ERROR.search(line):
            return line.strip()[:200]
    return (stdout or "").strip().splitlines()[0][:200] if (stdout or "").strip() else ""


def _new_text(before: list[str], after: list[str]) -> list[str]:
    seen = set(before)
    return [t for t in after if t not in seen and t.strip()]


def _first_stack(log_text: str, lines: int = 12) -> str:
    out, capture = [], False
    for line in log_text.splitlines():
        if "FATAL EXCEPTION" in line:
            capture = True
        if capture:
            out.append(line.strip())
            if len(out) >= lines:
                break
    return "\n".join(out)


# ---- UI-based reachability assertion ----

# Words that mean "you are not authenticated" — used to decide whether a screen reached
# by a raw `am start` is actually a bypass or just the login wall doing its job.
_AUTH_WALL = (
    "sign in", "signin", "log in", "login", "register", "create account", "password",
    "authenticate", "verify your", "enter your email", "get started", "welcome back",
)


def looks_like_auth_wall(texts: list[str]) -> bool:
    joined = " ".join(texts).lower()
    return any(w in joined for w in _AUTH_WALL)


def assess_screen_reach(after: Snapshot, expected_component: str) -> dict:
    """Did we land on the component we aimed at, and does it look gated?

    A component that renders its own content is meaningfully reached. One that bounces
    to a login wall is NOT an authentication bypass, however cleanly `am start` returned
    — this distinction is the difference between a finding and an embarrassment.
    """
    landed = expected_component.split(".")[-1].lower() in (after.focus or "").lower()
    walled = looks_like_auth_wall(after.ui_texts)
    return {
        "landed_on_target": landed,
        "focus": after.focus,
        "shows_auth_wall": walled,
        "assessment": (
            "reached target and rendered content (no auth wall visible)"
            if landed and not walled else
            "reached target but an auth wall is on screen — NOT an auth bypass"
            if landed and walled else
            "did not land on the target component"
        ),
        "ui_sample": after.ui_texts[:12],
    }
