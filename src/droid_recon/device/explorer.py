"""UI exploration: authenticate with supplied credentials, then crawl app features.

Why this exists: the static+IPC layers only reach what an unauthenticated caller can
reach. The bugs that pay — IDOR, broken object authorization, token handling, post-login
WebViews — live behind a login screen. Reaching them needs real credentials driven
through the real UI.

Credentials come from a JSON file or env vars and are redacted from every artifact.
They are typed into the app, so they DO end up in the app's own storage and possibly in
its traffic — which is the point (that is what we're auditing) — but droid-recon never
writes them to findings, reports, or the session log.

The crawler is a bounded BFS over screen states, keyed by a structural signature of the
UI tree so that visually-identical screens are not revisited. It is deliberately not an
LLM loop: the orchestrator reads the resulting screen graph and screenshots and decides
where to dig.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import shell
from ..log import ok, say, warn
from . import screen

SETTLE = 1.5

# Field identification heuristics, in priority order.
_USER_HINTS = ("email", "username", "user_name", "userid", "login", "phone", "account")
_PASS_HINTS = ("password", "passwd", "pwd", "pin", "passcode")
_SUBMIT_HINTS = ("sign in", "signin", "log in", "login", "continue", "next", "submit",
                 "done", "go", "enter", "confirm")
# Controls that would end the session or leave the app — never press these.
_AVOID = ("logout", "log out", "sign out", "delete", "remove", "uninstall", "buy",
          "purchase", "pay", "subscribe", "share", "call", "send")


@dataclass
class Credentials:
    username: str = ""
    password: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None = None) -> Credentials:
        """From a JSON file, else DROID_RECON_USER / DROID_RECON_PASS."""
        if path:
            p = Path(path).expanduser()
            if p.exists():
                d = json.loads(p.read_text())
                return cls(d.get("username", ""), d.get("password", ""),
                           {k: v for k, v in d.items() if k not in ("username", "password")})
            warn(f"credentials file not found: {p}")
        return cls(os.environ.get("DROID_RECON_USER", ""),
                   os.environ.get("DROID_RECON_PASS", ""))

    @property
    def present(self) -> bool:
        return bool(self.username and self.password)

    def redact(self, text: str) -> str:
        """Strip credential values from anything destined for an artifact."""
        out = text
        for secret in (self.password, self.username, *self.extra.values()):
            if secret and len(secret) >= 3:
                out = out.replace(secret, "<redacted>")
        return out


@dataclass
class ScreenState:
    sig: str
    activity: str
    texts: list[str]
    clickables: list[dict]
    screenshot: str | None = None
    depth: int = 0
    reached_by: str = ""

    def to_dict(self) -> dict:
        return {
            "sig": self.sig,
            "activity": self.activity,
            "texts": self.texts[:25],
            "clickable_count": len(self.clickables),
            "screenshot": self.screenshot,
            "depth": self.depth,
            "reached_by": self.reached_by,
        }


def _signature(activity: str, items: list[dict]) -> str:
    """Structural fingerprint: same layout => same state, regardless of dynamic text."""
    parts = [activity] + sorted(
        f"{i.get('resource_id','')}|{i.get('class','')}" for i in items
    )
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _capture_state(serial: str | None, depth: int = 0, reached_by: str = "",
                   shots: Path | None = None) -> ScreenState | None:
    xml = screen.ui_tree_xml(serial)
    if not xml:
        return None
    items = screen.ui_summary(xml, max_items=150)
    activity = screen.current_focus(serial)
    texts = [i["text"] or i["desc"] for i in items if (i["text"] or i["desc"])]
    clickables = [i for i in items if i.get("clickable")]
    shot = None
    if shots is not None:
        p = screen.capture(shots, f"d{depth}_{activity.split('/')[-1][:30]}", serial)
        shot = str(p) if p else None
    return ScreenState(_signature(activity, items), activity, texts, clickables, shot,
                       depth, reached_by)


def _bounds_center(bounds: str) -> tuple[int, int] | None:
    m = re.findall(r"\[(\d+),(\d+)\]", bounds or "")
    if len(m) != 2:
        return None
    (x1, y1), (x2, y2) = (int(m[0][0]), int(m[0][1])), (int(m[1][0]), int(m[1][1]))
    return (x1 + x2) // 2, (y1 + y2) // 2


def _tap(serial: str | None, bounds: str) -> bool:
    c = _bounds_center(bounds)
    if not c:
        return False
    shell.adb_shell(["input", "tap", str(c[0]), str(c[1])], serial=serial, timeout=25)
    return True


def _label(item: dict) -> str:
    return (item.get("text") or item.get("desc") or item.get("resource_id", "")).strip()


# ---- authentication ----

def authenticate(package: str, creds: Credentials, serial: str | None = None,
                 shots: Path | None = None, max_attempts: int = 3) -> dict:
    """Find the login form, fill it, submit, and verify we actually got in."""
    if not creds.present:
        return {"attempted": False, "reason": "no credentials supplied "
                                              "(--credentials or DROID_RECON_USER/PASS)"}

    say("auth", f"attempting login as {creds.username[:3]}***")
    before = _capture_state(serial, 0, "pre-auth", shots)
    if before is None:
        return {"attempted": False, "reason": "could not read the UI tree"}

    if not _looks_like_login(before):
        return {"attempted": False, "reason": "no login form detected on the current screen",
                "activity": before.activity, "ui_sample": before.texts[:10]}

    xml = screen.ui_tree_xml(serial)
    fields = _find_fields(xml or "")
    if not fields.get("password"):
        return {"attempted": False, "reason": "no password field found",
                "fields_seen": sorted(fields)}

    if fields.get("username"):
        _tap(serial, fields["username"])
        time.sleep(0.4)
        shell.adb_shell(["input", "text", _escape(creds.username)], serial=serial, timeout=25)
    _tap(serial, fields["password"])
    time.sleep(0.4)
    shell.adb_shell(["input", "text", _escape(creds.password)], serial=serial, timeout=25)
    shell.adb_shell(["input", "keyevent", "111"], serial=serial, timeout=20)  # ESC: hide IME

    submitted = False
    if fields.get("submit"):
        submitted = _tap(serial, fields["submit"])
    if not submitted:
        shell.adb_shell(["input", "keyevent", "66"], serial=serial, timeout=20)  # ENTER

    time.sleep(4.0)
    after = _capture_state(serial, 0, "post-auth", shots)
    if after is None:
        return {"attempted": True, "authenticated": False, "reason": "UI unreadable after submit"}

    # Success = we left the login screen and no error text appeared.
    still_login = _looks_like_login(after)
    err = _error_text(after.texts)
    authed = (after.sig != before.sig) and not still_login and not err

    (ok if authed else warn)(
        f"login {'succeeded' if authed else 'did not succeed'} "
        f"(activity={after.activity.split('/')[-1]})"
    )
    return {
        "attempted": True,
        "authenticated": authed,
        "activity_before": before.activity,
        "activity_after": after.activity,
        "still_on_login": still_login,
        "error_text": err,
        "screenshot": after.screenshot,
        "ui_sample": [creds.redact(t) for t in after.texts[:12]],
    }


def _escape(text: str) -> str:
    """`input text` is space-delimited and treats several chars specially."""
    out = text.replace("%", "\\%").replace(" ", "%s")
    for ch in "()<>|;&*\\~\"'`$":
        out = out.replace(ch, "\\" + ch)
    return out


def _looks_like_login(state: ScreenState) -> bool:
    joined = " ".join(state.texts).lower()
    has_pass_word = any(h in joined for h in _PASS_HINTS)
    has_submit = any(h in joined for h in _SUBMIT_HINTS)
    return has_pass_word or (has_submit and any(h in joined for h in _USER_HINTS))


def _error_text(texts: list[str]) -> str:
    for t in texts:
        low = t.lower()
        if any(w in low for w in ("incorrect", "invalid", "failed", "wrong", "try again",
                                  "not recognized", "error")):
            return t[:160]
    return ""


def _find_fields(xml: str) -> dict[str, str]:
    """Locate username/password/submit by class, resource-id and hint text."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return {}

    fields: dict[str, str] = {}
    edits: list[tuple[dict, str]] = []

    for node in root.iter("node"):
        a = node.attrib
        cls = a.get("class", "")
        rid = (a.get("resource-id") or "").lower()
        text = (a.get("text") or "").lower()
        desc = (a.get("content-desc") or "").lower()
        hint = (a.get("hint") or "").lower()
        blob = f"{rid} {text} {desc} {hint}"
        bounds = a.get("bounds", "")

        if "EditText" in cls or a.get("focusable") == "true" and "Edit" in cls:
            edits.append((a, blob))
            if a.get("password") == "true" or any(h in blob for h in _PASS_HINTS):
                fields.setdefault("password", bounds)
            elif any(h in blob for h in _USER_HINTS):
                fields.setdefault("username", bounds)
        elif a.get("clickable") == "true" and any(h in blob for h in _SUBMIT_HINTS):
            fields.setdefault("submit", bounds)

    # Fall back to positional convention: first EditText = user, second = password.
    if "password" not in fields and len(edits) >= 2:
        fields.setdefault("username", edits[0][0].get("bounds", ""))
        fields["password"] = edits[1][0].get("bounds", "")
    elif "password" not in fields and len(edits) == 1:
        fields["password"] = edits[0][0].get("bounds", "")

    return fields


# ---- exploration ----

def explore(package: str, serial: str | None = None, *, max_screens: int = 25,
            max_depth: int = 4, shots: Path | None = None,
            creds: Credentials | None = None) -> dict:
    """Bounded BFS over the app's screens. Returns a screen graph.

    Deliberately avoids destructive controls (logout, delete, purchase) — an autonomous
    crawler that taps "Delete account" has ended the audit.
    """
    creds = creds or Credentials()
    visited: dict[str, ScreenState] = {}
    edges: list[dict] = []
    avoided: list[str] = []

    start = _capture_state(serial, 0, "entry", shots)
    if start is None:
        return {"error": "could not read the UI tree — is the app in the foreground?"}
    visited[start.sig] = start
    queue = [(start, 0)]

    say("explore", f"crawling {package} (max {max_screens} screens, depth {max_depth})")

    while queue and len(visited) < max_screens:
        state, depth = queue.pop(0)
        if depth >= max_depth:
            continue

        for item in state.clickables[:12]:
            if len(visited) >= max_screens:
                break
            label = _label(item)
            if not label:
                continue
            if any(bad in label.lower() for bad in _AVOID):
                avoided.append(label)
                continue

            if not _tap(serial, item.get("bounds", "")):
                continue
            time.sleep(SETTLE)

            new = _capture_state(serial, depth + 1, label, shots)
            if new is None:
                _back(serial)
                continue

            # Left the app entirely — go back and keep the crawl inside the target.
            if package not in (new.activity or "") and new.activity:
                _back(serial)
                time.sleep(SETTLE)
                continue

            edges.append({"from": state.sig, "to": new.sig, "via": creds.redact(label)})
            if new.sig not in visited:
                visited[new.sig] = new
                queue.append((new, depth + 1))

            _back(serial)
            time.sleep(SETTLE)

    ok(f"explored {len(visited)} screens, {len(edges)} transitions")
    return {
        "screens": [creds and _redact_state(s, creds) or s.to_dict() for s in visited.values()],
        "transitions": edges,
        "screen_count": len(visited),
        "avoided_controls": sorted(set(avoided)),
        "note": ("Destructive controls (logout/delete/purchase) were skipped by design. "
                 "Screens listed here were reached through the real UI, so anything "
                 "found on them is reachable by an ordinary authenticated user."),
    }


def _redact_state(s: ScreenState, creds: Credentials) -> dict:
    d = s.to_dict()
    d["texts"] = [creds.redact(t) for t in d.get("texts", [])]
    d["reached_by"] = creds.redact(d.get("reached_by", ""))
    return d


def _back(serial: str | None) -> None:
    shell.adb_shell(["input", "keyevent", "4"], serial=serial, timeout=20)
