"""Screenshots and UI tree dumps.

Screenshots are written to disk as PNGs rather than analysed here — the orchestrator
(Claude Code) reads them directly with its own vision, so no vision model, API key, or
LLM dependency is needed in this process.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from .. import shell
from ..log import warn

REMOTE_PNG = "/data/local/tmp/droid-recon-screen.png"
REMOTE_UI = "/data/local/tmp/droid-recon-ui.xml"


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]


def capture(dest_dir: Path, label: str, serial: str | None = None,
            *, agent=None) -> Path | None:
    """screencap on device, then pull. Returns the local path, or None on failure."""
    from ..device_agent.runtime import exec_on_device
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:80]
    local = dest_dir / f"{_stamp()}_{safe}.png"

    cap = exec_on_device(["screencap", "-p", REMOTE_PNG],
                         agent=agent, serial=serial, timeout=45)
    if not cap.ok:
        return None

    if agent:
        data = agent.read_file(REMOTE_PNG, timeout=60)
        if data:
            local.write_bytes(data)
    else:
        shell.adb("pull", REMOTE_PNG, str(local), serial=serial, timeout=60)
    exec_on_device(["rm", "-f", REMOTE_PNG], agent=agent, serial=serial, timeout=20)

    if local.exists() and local.stat().st_size > 0:
        return local
    return None


def ui_tree_xml(serial: str | None = None, *, agent=None) -> str | None:
    """Raw uiautomator dump. Fails on some transient screens — that is survivable."""
    from ..device_agent.runtime import exec_on_device
    proc = exec_on_device(["uiautomator", "dump", REMOTE_UI],
                          agent=agent, serial=serial, timeout=60)
    if "ERROR" in proc.stdout or not proc.ok:
        return None
    cat = exec_on_device(["cat", REMOTE_UI], agent=agent, serial=serial, timeout=30)
    exec_on_device(["rm", "-f", REMOTE_UI], agent=agent, serial=serial, timeout=20)
    return cat.stdout if cat.stdout.lstrip().startswith("<") else None


def ui_summary(xml_text: str, max_items: int = 60) -> list[dict]:
    """Flatten a uiautomator dump to the interactable/text-bearing nodes."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    items: list[dict] = []
    for node in root.iter("node"):
        text = (node.attrib.get("text") or "").strip()
        desc = (node.attrib.get("content-desc") or "").strip()
        rid = node.attrib.get("resource-id") or ""
        clickable = node.attrib.get("clickable") == "true"
        if not (text or desc or (rid and clickable)):
            continue
        items.append({
            "text": text[:120],
            "desc": desc[:120],
            "resource_id": rid,
            "class": node.attrib.get("class", ""),
            "clickable": clickable,
            "bounds": node.attrib.get("bounds", ""),
        })
        if len(items) >= max_items:
            break
    return items


def current_focus(serial: str | None = None, *, agent=None) -> str:
    """Which activity is actually on screen — the ground truth for 'did the launch land'."""
    from ..device_agent.runtime import exec_on_device
    proc = exec_on_device(["dumpsys", "window"], agent=agent, serial=serial, timeout=45)
    for line in proc.stdout.splitlines():
        if "mCurrentFocus" in line or "mFocusedApp" in line:
            m = re.search(r"([\w.]+/[\w.$]+)", line)
            if m:
                return m.group(1)
    return ""


def dismiss_system_dialogs(serial: str | None = None, *, agent=None) -> None:
    """Clear ANR / crash dialogs that would otherwise block every subsequent probe."""
    from ..device_agent.runtime import exec_on_device
    exec_on_device(["am", "broadcast", "-a", "android.intent.action.CLOSE_SYSTEM_DIALOGS"],
                   agent=agent, serial=serial, timeout=20)
    exec_on_device(["input", "keyevent", "4"], agent=agent, serial=serial, timeout=20)
