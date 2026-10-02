"""IPC probes: activities, deep links, broadcasts, services, content providers.

THE RULE THIS MODULE ENFORCES
-----------------------------
`adb shell` runs as the shell UID and holds START_ANY_ACTIVITY. So it can launch any
activity and query many providers *regardless of export state or permissions*. A probe
that "succeeds" therefore proves nothing about who can actually reach the component.

Every Observation gets its `reachable_from` from the manifest Component that produced
it — never from the probe's exit code. A probe answers "what happens", the manifest
answers "who can make it happen". Conflating them is how you file a report saying
"unexported activity accessible via root am start", which is true on every Android
device ever shipped and is not a bug.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .. import shell
from ..log import say
from ..models import Component, Observation
from . import logcat

PROBE_TIMEOUT = 30

_COMMAND_REJECTED = re.compile(
    r"(?:Error:\s*app is in background uid|Background execution not allowed|"
    r"Not allowed to start service|Error:\s*Not found; no service started)",
    re.IGNORECASE,
)

# `content query` prints "Row: 0 col=val, ..." per row.
_ROW = re.compile(r"^Row:\s*\d+", re.MULTILINE)
_PROVIDER_OPERATION = {
    "query_provider": "read", "read_provider": "read",
    "insert_provider": "write", "update_provider": "write",
    "delete_provider": "write", "write_provider": "write",
    "call_provider": "call",
}


@dataclass
class ProbeContext:
    package: str
    serial: str | None = None
    capture_logcat: bool = True
    counter: int = 0
    agent: object = None  # DeviceAgentClient | None

    def next_id(self, kind: str) -> str:
        self.counter += 1
        return f"O{self.counter:04d}-{kind}"


def _excerpt(text: str, limit: int = 600) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + f"... [+{len(text) - limit} chars]"


def _run_probe(ctx: ProbeContext, kind: str, argv: list[str], component: Component | None,
               *, reach_override: str | None = None) -> Observation:
    """Run one device command and wrap it as an Observation with manifest-derived reach."""
    from ..device_agent.runtime import exec_on_device

    if ctx.capture_logcat:
        logcat.clear(ctx.serial, agent=ctx.agent)

    proc = exec_on_device(argv, agent=ctx.agent, serial=ctx.serial, timeout=PROBE_TIMEOUT)
    log_text = (logcat.window(ctx.package, ctx.serial, agent=ctx.agent)
                if ctx.capture_logcat else "")

    operation = _PROVIDER_OPERATION.get(kind) if component and component.type == "provider" else None
    if reach_override is not None:
        reach = reach_override
    elif component is None:
        reach = "shell"
    else:
        reach = component.provider_reach(operation) if operation else component.reachable_from
    obs = Observation(
        id=ctx.next_id(kind),
        kind=kind,
        package=ctx.package,
        component=component.name if component else None,
        reachable_from=reach,  # from the MANIFEST, never from proc.rc
        command=["adb", "shell", *argv],
        rc=proc.rc,
        stdout_excerpt=_excerpt(proc.stdout),
        stderr_excerpt=_excerpt(proc.stderr),
        logcat_excerpt=_excerpt(log_text, 3000),
    )
    if operation:
        obs.detail["reach_basis"] = f"manifest provider {operation} reach"
        obs.detail["reach_limit"] = "path permissions, URI grants, and code checks may differ"
    _classify(obs, proc.stdout + proc.stderr, log_text, ctx.package,
              component=component.target_activity or component.name if component else None)
    return obs


def _classify(obs: Observation, output: str, log_text: str, package: str = "",
              *, component: str | None = None) -> None:
    """Assign a machine-readable signal and decide whether a human should look.

    `interesting` requires BOTH a meaningful effect AND third-party/browser reach.
    A shell-only-reachable component can never be interesting on its own.
    """
    lowered = output.lower()
    rejected = _COMMAND_REJECTED.search(output) if obs.rc != 0 else None
    if rejected:
        obs.detail["command_rejected"] = rejected.group(0)

    if "permission denial" in lowered or "securityexception" in lowered or logcat.denied(log_text):
        obs.signal = "denied"
    elif rejected:
        # A late crash from the preceding launch can enter this logcat window even
        # after `logcat -c`. The OS refused this command before app dispatch.
        obs.signal = "error"
        if logcat.crashed(log_text):
            obs.detail["unattributed_logcat_crash"] = "probe command rejected before dispatch"
    elif logcat.crashed(log_text):
        origin = logcat.crash_origin(log_text, package, component)
        obs.detail["crash_origin"] = origin
        if origin == "other_process":
            obs.signal = "error"
        else:
            obs.signal = "crash"
    elif _ROW.search(output):
        obs.signal = "rows_returned"
        obs.detail["row_count"] = len(_ROW.findall(output))
    elif "no result found" in lowered or "no rows" in lowered:
        obs.signal = "empty_result"
    elif "error while accessing provider" in lowered or "unknown uri" in lowered:
        obs.signal = "provider_error"
    elif "does not exist" in lowered or "unable to resolve" in lowered:
        obs.signal = "not_found"
    elif obs.rc == 0:
        obs.signal = "ok"
    else:
        obs.signal = "error"

    leaks = logcat.has_sensitive(log_text, package)
    if leaks:
        obs.detail["logcat_sensitive_tokens"] = leaks

    reachable = obs.reachable_from in ("third_party_app", "browser")
    attributable = obs.detail.get("crash_origin") == "target_component"
    meaningful = (obs.signal in ("rows_returned", "ok") or
                  (obs.signal == "crash" and attributable) or bool(leaks))
    obs.interesting = reachable and meaningful


# ---- activity ----

def launch_activity(ctx: ProbeContext, comp: Component) -> Observation:
    return _run_probe(ctx, "launch_activity",
                      ["am", "start", "-W", "-n", f"{ctx.package}/{comp.name}"], comp)


def launch_deeplink(ctx: ProbeContext, comp: Component, uri: str) -> Observation:
    obs = _run_probe(
        ctx, "deeplink",
        ["am", "start", "-a", "android.intent.action.VIEW",
         "-c", "android.intent.category.BROWSABLE", "-d", uri],
        comp,
    )
    obs.detail["uri"] = uri
    return obs


# ---- broadcast ----

def send_broadcast(ctx: ProbeContext, comp: Component, action: str) -> Observation:
    obs = _run_probe(
        ctx, "broadcast",
        ["am", "broadcast", "-a", action, "-n", f"{ctx.package}/{comp.name}"],
        comp,
    )
    obs.detail["action"] = action
    return obs


# ---- service ----

def start_service(ctx: ProbeContext, comp: Component) -> Observation:
    return _run_probe(ctx, "start_service",
                      ["am", "start-service", "-n", f"{ctx.package}/{comp.name}"], comp)


# ---- provider ----

def query_provider(ctx: ProbeContext, comp: Component, authority: str, path: str) -> Observation:
    uri = f"content://{authority}" + (f"/{path}" if path else "")
    obs = _run_probe(ctx, "query_provider", ["content", "query", "--uri", uri], comp)
    obs.detail["uri"] = uri
    obs.detail["authority"] = authority
    obs.detail["path"] = path
    return obs


def call_provider(ctx: ProbeContext, comp: Component, authority: str, method: str) -> Observation:
    uri = f"content://{authority}"
    obs = _run_probe(ctx, "call_provider",
                     ["content", "call", "--uri", uri, "--method", method], comp)
    obs.detail["uri"] = uri
    obs.detail["method"] = method
    return obs


def read_provider_file(ctx: ProbeContext, comp: Component, authority: str, path: str) -> Observation:
    """`content read` — the FileProvider path-traversal primitive."""
    uri = f"content://{authority}/{path}"
    obs = _run_probe(ctx, "read_provider", ["content", "read", "--uri", uri], comp)
    obs.detail["uri"] = uri
    obs.detail["traversal_candidate"] = ".." in path or "%2F" in path.lower()
    # A traversal read that returns bytes without an error is a strong signal.
    if obs.rc == 0 and obs.stdout_excerpt and obs.signal == "ok":
        obs.signal = "bytes_returned"
        obs.interesting = obs.reachable_from in ("third_party_app", "browser")
    return obs


# ---- dumpsys corroboration ----

def dumpsys_package(package: str, serial: str | None = None, *, agent=None) -> str:
    from ..device_agent.runtime import exec_on_device
    return exec_on_device(["dumpsys", "package", package],
                          agent=agent, serial=serial, timeout=60).stdout


def runtime_permissions(package: str, serial: str | None = None,
                        *, agent=None) -> dict[str, bool]:
    """Which permissions are actually granted at runtime, per dumpsys."""
    text = dumpsys_package(package, serial, agent=agent)
    out: dict[str, bool] = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(android\.permission\.[\w.]+|[\w.]+\.permission\.[\w.]+):\s*granted=(true|false)", line)
        if m:
            out[m.group(1)] = m.group(2) == "true"
    return out


def resolve_authorities(package: str, serial: str | None = None,
                        *, agent=None) -> list[str]:
    """Provider authorities the platform has actually registered for this package."""
    text = dumpsys_package(package, serial, agent=agent)
    found: set[str] = set()
    for m in re.finditer(r"authority=([\w.;\-]+)", text):
        for a in m.group(1).split(";"):
            if a:
                found.add(a)
    return sorted(found)
