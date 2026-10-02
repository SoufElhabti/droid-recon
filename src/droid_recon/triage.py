"""Promote observations to findings — the false-positive gate.

An observation becomes a finding only if ALL of these hold:

  1. `reachable_from` is `third_party_app` or `browser`. Anything reachable only from
     `shell` is excluded by construction: adb shell is more privileged than any app,
     so "it worked from adb" is not evidence of anything.
  2. The probe produced a real effect (rows/bytes returned, a crash, a credential in
     the log) — not merely `Status: ok`.
  3. A source -> sink -> chain story can be stated. This mirrors the required fields in
     android-privesc-hunt/prompts/findings-schema.json and is the single most effective
     filter in the pipeline.

Rules here are deliberately conservative. Anything that passes 1 and 2 but not 3 is
emitted as a *candidate* for the orchestrator to adjudicate, not written to findings.jsonl.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .device import logcat
from .models import AttackSurface, Component, Finding, Observation, Severity

# Effects that mean something actually happened.
_MEANINGFUL = {"rows_returned", "bytes_returned", "crash"}


@dataclass
class TriageResult:
    findings: list[Finding]
    candidates: list[dict]
    rejected: list[dict]

    def summary(self) -> dict:
        return {
            "findings": len(self.findings),
            "candidates": len(self.candidates),
            "rejected": len(self.rejected),
        }


def _component_of(surface: AttackSurface, name: str | None) -> Component | None:
    if not name:
        return None
    return next((c for c in surface.components if c.name == name), None)


def _uri_from_command(obs: Observation) -> str | None:
    """Recover the probed URI from the argv when `detail` was not populated."""
    argv = obs.command
    for i, tok in enumerate(argv):
        if tok == "--uri" and i + 1 < len(argv):
            return argv[i + 1]
    return next((t for t in argv if t.startswith("content://")), None)


def _reject(obs: Observation, why: str) -> dict:
    return {"observation": obs.id, "kind": obs.kind, "component": obs.component, "why": why}


def _candidate(obs: Observation, why: str) -> dict:
    return {
        "observation": obs.id, "kind": obs.kind, "component": obs.component,
        "reachable_from": obs.reachable_from, "signal": obs.signal,
        "why_candidate": why, "command": obs.command,
        "stdout_excerpt": obs.stdout_excerpt[:300],
    }


def _severity_for(obs: Observation, comp: Component | None) -> Severity:
    if obs.kind in ("query_provider", "read_provider", "call_provider"):
        if obs.signal in ("rows_returned", "bytes_returned"):
            unguarded = comp is not None and not (comp.read_permission or comp.permission)
            return "high" if unguarded else "medium"
    if obs.detail.get("logcat_sensitive_tokens"):
        return "medium"
    if obs.signal == "crash":
        return "low"
    return "low"


def _exploitability(obs: Observation) -> str:
    if obs.reachable_from == "browser":
        return "remote-one-click"
    return "local-zero-click" if obs.kind != "launch_activity" else "local-one-click"


def _story(obs: Observation, comp: Component | None) -> tuple[dict, dict, list[str]] | None:
    """Build (source, sink, chain), or None if no coherent story exists."""
    cname = comp.name if comp else (obs.component or "?")

    if obs.kind in ("query_provider", "read_provider") and obs.signal in _MEANINGFUL:
        uri = obs.detail.get("uri") or _uri_from_command(obs) or f"content://{cname}"
        guard = (comp.read_permission or comp.permission) if comp else None
        source = {
            "type": "ContentResolver query from an unprivileged app",
            "name": uri,
            "code_location": f"{cname} (manifest: exported provider)",
            "code_excerpt": f'<provider android:name="{cname}" android:exported="true"'
                            + (f' android:readPermission="{guard}"' if guard else "")
                            + ' />',
        }
        sink = {
            "type": "provider returned data to the caller",
            "name": obs.signal,
            "code_location": uri,
            "code_excerpt": obs.stdout_excerpt[:300],
        }
        chain = [
            "Attacker app declares no special permission"
            + (f" (or holds {guard}, protection level allows it)" if guard else ""),
            f"Attacker calls ContentResolver.query(Uri.parse(\"{uri}\"))",
            f"Provider {cname} is exported with no effective read guard",
            f"Provider returns data ({obs.signal}) to the attacker process",
        ]
        return source, sink, chain

    if obs.detail.get("logcat_sensitive_tokens"):
        toks = ", ".join(obs.detail["logcat_sensitive_tokens"][:5])
        source = {
            "type": "IPC entry point reachable by a third-party app",
            "name": obs.kind,
            "code_location": cname,
            "code_excerpt": " ".join(obs.command),
        }
        sink = {
            "type": "sensitive material written to the system log",
            "name": toks,
            "code_location": "logcat",
            "code_excerpt": obs.logcat_excerpt[:300],
        }
        chain = [
            f"Attacker triggers {cname} via {obs.kind}",
            "Component logs credential-shaped material",
            "Any app holding READ_LOGS, or any local debug tooling, reads it",
        ]
        return source, sink, chain

    if obs.signal == "crash" and obs.reachable_from in ("third_party_app", "browser"):
        source = {
            "type": "component invocation through an exported entry point",
            "name": obs.kind,
            "code_location": cname,
            "code_excerpt": " ".join(obs.command),
        }
        sink = {
            "type": "unhandled exception in the target process",
            "name": "FATAL EXCEPTION",
            "code_location": cname,
            "code_excerpt": obs.logcat_excerpt[:300],
        }
        chain = [
            f"Manifest marks {cname} as reachable by an ordinary caller",
            f"Shell probe invokes {cname}; the fatal stack names this component",
            "The target process crashes; an ordinary-app reproduction is needed to confirm impact",
        ]
        return source, sink, chain

    return None


def is_platform_component(surface: AttackSurface) -> bool:
    """Is this a platform/system package whose exported surface is probably intentional?

    A package running under a platform shared UID is signed with the platform key and is
    part of the OS. Its exported providers are usually documented API (e.g.
    `content://settings/system` is world-readable by design, per Settings.System). Such
    results still get reported — suppressing them would hide real system bugs — but with
    a lowered confidence and an explicit note, so nobody files an AOSP design decision
    as a vulnerability.
    """
    return (surface.shared_user_id or "").startswith(
        ("android.uid.system", "android.uid.phone", "android.uid.shell", "android.media")
    )


_PLATFORM_NOTE = (
    "This package runs under a platform shared UID, so it is part of the OS image and "
    "signed with the platform key. Its exported surface is frequently *documented API* "
    "rather than a mistake — e.g. content://settings/{system,secure,global} is "
    "world-readable by design. Confirm against the platform documentation before "
    "treating this as a vulnerability."
)


def _merge_key(obs: Observation) -> tuple:
    """Findings are deduplicated per (component, probe kind, signal).

    One misconfigured provider queried across six paths is ONE finding with six PoCs,
    not six findings. Emitting one per URI inflates the count and buries the signal.
    """
    return (obs.component, obs.kind, obs.signal)


def triage(surface: AttackSurface, observations: list[Observation],
           start_index: int = 0) -> TriageResult:
    findings: list[Finding] = []
    candidates: list[dict] = []
    rejected: list[dict] = []
    seq = start_index
    platform = is_platform_component(surface)
    merged: dict[tuple, Finding] = {}

    for obs in observations:
        comp = _component_of(surface, obs.component)

        # Gate 1 — reachability, from the manifest.
        if obs.reachable_from not in ("third_party_app", "browser"):
            rejected.append(_reject(
                obs,
                f"reachable_from={obs.reachable_from}: only adb shell (which holds "
                f"START_ANY_ACTIVITY and runs as the shell UID) can trigger this — "
                f"not a third-party app. Not a finding.",
            ))
            continue

        if obs.signal == "crash":
            origin = obs.detail.get("crash_origin") or logcat.crash_origin(
                obs.logcat_excerpt, obs.package,
                comp.target_activity or comp.name if comp else obs.component,
            )
            if origin == "app_initialization":
                rejected.append(_reject(
                    obs, "app initialization crashed before the requested component "
                    "executed; this observation does not establish a component defect",
                ))
                continue
            if origin != "target_component":
                candidates.append(_candidate(
                    obs, "a process crash was observed, but the fatal stack does not "
                    "identify the requested component; attribution is inconclusive",
                ))
                continue
            if comp and comp.permission and not obs.detail.get("ordinary_caller_verified"):
                candidates.append(_candidate(
                    obs, f"{comp.name} requires {comp.permission}; an adb shell probe "
                    "does not demonstrate access from an ordinary app UID",
                ))
                continue

        # Gate 2 — a real effect.
        if obs.signal not in _MEANINGFUL and not obs.detail.get("logcat_sensitive_tokens"):
            rejected.append(_reject(obs, f"signal={obs.signal!r}: no observable effect"))
            continue

        # Gate 3 — a source -> sink -> chain story.
        story = _story(obs, comp)
        if story is None:
            candidates.append(_candidate(
                obs, "reachable and produced an effect, but no source->sink->chain "
                "could be stated automatically — needs manual adjudication",
            ))
            continue

        source, sink, chain = story

        # Same component + same probe kind + same outcome = one finding, many PoCs.
        key = _merge_key(obs)
        if key in merged:
            existing = merged[key]
            uri = obs.detail.get("uri") or _uri_from_command(obs)
            if uri and uri not in existing.evidence.setdefault("additional_uris", []):
                existing.evidence["additional_uris"].append(uri)
            existing.observations.append(obs.id)
            rows = obs.detail.get("row_count")
            if rows:
                existing.evidence["total_rows"] = existing.evidence.get("total_rows", 0) + rows
            continue

        seq += 1
        finding = Finding(
            id=f"F{seq:03d}",
            title=_title(obs, comp),
            severity=_severity_for(obs, comp),
            exploitability=_exploitability(obs),
            confidence="50%" if platform else "80%",
            attack_class=_attack_class(obs),
            component={
                "type": comp.type if comp else "unknown",
                "name": obs.component or "?",
                "exported": comp.exported if comp else False,
                "permission": (comp.read_permission or comp.permission) if comp else None,
            },
            reachable_from=obs.reachable_from,
            source=source,
            sink=sink,
            chain=chain,
            poc=" ".join(obs.command),
            impact=_impact(obs, comp),
            evidence={
                "observation_id": obs.id,
                "stdout_excerpt": obs.stdout_excerpt[:600],
                "logcat_excerpt": obs.logcat_excerpt[:600],
                "screenshot": obs.screenshot,
            },
            observations=[obs.id],
            cwe=_cwe(obs),
            notes="Reachability is inferred from the manifest, not from the probe's exit code. "
                  "The probe ran as the shell UID. Confirm the same effect from an ordinary "
                  "app UID before treating this as a demonstrated third-party exploit."
                  + (f"\n\nPLATFORM COMPONENT: {_PLATFORM_NOTE}" if platform else ""),
        )
        stable_key = "|".join((surface.package, obs.component or "", obs.kind,
                               obs.signal, str(sink)))
        finding.evidence["stable_id"] = "DR-" + hashlib.sha256(
            stable_key.encode("utf-8")
        ).hexdigest()[:12]
        if platform:
            finding.severity = _downgrade(finding.severity)
            finding.evidence["platform_by_design_caveat"] = True
        merged[key] = finding
        findings.append(finding)

    return TriageResult(findings=findings, candidates=candidates, rejected=rejected)


def _downgrade(sev: Severity) -> Severity:
    """One notch down — a platform package's exported surface is usually intentional."""
    order: list[Severity] = ["critical", "high", "medium", "low", "info"]
    return order[min(order.index(sev) + 1, len(order) - 1)]


def _title(obs: Observation, comp: Component | None) -> str:
    name = (obs.component or "component").split(".")[-1]
    if obs.kind in ("query_provider", "read_provider"):
        return f"Exported content provider {name} returns data to any app without permission"
    if obs.detail.get("logcat_sensitive_tokens"):
        return f"Credential-shaped material logged when {name} is triggered by an unprivileged app"
    if obs.signal == "crash":
        return f"Exported {comp.type if comp else 'component'} {name} crashes during component invocation"
    return f"{name}: {obs.signal}"


def _attack_class(obs: Observation) -> str:
    if obs.kind in ("query_provider", "read_provider", "call_provider"):
        return "Unprotected exported ContentProvider (data exposure)"
    if obs.kind == "deeplink":
        return "Deep-link entry point (intent redirection / auth bypass surface)"
    if obs.kind == "broadcast":
        return "Exported BroadcastReceiver (unauthenticated state change)"
    if obs.kind == "start_service":
        return "Exported Service (unauthenticated invocation)"
    return "Exported component (unauthenticated invocation)"


def _cwe(obs: Observation) -> str:
    if obs.kind in ("query_provider", "read_provider", "call_provider"):
        return "CWE-926: Improper Export of Android Application Components"
    if obs.detail.get("logcat_sensitive_tokens"):
        return "CWE-532: Insertion of Sensitive Information into Log File"
    if obs.signal == "crash":
        return "CWE-20: Improper Input Validation"
    return "CWE-926: Improper Export of Android Application Components"


def _impact(obs: Observation, comp: Component | None) -> str:
    if obs.kind in ("query_provider", "read_provider"):
        rows = obs.detail.get("row_count")
        qty = f"{rows} row(s)" if rows else "data"
        return (f"Any app installed on the device — with no permissions declared — can read "
                f"{qty} from {obs.detail.get('uri', 'this provider')}. No user interaction "
                f"and no prompt.")
    if obs.detail.get("logcat_sensitive_tokens"):
        return ("Credential-shaped values reach the system log, where they are readable by "
                "diagnostic tooling and by any process holding READ_LOGS.")
    if obs.signal == "crash":
        return (f"A shell probe triggered a crash in {obs.component}. The exported manifest "
                "entry suggests ordinary-app reachability, which needs separate reproduction.")
    return "See chain."
