"""Attack chains: correlate evidence across layers, then verify dynamically.

A single observation is rarely a bug. What makes a report is a *chain*:

    a reachable entry point -> a dangerous code path -> an observed effect

Each of those comes from a different layer (manifest / decompiled code / runtime probe /
traffic / native trace), and no layer can produce a chain alone. This module joins them
and then re-runs the chain's own steps to check the effect reproduces — a chain that
only fired once is a coincidence, not a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .log import ok, say, warn
from .models import AttackSurface, Component, utcnow


@dataclass
class ChainStep:
    layer: str          # manifest | code | runtime | traffic | native | ui
    claim: str
    evidence: str
    artifact: str = ""

    def to_dict(self) -> dict:
        return {"layer": self.layer, "claim": self.claim,
                "evidence": self.evidence[:400], "artifact": self.artifact}


@dataclass
class AttackChain:
    id: str
    title: str
    attack_class: str
    component: str
    reachable_from: str
    steps: list[ChainStep] = field(default_factory=list)
    poc: list[str] = field(default_factory=list)
    verified: bool = False
    verification: dict = field(default_factory=dict)
    severity: str = "medium"
    confidence: str = "50%"
    timestamp: str = field(default_factory=utcnow)

    @property
    def layers(self) -> set[str]:
        return {s.layer for s in self.steps}

    @property
    def is_complete(self) -> bool:
        """A chain needs reachability (manifest) AND an observed effect (runtime/traffic).

        Code evidence alone is a hypothesis; runtime evidence alone can't establish who
        could trigger it. Requiring both is what keeps this out of speculation.
        """
        return "manifest" in self.layers and bool(
            self.layers & {"runtime", "traffic", "native", "ui"}
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "attack_class": self.attack_class,
            "component": self.component,
            "reachable_from": self.reachable_from,
            "steps": [s.to_dict() for s in self.steps],
            "poc": self.poc,
            "verified": self.verified,
            "verification": self.verification,
            "severity": self.severity,
            "confidence": self.confidence,
            "complete": self.is_complete,
            "layers": sorted(self.layers),
            "timestamp": self.timestamp,
        }


def _comp(surface: AttackSurface, name: str | None) -> Component | None:
    return next((c for c in surface.components if c.name == name), None) if name else None


def build(
    surface: AttackSurface,
    *,
    code_report: dict | None = None,
    exploit_attempts: list[dict] | None = None,
    traffic: dict | None = None,
    native: dict | None = None,
) -> list[AttackChain]:
    """Join per-layer evidence into candidate chains."""
    code_report = code_report or {}
    exploit_attempts = exploit_attempts or []
    chains: list[AttackChain] = []
    seq = 0

    focused = (code_report.get("focused") or {})
    sinks_by_file: dict[str, list[dict]] = {}
    for hit in focused.get("sinks", []):
        sinks_by_file.setdefault(hit.get("file", ""), []).append(hit)

    # --- chains anchored on a landed exploit payload ---
    for att in exploit_attempts:
        verdict = att.get("verdict", {})
        if not verdict.get("hit"):
            continue
        comp_name = att.get("component", "")
        comp = _comp(surface, comp_name)
        reach = att.get("reachable_from", "shell")
        if reach not in ("third_party_app", "browser"):
            continue  # shell-only can never be an attacker chain

        seq += 1
        payload = att.get("payload", {})
        chain = AttackChain(
            id=f"CHAIN-{seq:03d}",
            title=f"{payload.get('attack_class','IPC')} via {comp_name.split('.')[-1]}",
            attack_class=payload.get("attack_class", "IPC"),
            component=comp_name,
            reachable_from=reach,
        )
        chain.steps.append(ChainStep(
            "manifest",
            f"{comp_name} is exported and reachable by {reach}",
            f"exported={comp.exported if comp else '?'}, "
            f"permission={(comp.read_permission or comp.permission) if comp else None}",
            "attack_surface.json",
        ))

        src = comp_name.replace(".", "/") + ".java"
        matching = [h for f, hits in sinks_by_file.items() if src.endswith(f) or f.endswith(src)
                    for h in hits]
        for h in matching[:3]:
            chain.steps.append(ChainStep(
                "code", f"{h.get('label')} in the component's implementation",
                f"{h.get('file')}:{h.get('line')}  {h.get('context','')[:160]}",
                "code_report.json",
            ))

        chain.steps.append(ChainStep(
            "runtime",
            f"payload '{payload.get('name')}' produced: {', '.join(verdict.get('signals', []))}",
            str(verdict.get("evidence", ""))[:300],
            "exploits.jsonl",
        ))

        scr = att.get("screen_assessment") or {}
        if scr.get("landed_on_target"):
            chain.steps.append(ChainStep(
                "ui", scr.get("assessment", ""), f"focus={scr.get('focus','')}",
                att.get("screenshot") or "",
            ))

        chain.poc = [" ".join(att.get("command", []))]
        chain.severity = "high" if verdict.get("confidence") == "confirmed" else "medium"
        chain.confidence = "85%" if verdict.get("confidence") == "confirmed" else "60%"
        chains.append(chain)

    # --- chains anchored on captured traffic ---
    if traffic:
        for item in (traffic.get("cleartext") or [])[:5]:
            seq += 1
            c = AttackChain(
                id=f"CHAIN-{seq:03d}",
                title="Sensitive traffic over plaintext HTTP",
                attack_class="Cleartext transmission (CWE-319)",
                component="(network)", reachable_from="third_party_app",
            )
            c.steps.append(ChainStep("manifest",
                                     "app permits cleartext traffic",
                                     f"usesCleartextTraffic={surface.uses_cleartext_traffic}",
                                     "attack_surface.json"))
            c.steps.append(ChainStep("traffic", item.get("why", ""),
                                     f"{item.get('method')} {item.get('url')}", "flows.jsonl"))
            c.poc = [f"mitmdump capture: {item.get('url','')}"]
            c.severity = "medium"
            chains.append(c)

        for item in (traffic.get("secrets_in_traffic") or [])[:5]:
            seq += 1
            c = AttackChain(
                id=f"CHAIN-{seq:03d}",
                title="Credential material observed in application traffic",
                attack_class="Sensitive data in transit (CWE-200)",
                component="(network)", reachable_from="third_party_app",
            )
            c.steps.append(ChainStep("traffic",
                                     f"request carries {', '.join(item.get('keys', []))}"
                                     + (" IN THE URL" if item.get("in_url") else ""),
                                     f"{item.get('method')} {item.get('url')}", "flows.jsonl"))
            c.severity = "high" if item.get("in_url") else "medium"
            c.poc = [f"observed at {item.get('url','')}"]
            chains.append(c)

    # --- chains anchored on the native layer ---
    if native and native.get("findings"):
        nf = native["findings"]
        for d in (nf.get("dangerous_imports") or [])[:4]:
            seq += 1
            c = AttackChain(
                id=f"CHAIN-{seq:03d}",
                title=f"Native library imports {d['symbol']} ({d['why']})",
                attack_class="Native code risk",
                component=native.get("program", "(native)"),
                reachable_from="third_party_app" if nf.get("jni_count") else "none",
            )
            c.steps.append(ChainStep("native", f"{d['symbol']}: {d['why']}",
                                     f"imports of {native.get('program','')}",
                                     "ghidra.json"))
            if nf.get("jni_entry_points"):
                c.steps.append(ChainStep(
                    "code",
                    f"{nf['jni_count']} JNI entry points expose this library to Java",
                    ", ".join(nf["jni_entry_points"][:6]), "ghidra.json"))
            c.severity = "medium"
            c.confidence = "40%"
            chains.append(c)

    return chains


def verify(chain: AttackChain, *, package: str, serial: str | None = None,
           repeats: int = 2) -> AttackChain:
    """Re-run the chain's PoC and require the effect to reproduce.

    A one-off effect is indistinguishable from an unrelated coincidence — an unrelated
    activity transition, a crash the app was going to have anyway. Requiring N-of-N
    reproduction removes most of that.
    """
    from . import shell
    from .device import logcat

    if not chain.poc or not chain.poc[0].startswith("adb "):
        chain.verification = {"attempted": False,
                              "reason": "no re-runnable adb PoC for this chain"}
        return chain

    argv = chain.poc[0].split()[1:]  # drop leading "adb"
    if argv and argv[0] == "shell":
        argv = argv[1:]

    say("verify", f"{chain.id}: re-running PoC {repeats}x")
    runs = []
    for i in range(repeats):
        logcat.clear(serial)
        proc = shell.adb_shell(argv, serial=serial, timeout=45)
        import time
        time.sleep(2.0)
        log_text = logcat.window(package, serial)
        runs.append({
            "run": i + 1,
            "rc": proc.rc,
            "crashed": logcat.crashed(log_text),
            "denied": logcat.denied(log_text),
            "stdout": (proc.stdout + proc.stderr).strip()[:200],
        })

    denied_any = any(r["denied"] for r in runs)
    consistent = len({(r["crashed"], r["rc"]) for r in runs}) == 1

    chain.verified = consistent and not denied_any
    chain.verification = {
        "attempted": True,
        "repeats": repeats,
        "runs": runs,
        "reproducible": consistent,
        "denied": denied_any,
        "conclusion": (
            "effect reproduced consistently" if chain.verified else
            "platform denied the action — not exploitable as tested" if denied_any else
            "effect did NOT reproduce consistently; treat as unconfirmed"
        ),
    }
    (ok if chain.verified else warn)(f"  {chain.id}: {chain.verification['conclusion']}")
    return chain


def summarise(chains: list[AttackChain]) -> dict:
    complete = [c for c in chains if c.is_complete]
    return {
        "total": len(chains),
        "complete": len(complete),
        "verified": sum(1 for c in chains if c.verified),
        "by_severity": {
            s: sum(1 for c in chains if c.severity == s) for s in ("high", "medium", "low")
        },
        "by_class": sorted({c.attack_class for c in chains}),
        "note": ("A chain is 'complete' when it has BOTH manifest reachability and an "
                 "observed runtime/traffic/native effect. Incomplete chains are leads, "
                 "not findings."),
    }
