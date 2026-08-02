"""Bounded audit digest.

The point of this module is what it *leaves out*. A real app yields 10k+ raw regex hits
and hundreds of observations; dumping that into an orchestrator's context is how you burn
a window and learn nothing. Everything here is top-N'd, and the full data stays on disk
behind an `artifact` pointer the reader can open on demand.

Ported from android-privesc-hunt/scripts/batch-auto.sh:78-162.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import AttackSurface, Finding, Observation
from .session import Session

TOP_N = 25
CHAR_BUDGET = 45_000  # ~15k tokens


def build(session: Session, *, top_n: int = TOP_N) -> dict:
    surface = session.read_surface()
    code = session.read_code_report() or {}
    observations = session.observations()
    findings = session.findings()

    doc: dict = {
        "package": session.package,
        "session_dir": str(session.dir),
        "artifacts": {
            "attack_surface": str(session.surface_path),
            "code_report": str(session.code_path),
            "observations": str(session.observations_path),
            "findings": str(session.findings_path),
            "dead_ends": str(session.dead_ends_path),
            "screenshots": str(session.screenshots),
            "storage": str(session.storage),
            "frida": str(session.dir / "frida"),
            "log": str(session.log_path),
        },
    }

    if surface:
        doc["verdict"] = code.get("verdict") or ""
        doc["summary"] = surface.summary()
        doc["app_issues"] = surface.app_issues
        doc["attack_surface_top"] = _top_components(surface, top_n)
        doc["permission_misconfigs"] = surface.permission_misconfigs[:10]
        doc["fileprovider_paths"] = [
            p for p in surface.fileprovider_paths if p.get("dangerous")
        ][:10]

    if code:
        doc["code_summary"] = code.get("summary", {})
        doc["code_focused"] = code.get("focused", {})
        pp = code.get("provider_paths", {})
        doc["provider_paths"] = pp.get("paths", {})
        doc["provider_floating_paths"] = pp.get("floating_paths", [])[:20]
        doc["provider_call_methods"] = pp.get("call_methods", [])[:20]

    doc["observations_summary"] = _observations_summary(observations)
    doc["interesting_observations"] = [
        _thin_observation(o) for o in observations if o.interesting
    ][:top_n]
    doc["findings"] = [_thin_finding(f) for f in findings][:top_n]

    return doc


def _top_components(surface: AttackSurface, top_n: int) -> list[dict]:
    """Third-party-reachable components first; those are the only ones an attacker has."""
    def rank(c) -> tuple:
        reach_rank = {"browser": 0, "third_party_app": 1, "shell": 2, "none": 3}
        return (reach_rank.get(c.reachable_from, 4), -len(c.issues))

    out = []
    for c in sorted(surface.components, key=rank)[:top_n]:
        out.append({
            "name": c.name,
            "type": c.type,
            "exported": c.exported,
            "exported_source": c.exported_source,
            "reachable_from": c.reachable_from,
            "permission": c.read_permission or c.permission,
            "authorities": c.authorities,
            "browsable": c.browsable,
            "deeplinks": c.deeplinks()[:5],
            "issues": c.issues,
        })
    return out


def _observations_summary(observations: list[Observation]) -> dict:
    by_kind: dict[str, int] = {}
    by_signal: dict[str, int] = {}
    by_reach: dict[str, int] = {}
    for o in observations:
        by_kind[o.kind] = by_kind.get(o.kind, 0) + 1
        by_signal[o.signal] = by_signal.get(o.signal, 0) + 1
        by_reach[o.reachable_from] = by_reach.get(o.reachable_from, 0) + 1
    return {
        "total": len(observations),
        "interesting": sum(1 for o in observations if o.interesting),
        "by_kind": by_kind,
        "by_signal": by_signal,
        "by_reachable_from": by_reach,
    }


def _thin_observation(o: Observation) -> dict:
    return {
        "id": o.id,
        "kind": o.kind,
        "component": o.component,
        "reachable_from": o.reachable_from,
        "signal": o.signal,
        "command": " ".join(o.command),
        "stdout_excerpt": o.stdout_excerpt[:300],
        "detail": {k: v for k, v in o.detail.items() if k != "sample"},
        "screenshot": o.screenshot,
    }


def _thin_finding(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "exploitability": f.exploitability,
        "reachable_from": f.reachable_from,
        "attack_class": f.attack_class,
        "component": f.component,
        "chain": f.chain,
        "poc": f.poc,
        "impact": f.impact,
        "cwe": f.cwe,
        "confidence": f.confidence,
        "additional_pocs": f.evidence.get("additional_uris", []),
        "platform_caveat": bool(f.evidence.get("platform_by_design_caveat")),
        "notes": f.notes,
        "observations": f.observations,
    }


# ---- markdown rendering ----

def to_markdown(doc: dict) -> str:
    L: list[str] = []
    a = L.append

    a(f"# droid-recon — {doc['package']}\n")
    if doc.get("verdict"):
        a(f"**Triage:** {doc['verdict']}\n")

    s = doc.get("summary")
    if s:
        a("## Attack surface\n")
        a(f"- Components: **{s['total_components']}** "
          f"({s['activities']} activities, {s['services']} services, "
          f"{s['receivers']} receivers, {s['providers']} providers)")
        a(f"- Exported: **{s['exported_components']}**")
        a(f"- **Reachable by a third-party app or the browser: {s['reachable_third_party']}** "
          f"← the only ones an attacker actually has")
        flags = [k for k in ("debuggable", "allow_backup", "has_browsable",
                             "has_send_target", "has_grant_uri") if s.get(k)]
        if flags:
            a(f"- Flags: {', '.join(flags)}")
        a("")

    if doc.get("app_issues"):
        a("### Application-level issues\n")
        for issue in doc["app_issues"]:
            a(f"- {issue}")
        a("")

    comps = [c for c in doc.get("attack_surface_top", [])
             if c["reachable_from"] in ("third_party_app", "browser")]
    if comps:
        a("### Third-party-reachable components\n")
        a("| Component | Type | Reach | Guard | Issues |")
        a("|---|---|---|---|---|")
        for c in comps[:20]:
            issues = "; ".join(c["issues"])[:110] or "—"
            a(f"| `{c['name'].split('.')[-1]}` | {c['type']} | {c['reachable_from']} | "
              f"{c['permission'] or '—'} | {issues} |")
        a("")

    pp = doc.get("provider_paths") or {}
    floating = doc.get("provider_floating_paths") or []
    calls = doc.get("provider_call_methods") or []
    if pp or floating or calls:
        a("### Provider surface recovered from code\n")
        if pp:
            a("`UriMatcher.addURI` literals, attributed to their declared authority:\n")
            for auth, paths in list(pp.items())[:10]:
                a(f"- `{auth}` → {', '.join(paths[:12])}")
            a("")
        if floating:
            a(f"Paths from an `addURI` whose authority could not be resolved "
              f"(**not attributable to any specific provider** — probed against all): "
              f"{', '.join(f'`{p}`' for p in floating[:12])}\n")
        if calls:
            a(f"`ContentProvider.call()` methods — a separate entry point that bypasses "
              f"the UriMatcher and is often unguarded when `query()` is not: "
              f"{', '.join(f'`{m}`' for m in calls[:12])}\n")

    if doc.get("fileprovider_paths"):
        a("### Dangerous FileProvider declarations\n")
        for p in doc["fileprovider_paths"]:
            a(f"- `<{p['type']} path=\"{p['path']}\"/>` in {p['file']} — {p.get('why', '')}")
        a("")

    cs = doc.get("code_summary")
    if cs:
        a("## Code sweep\n")
        a(f"- Files scanned: {cs.get('files_scanned', 0)}")
        a(f"- Sink hits: {cs.get('sink_hits', 0)} "
          f"(**{cs.get('sink_hits_app', 0)} outside bundled libraries**)")
        a(f"- Source hits: {cs.get('source_hits', 0)} "
          f"({cs.get('source_hits_app', 0)} outside libraries)")
        if cs.get("secrets"):
            a(f"- **Secret-shaped literals: {cs['secrets']}**")
        if cs.get("local_servers"):
            a(f"- Local servers: {cs['local_servers']}")
        lottie_stacks = cs.get("lottie_stacks") or []
        if lottie_stacks:
            a(f"- Lottie stacks: {', '.join(f'`{name}`' for name in lottie_stacks)}")
            if cs.get("lottie_attacker_influenced_delivery"):
                a("- **Attacker-influenced Lottie delivery candidate: yes** "
                  "(runtime confirmation required)")
            else:
                a("- Attacker-influenced Lottie delivery candidate: not found by the "
                  "bounded static pass")
        a("")

    focused = doc.get("code_focused", {})
    top_sinks = [h for h in focused.get("sinks", []) if h.get("in_exported_component")][:12]
    if top_sinks:
        a("### Sinks inside exported components\n")
        for h in top_sinks:
            a(f"- `{h['file']}:{h['line']}` — **{h['label']}**")
            a(f"  `{h['context'][:150]}`")
        a("")
    if focused.get("secrets"):
        a("### Secret-shaped literals\n")
        for h in focused["secrets"][:10]:
            a(f"- `{h['file']}:{h['line']}` — {h['label']}")
        a("")

    os_ = doc.get("observations_summary", {})
    if os_.get("total"):
        a("## Dynamic probes\n")
        a(f"- Observations: **{os_['total']}** ({os_['interesting']} flagged interesting)")
        a(f"- By signal: {_kv(os_.get('by_signal', {}))}")
        a(f"- By reachability: {_kv(os_.get('by_reachable_from', {}))}")
        a("")
        a("> Probes run as the **shell UID**, which holds `START_ANY_ACTIVITY`. "
          "A probe that succeeds against a `shell`-only component proves nothing — "
          "reachability comes from the manifest, not the exit code.\n")

    interesting = doc.get("interesting_observations", [])
    if interesting:
        a("### Interesting observations\n")
        for o in interesting[:15]:
            a(f"- **{o['id']}** `{o['kind']}` → {o['signal']} "
              f"(reach: {o['reachable_from']}) — `{o['component'] or ''}`")
            a(f"  `{o['command']}`")
            if o.get("stdout_excerpt"):
                a(f"  ```\n  {o['stdout_excerpt'][:200]}\n  ```")
        a("")

    findings = doc.get("findings", [])
    a(f"## Findings ({len(findings)})\n")
    if not findings:
        a("_No observation passed all three triage gates "
          "(third-party reachable + real effect + source→sink→chain)._\n")
    for f in findings:
        a(f"### {f['id']} — {f['title']}\n")
        a(f"**{f['severity'].upper()}** · {f['exploitability']} · reach: `{f['reachable_from']}` "
          f"· confidence {f.get('confidence', '?')} · {f['cwe']}\n")
        a(f"**Component:** `{f['component'].get('name')}` ({f['component'].get('type')})\n")

        if f.get("platform_caveat"):
            a("> ⚠️ **Platform component — likely by design.** This package runs under a "
              "platform shared UID, so its exported surface is often documented API rather "
              "than a mistake. Severity has been downgraded one notch and confidence halved. "
              "Verify against the platform documentation before treating this as a bug.\n")

        a("**Chain:**\n")
        for i, step in enumerate(f["chain"], 1):
            a(f"{i}. {step}")
        a(f"\n**PoC:** `{f['poc']}`\n")
        extra = f.get("additional_pocs") or []
        if extra:
            a(f"**Also reproduces on {len(extra)} further URI(s)** "
              f"(merged into this finding rather than filed separately):\n")
            for uri in extra[:10]:
                a(f"- `{uri}`")
            a("")
        a(f"**Impact:** {f['impact']}\n")
        if f.get("observations"):
            a(f"_Observations: {', '.join(f['observations'][:8])}_\n")

    a("## Artifacts\n")
    for k, v in doc.get("artifacts", {}).items():
        a(f"- `{k}`: {v}")

    text = "\n".join(L)
    if len(text) > CHAR_BUDGET:
        text = text[:CHAR_BUDGET] + (
            f"\n\n_[report truncated at {CHAR_BUDGET} chars — "
            f"full data in the artifacts listed above]_\n"
        )
    return text


def _kv(d: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(d.items(), key=lambda kv: -kv[1])) or "—"


def write(session: Session, *, top_n: int = TOP_N) -> tuple[Path, Path, dict]:
    doc = build(session, top_n=top_n)
    json_path = session.dir / "report.json"
    md_path = session.dir / "report.md"
    json_path.write_text(json.dumps(doc, indent=2))
    md_path.write_text(to_markdown(doc))
    return md_path, json_path, doc
