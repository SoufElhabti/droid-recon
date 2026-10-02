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

from . import android_versions, standards
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
            "coverage": str(session.coverage_path),
            "evidence_manifest": str(session.evidence_path),
            "observations": str(session.observations_path),
            "findings": str(session.findings_path),
            "ordinary_results": str(session.dir / "ordinary_results.jsonl"),
            "dead_ends": str(session.dead_ends_path),
            "screenshots": str(session.screenshots),
            "storage": str(session.storage),
            "log": str(session.log_path),
        },
    }

    doc["coverage"] = session.coverage_summary(top_n=top_n)
    doc["standards_mapping"] = standards.metadata()
    evidence = session.read_evidence_manifest()
    if evidence:
        doc["evidence_summary"] = _evidence_summary(evidence)

    if surface:
        doc["verdict"] = code.get("verdict") or ""
        doc["summary"] = surface.summary()
        doc["app_issues"] = surface.app_issues
        doc["attack_surface_top"] = _top_components(surface, top_n)
        doc["permission_misconfigs"] = surface.permission_misconfigs[:10]
        doc["fileprovider_paths"] = [
            p for p in surface.fileprovider_paths if p.get("dangerous")
        ][:10]
        device_context = evidence.get("sdk") if evidence else None
        doc["android_version_caveats"] = android_versions.version_caveats(
            surface, device_context,
        )
        _annotate_coverage(doc["coverage"], surface)

    if code:
        doc["code_summary"] = code.get("summary", {})
        doc["code_focused"] = code.get("focused", {})
        extras = code.get("intent_extras") or {}
        inputs = [
            {"component": component, **entry}
            for component, entries in sorted((extras.get("by_component") or {}).items())
            for entry in entries
        ]
        doc["intent_input_summary"] = {
            "components": len(extras.get("by_component") or {}),
            "unique_keys": len(extras.get("global_keys") or []),
            "entries": len(inputs),
            "defaults_observed": sum(entry.get("default_status") == "literal"
                                     for entry in inputs),
            "validation_evidence_observed": sum(bool(entry.get("validation_evidence"))
                                                for entry in inputs),
        }
        doc["intent_inputs"] = inputs[:top_n]
        doc["intent_inputs_omitted"] = max(0, len(inputs) - top_n)
        flows = code.get("flow_candidates") or {}
        doc["flow_summary"] = flows.get("summary", {})
        doc["flow_candidates"] = [
            standards.annotate_flow_candidate(candidate)
            for candidate in (flows.get("candidates") or [])[:top_n]
        ]
        doc["flow_missing_components"] = (flows.get("missing_components") or [])[:top_n]
        pp = code.get("provider_paths", {})
        doc["provider_paths"] = pp.get("paths", {})
        doc["provider_floating_paths"] = pp.get("floating_paths", [])[:20]
        doc["provider_call_methods"] = pp.get("call_methods", [])[:20]

    doc["observations_summary"] = _observations_summary(observations)
    ordinary_path = session.dir / "ordinary_results.jsonl"
    if ordinary_path.is_file():
        doc["ordinary_caller_summary"] = _ordinary_summary(ordinary_path, top_n)
    doc["interesting_observations"] = [
        _thin_observation(o) for o in observations if o.interesting
    ][:top_n]
    doc["finding_count"] = len(findings)
    doc["findings"] = [_thin_finding(f) for f in findings][:top_n]
    doc["findings_omitted"] = max(0, len(findings) - len(doc["findings"]))

    return doc


def _annotate_coverage(summary: dict, surface: AttackSurface) -> None:
    """Map recorded checks only; the mapping never changes a result state."""
    component_types = {c.name: c.type for c in surface.components}
    for entry in summary.get("entries", []):
        stage = entry.get("stage")
        check_id = None
        if stage == "manifest":
            kind = component_types.get(entry.get("component"))
            if kind == "activity-alias":
                kind = "activity"
            if kind in ("activity", "service", "receiver", "provider"):
                check_id = f"manifest.{kind}"
        elif stage == "ipc":
            check_id = "dynamic.component_probe"
        elif stage == "ordinary_uid":
            check_id = "dynamic.ordinary_caller"
        if check_id:
            entry["standards"] = standards.for_check(check_id)


def _evidence_summary(evidence: dict) -> dict:
    """Keep identifying context visible without duplicating the full manifest."""
    apks = evidence.get("apks") or []
    device = evidence.get("device") or {}
    return {
        "generated_at": evidence.get("generated_at"),
        "app_version": evidence.get("app_version"),
        "sdk": evidence.get("sdk"),
        "execution_contexts": evidence.get("execution_contexts") or [],
        "device": {key: device.get(key) for key in (
            "serial", "release", "build_type", "product", "abi", "is_root",
            "webview_package",
        ) if key in device},
        "apk_count": len(apks),
        "apks": [{
            "name": Path(apk.get("path") or "").name,
            "sha256": apk.get("sha256"),
            "signing_certificate": apk.get("signing_certificate"),
        } for apk in apks[:8]],
        "apks_omitted": max(0, len(apks) - 8),
    }


def _top_components(surface: AttackSurface, top_n: int) -> list[dict]:
    """Rank manifest-reachable components first; runtime access needs validation."""
    def rank(c) -> tuple:
        reach_rank = {"browser": 0, "third_party_app": 1, "shell": 2, "none": 3}
        reach = ("third_party_app" if c.type == "provider" and c.publicly_reachable
                 else c.reachable_from)
        return (reach_rank.get(reach, 4), -len(c.issues))

    out = []
    for c in sorted(surface.components, key=rank)[:top_n]:
        out.append({
            "name": c.name,
            "type": c.type,
            "exported": c.exported,
            "exported_source": c.exported_source,
            "reachable_from": c.reachable_from,
            "publicly_reachable": c.publicly_reachable,
            "provider_reach": ({operation: c.provider_reach(operation)
                                for operation in ("read", "write", "call")}
                               if c.type == "provider" else None),
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


def _ordinary_summary(path: Path, top_n: int) -> dict:
    """Summarize bounded caller evidence without retaining provider row values."""
    counts = {"accessible": 0, "denied": 0, "inconclusive": 0}
    by_status: dict[str, int] = {}
    examples: list[dict] = []
    total = 0
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            total += 1
            accessible = (item.get("accessible")
                          if item.get("verified_ordinary_uid") is True else None)
            category = ("accessible" if accessible is True else
                        "denied" if accessible is False else "inconclusive")
            counts[category] += 1
            status = str(item.get("status") or "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            if len(examples) < top_n:
                examples.append({
                    "component": item.get("component"),
                    "declared_component": item.get("declared_component"),
                    "resolution_scope": item.get("resolution_scope") or "component",
                    "operation": item.get("operation"),
                    "status": status,
                    "accessible": accessible,
                    "verified_ordinary_uid": item.get("verified_ordinary_uid") is True,
                    "request_id": item.get("request_id"),
                })
    return {"total": total, **counts, "by_status": by_status,
            "examples": examples, "examples_omitted": max(0, total - len(examples))}


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
        "stable_id": f.evidence.get("stable_id"),
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

    evidence = doc.get("evidence_summary")
    if evidence:
        a("## Reproduction context\n")
        version = evidence.get("app_version") or {}
        sdk = evidence.get("sdk") or {}
        device = evidence.get("device") or {}
        a(f"- App version: {version.get('name') or 'unknown'} "
          f"(code {version.get('code') if version.get('code') is not None else 'unknown'})")
        a(f"- SDK: min {sdk.get('min') or 'unknown'}, target {sdk.get('target') or 'unknown'}, "
          f"device {sdk.get('device') or 'unknown'}")
        a(f"- Execution context: {', '.join(evidence.get('execution_contexts') or []) or 'unknown'}")
        if device:
            a(f"- Device: {device.get('product') or 'unknown'} "
              f"(Android {device.get('release') or 'unknown'}, "
              f"{device.get('build_type') or 'unknown'} build); "
              f"WebView {device.get('webview_package') or 'unknown'}")
        a(f"- APKs: {evidence.get('apk_count', 0)}; hashes and signing certificate details "
          "are in `evidence_manifest` below.\n")

    cov = doc.get("coverage") or {}
    a("## Coverage (recorded checks only)\n")
    if not cov.get("total_checks"):
        a("_No checks have been recorded in the coverage ledger. The report cannot infer what was tested._\n")
    else:
        a("Only checks explicitly recorded in the ledger appear here; unlisted checks have unknown coverage.\n")
        a("| Stage | Tested | Skipped | Unsupported | Failed |")
        a("|---|---:|---:|---:|---:|")
        for stage in cov.get("stages", []):
            counts = stage["by_status"]
            a(f"| {stage['stage']} | {counts['tested']} | {counts['skipped']} | "
              f"{counts['unsupported']} | {counts['failed']} |")
        a("")

        states = cov.get("by_result_state", {})
        active_states = [f"{state}={count}" for state, count in states.items() if count]
        if active_states:
            a(f"Evidence states: {', '.join(active_states)}.\n")

        gaps = [e for e in cov.get("entries", []) if e["status"] != "tested"]
        if gaps:
            a("### Coverage gaps\n")
            for entry in gaps:
                scope = "/".join(filter(None, (entry["stage"], entry.get("component"), entry.get("check"))))
                reason = " ".join((entry.get("reason") or "").split())[:300]
                a(f"- `{scope}`: **{entry['status']}** ({entry.get('result_state') or 'unclassified'}) — {reason}")
            a("")

        if cov.get("entries_omitted"):
            a(f"{cov['entries_omitted']} further check(s) are in the coverage artifact.\n")

        a("### Evidence state meanings\n")
        for state, meaning in cov.get("result_state_definitions", {}).items():
            a(f"- **{state}:** {meaning}")
        a("")

    mapping = doc.get("standards_mapping") or {}
    if mapping:
        a("### OWASP cross-reference\n")
        a(f"Mapping catalog: `{mapping.get('catalog_version', 'unknown')}` "
          f"(checked {mapping.get('checked_on', 'unknown')}). "
          "References for mapped checks are in the JSON report. "
          "A mapping alone does not verify an OWASP control or test.\n")

    caveats = doc.get("android_version_caveats") or []
    if caveats:
        a("## Android version caveats\n")
        for caveat in caveats:
            components = caveat.get("components") or []
            scope = f" ({', '.join(f'`{name}`' for name in components[:5])})" if components else ""
            a(f"- **{caveat['id']}**{scope}: {caveat['message']} "
              f"[Android documentation]({caveat['source']}).")
        a("")

    s = doc.get("summary")
    if s:
        a("## Attack surface\n")
        a(f"- Components: **{s['total_components']}** "
          f"({s['activities']} activities, {s['services']} services, "
          f"{s['receivers']} receivers, {s['providers']} providers)")
        a(f"- Exported: **{s['exported_components']}**")
        a(f"- **Manifest candidates for third-party app or browser access: "
          f"{s['reachable_third_party']}** (runtime access needs validation)")
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

    comps = [c for c in doc.get("attack_surface_top", []) if c["publicly_reachable"]]
    if comps:
        a("### Third-party-reachable components\n")
        a("| Component | Type | Reach | Guard | Issues |")
        a("|---|---|---|---|---|")
        for c in comps[:20]:
            issues = "; ".join(c["issues"])[:110] or "—"
            reach = (", ".join(f"{op}={value}" for op, value in c["provider_reach"].items())
                     if c.get("provider_reach") else c["reachable_from"])
            a(f"| `{c['name'].split('.')[-1]}` | {c['type']} | {reach} | "
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

    inputs = doc.get("intent_inputs") or []
    if inputs:
        summary = doc["intent_input_summary"]
        a("### Extracted Intent inputs\n")
        a(f"{summary['unique_keys']} unique key(s) across {summary['components']} "
          f"component(s); {summary['defaults_observed']} literal default(s) and "
          f"{summary['validation_evidence_observed']} nearby validation check(s) observed.\n")
        a("| Component | Key / type | Default | Validation evidence | Source |")
        a("|---|---|---|---|---|")
        for entry in inputs[:15]:
            default = entry.get("default") or {}
            default_label = (str(default.get("literal"))[:45]
                             if entry.get("default_status") == "literal" else
                             str(entry.get("default_status") or "unknown"))
            validation = entry.get("validation_evidence") or []
            validation_label = (", ".join(item.get("check", "check") for item in validation[:2])
                                if validation else "not observed")
            a(f"| `{entry['component'].split('.')[-1]}` | "
              f"`{entry.get('key', '?')}` / {entry.get('type', 'unknown')} | "
              f"`{default_label}` | {validation_label} | "
              f"`{entry.get('source', '?')}:{entry.get('line', '?')}` |")
        if doc.get("intent_inputs_omitted"):
            a(f"\n{doc['intent_inputs_omitted']} more entry/entries are in `code_report`.\n")
        a("\n_Nearby checks are evidence for review; their effectiveness is unverified._\n")

    flow_summary = doc.get("flow_summary") or {}
    if flow_summary:
        a("### Input-to-sink candidates (static review queue)\n")
        a(f"- Reachable components scanned: {flow_summary.get('components_scanned', 0)}"
          f" / {flow_summary.get('reachable_components', 0)}")
        a(f"- Candidates: {flow_summary.get('candidates', 0)} "
          f"({flow_summary.get('no_guard_seen', 0)} with no nearby guard seen)")
        for candidate in doc.get("flow_candidates", [])[:12]:
            source = candidate["source"]
            sink = candidate["sink"]
            a(f"- `{candidate['component']}`: `{candidate['file']}:{source['line']}` "
              f"→ `{sink['api']}` at line {sink['line']} "
              f"({candidate['review_bucket']})")
        missing = doc.get("flow_missing_components") or []
        if missing:
            a(f"- Source unavailable for {len(missing)} component(s) in the displayed set; "
              "see `code_report.json` for the complete limit and reasons.")
        a("\n_These are lexical candidates; validation and runtime effect require review._\n")

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

    ordinary = doc.get("ordinary_caller_summary") or {}
    if ordinary.get("total"):
        a("## Ordinary app caller checks\n")
        a(f"- Probes: {ordinary['total']}; OS accepted/query returned: "
          f"{ordinary['accessible']}; denied/not found: {ordinary['denied']}; "
          f"inconclusive: {ordinary['inconclusive']}.")
        a("- Calls originated in a separate app UID with no requested permissions. "
          "OS access alone does not prove a sensitive effect.\n")
        for item in ordinary.get("examples", [])[:10]:
            identity = (item.get("component") or
                        f"{item.get('declared_component') or 'implicit'} (package-level resolution)")
            a(f"- `{identity}` "
              f"`{item.get('operation') or 'unknown'}`: {item['status']} "
              f"(request `{item.get('request_id') or '?'}`).")
        if ordinary.get("examples_omitted"):
            a(f"- {ordinary['examples_omitted']} more result(s) in `ordinary_results`.\n")
        a("")

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
    a(f"## Findings ({doc.get('finding_count', len(findings))})\n")
    if not doc.get("finding_count", len(findings)):
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

    if doc.get("findings_omitted"):
        a(f"_{doc['findings_omitted']} additional finding(s) are in `findings`._\n")

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
    json_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    md_path.write_text(to_markdown(doc), encoding="utf-8")
    return md_path, json_path, doc
