"""Regex sweep over the decompiled tree + triage verdict.

Ported from android-privesc-hunt/scripts/pre-analyze.sh:236-298.

The output of a naive sweep on a real app is tens of thousands of hits, 95% of them in
bundled libraries. Two filters make it usable: library-path exclusion, and a `focused`
view restricted to files that plausibly implement an exported component.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..log import say
from ..models import AttackSurface
from . import patterns as P


@dataclass
class Hit:
    file: str
    line: int
    label: str
    context: str
    library: bool = False

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "label": self.label,
            "context": self.context,
            "library": self.library,
        }


@dataclass
class CodeReport:
    sink_hits: list[Hit] = field(default_factory=list)
    source_hits: list[Hit] = field(default_factory=list)
    local_servers: list[Hit] = field(default_factory=list)
    secrets: list[Hit] = field(default_factory=list)
    provider_paths: dict = field(default_factory=dict)
    lottie: dict = field(default_factory=dict)
    files_scanned: int = 0

    def app_only(self, hits: list[Hit]) -> list[Hit]:
        return [h for h in hits if not h.library]

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "sink_hits": [h.to_dict() for h in self.sink_hits],
            "source_hits": [h.to_dict() for h in self.source_hits],
            "local_servers": [h.to_dict() for h in self.local_servers],
            "secrets": [h.to_dict() for h in self.secrets],
            "provider_paths": self.provider_paths,
            "lottie": self.lottie,
            "summary": self.summary(),
        }

    def summary(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "sink_hits": len(self.sink_hits),
            "sink_hits_app": len(self.app_only(self.sink_hits)),
            "source_hits": len(self.source_hits),
            "source_hits_app": len(self.app_only(self.source_hits)),
            "local_servers": len(self.local_servers),
            "secrets": len(self.secrets),
            "provider_authorities_with_paths": len(self.provider_paths.get("paths", {})),
            "lottie_stacks": (self.lottie.get("summary") or {}).get("stacks_present", []),
            "lottie_attacker_influenced_delivery": bool(
                (self.lottie.get("summary") or {}).get("attacker_influenced_delivery")
            ),
        }


def _component_source_hints(surface: AttackSurface) -> set[str]:
    """Relative jadx paths that would hold an exported component's implementation."""
    hints: set[str] = set()
    for c in surface.components:
        if not c.exported:
            continue
        hints.add(c.name.replace(".", "/") + ".java")
        if c.target_activity:
            hints.add(c.target_activity.replace(".", "/") + ".java")
    return hints


def sweep(tree: Path, surface: AttackSurface, *, context_chars: int = 60,
          max_hits_per_label: int = 200) -> CodeReport:
    report = CodeReport()
    tables = (
        (P.SINKS_RE, report.sink_hits),
        (P.SOURCES_RE, report.source_hits),
        (P.SERVERS_RE, report.local_servers),
        (P.SECRETS_RE, report.secrets),
    )
    label_counts: dict[str, int] = {}

    for java in tree.rglob("*.java"):
        # jadx paths in reports use '/' on every host so component hints match on Windows.
        rel = java.relative_to(tree).as_posix()
        is_lib = P.is_library_path(rel)
        try:
            content = java.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        report.files_scanned += 1

        for compiled, bucket in tables:
            for rx, label in compiled:
                for m in rx.finditer(content):
                    key = f"{label}|{is_lib}"
                    if label_counts.get(key, 0) >= max_hits_per_label:
                        break
                    label_counts[key] = label_counts.get(key, 0) + 1
                    line_no = content.count("\n", 0, m.start()) + 1
                    lo = max(0, m.start() - context_chars)
                    hi = min(len(content), m.end() + context_chars)
                    ctx = " ".join(content[lo:hi].split())
                    bucket.append(Hit(rel, line_no, label, ctx[:200], is_lib))

    say("code", f"swept {report.files_scanned} files: "
                f"{len(report.sink_hits)} sinks / {len(report.source_hits)} sources "
                f"({len(report.app_only(report.sink_hits))} sinks outside libraries)")
    return report


def focused(report: CodeReport, surface: AttackSurface, top_n: int = 40) -> dict:
    """Bounded view for an orchestrator: only hits in exported-component files.

    Ported from batch-auto.sh:126-161. This is what keeps report output inside a
    context window on an app with 10k+ raw hits.
    """
    hints = _component_source_hints(surface)

    def relevant(hits: list[Hit]) -> list[dict]:
        scored = []
        for h in hits:
            if h.library:
                continue
            direct = any(h.file.endswith(x) for x in hints)
            scored.append((0 if direct else 1, h))
        scored.sort(key=lambda t: t[0])
        return [h.to_dict() | {"in_exported_component": rank == 0} for rank, h in scored[:top_n]]

    return {
        "sinks": relevant(report.sink_hits),
        "sources": relevant(report.source_hits),
        "servers": [h.to_dict() for h in report.local_servers[:10]],
        "secrets": [h.to_dict() for h in report.secrets[:20]],
    }


def verdict(surface: AttackSurface, report: CodeReport | None = None) -> str:
    """Single-line triage string. Ported from pre-analyze.sh:284-298."""
    s = surface.summary()
    reachable = s["reachable_third_party"]

    if s["exported_components"] == 0:
        return "SKIP — no exported components"
    if reachable == 0:
        return (f"LOW — {s['exported_components']} exported components, but all are "
                f"signature/system-permission guarded (not reachable by a third-party app)")

    signals: list[str] = []
    if s["has_browsable"]:
        signals.append("browsable")
    if s["has_send_target"]:
        signals.append("SEND target")
    if s["has_grant_uri"]:
        signals.append("grantUriPermissions")
    if s["providers_write_reachable"]:
        signals.append(f"{s['providers_write_reachable']} writable provider(s)")
    if s["providers_call_reachable"]:
        signals.append(f"{s['providers_call_reachable']} callable provider(s)")
    if s["permission_misconfigs"]:
        signals.append(f"{s['permission_misconfigs']} perm misconfigs")
    if s["debuggable"]:
        signals.append("debuggable")
    if s["native_libs"]:
        signals.append(f"{s['native_libs']} native libs")
    if report is not None:
        app_sinks = len(report.app_only(report.sink_hits))
        if app_sinks:
            signals.append(f"{app_sinks} sink hits")
        if report.secrets:
            signals.append(f"{len(report.secrets)} secret hits")
        n_auth = len(report.provider_paths.get("paths", {}))
        if n_auth:
            signals.append(f"{n_auth} provider authorities with known paths")

    if not signals:
        return (f"LOW — {reachable} third-party-reachable components but no "
                f"interesting sinks/sources/patterns")
    return f"INVESTIGATE — {reachable} third-party-reachable, " + ", ".join(signals)
