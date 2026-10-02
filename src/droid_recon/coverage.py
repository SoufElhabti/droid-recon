"""Recorded audit coverage, separate from vulnerability findings.

Each event describes one stage/check/component combination. The latest event for a
combination is its current status; older events remain in the JSONL artifact so a
reviewer can see whether a blocked check was later completed. No entry is inferred
for work that the caller did not record.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .models import utcnow


STATUSES = ("tested", "skipped", "unsupported", "failed")
RESULT_STATES = (
    "STATIC_CANDIDATE", "OBSERVED", "CONFIRMED", "INCONCLUSIVE",
    "BLOCKED", "NOT_TESTED",
)
RESULT_STATE_DEFINITIONS = {
    "STATIC_CANDIDATE": "Source or configuration suggests a possible issue; no runtime effect is established.",
    "OBSERVED": "A runtime signal was seen; reachability, impact, or the attack chain remains unproven.",
    "CONFIRMED": "A reachable entry point, real effect, and source-to-sink attack chain are evidenced.",
    "INCONCLUSIVE": "The check ran but available evidence does not support a conclusion.",
    "BLOCKED": "A prerequisite or execution failure prevented the check from completing.",
    "NOT_TESTED": "The check was not attempted, including skipped or unsupported checks.",
}
_DEFAULT_RESULT_STATE = {
    "skipped": "NOT_TESTED",
    "unsupported": "NOT_TESTED",
    "failed": "BLOCKED",
}


@dataclass(frozen=True)
class CoverageEntry:
    stage: str
    status: str
    component: str | None = None
    check: str | None = None
    reason: str | None = None
    result_state: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    recorded_at: str = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        if not self.stage or not self.stage.strip():
            raise ValueError("coverage stage is required")
        if self.status not in STATUSES:
            raise ValueError(f"invalid coverage status: {self.status!r}")
        if self.status != "tested" and not (self.reason and self.reason.strip()):
            raise ValueError(f"coverage reason is required for {self.status}")
        if self.result_state is not None and self.result_state not in RESULT_STATES:
            raise ValueError(f"invalid coverage result state: {self.result_state!r}")
        if self.result_state == "CONFIRMED" and not self.evidence_ids:
            raise ValueError("CONFIRMED coverage requires evidence IDs")

    @property
    def key(self) -> tuple[str, str | None, str | None]:
        return self.stage, self.component, self.check

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> CoverageEntry:
        return cls(
            stage=value["stage"],
            status=value["status"],
            component=value.get("component"),
            check=value.get("check"),
            reason=value.get("reason"),
            result_state=value.get("result_state"),
            evidence_ids=list(value.get("evidence_ids") or []),
            recorded_at=value.get("recorded_at") or utcnow(),
        )


def make_entry(
    stage: str,
    status: str,
    *,
    component: str | None = None,
    check: str | None = None,
    reason: str | None = None,
    result_state: str | None = None,
    evidence_ids: list[str] | None = None,
) -> CoverageEntry:
    """Validate one event and assign a conservative result state where appropriate."""
    return CoverageEntry(
        stage=stage.strip(),
        status=status,
        component=component.strip() if component else None,
        check=check.strip() if check else None,
        reason=reason.strip() if reason else None,
        result_state=result_state or _DEFAULT_RESULT_STATE.get(status),
        evidence_ids=list(dict.fromkeys(evidence_ids or [])),
    )


def latest_entries(events: list[dict]) -> list[CoverageEntry]:
    """Reduce an append-only event stream to its current per-check view."""
    latest: dict[tuple[str, str | None, str | None], CoverageEntry] = {}
    for raw in events:
        try:
            entry = CoverageEntry.from_dict(raw)
        except (KeyError, TypeError, ValueError):
            continue
        latest[entry.key] = entry
    return list(latest.values())


def summarize(events: list[dict], *, top_n: int = 25) -> dict:
    """Return a bounded, explicitly recorded-only matrix for the report."""
    entries = latest_entries(events)
    by_status = {status: 0 for status in STATUSES}
    by_result_state = {state: 0 for state in RESULT_STATES}
    stages: dict[str, dict] = {}
    for entry in entries:
        by_status[entry.status] += 1
        if entry.result_state:
            by_result_state[entry.result_state] += 1
        row = stages.setdefault(entry.stage, {
            "stage": entry.stage,
            "total": 0,
            "by_status": {status: 0 for status in STATUSES},
        })
        row["total"] += 1
        row["by_status"][entry.status] += 1

    # Put gaps first, then substantive signals, then completed checks. The full
    # ledger remains available through the artifact path.
    priority = {"failed": 0, "unsupported": 1, "skipped": 2, "tested": 3}
    ordered = sorted(entries, key=lambda e: (
        priority[e.status], e.stage, e.component or "", e.check or "",
    ))
    selected = ordered[:max(0, top_n)]
    return {
        "recorded_only": True,
        "total_checks": len(entries),
        "by_status": by_status,
        "by_result_state": by_result_state,
        "stages": [stages[name] for name in sorted(stages)],
        "entries": [entry.to_dict() for entry in selected],
        "entries_omitted": len(entries) - len(selected),
        "result_state_definitions": RESULT_STATE_DEFINITIONS,
    }
