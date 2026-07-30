"""Session directory layout and append-only persistence.

Two artifact streams, deliberately separate:

  observations.jsonl  deterministic probe results — high recall, low precision.
  findings.jsonl      triage output only, and only for things that pass the
                      source -> sink -> chain gate with reachable_from != "shell".

Collapsing these into one file is how an audit tool becomes a false-positive firehose.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import log
from .models import AttackSurface, Finding, Observation, SessionState, jsonl_append, utcnow

DEFAULT_ROOT = Path("sessions")


class Session:
    def __init__(self, root: Path, package: str):
        self.dir = root
        self.package = package
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "screenshots").mkdir(exist_ok=True)
        (self.dir / "storage").mkdir(exist_ok=True)
        log.set_log_file(self.log_path)

    # ---- paths ----
    @property
    def state_path(self) -> Path:
        return self.dir / "state.json"

    @property
    def observations_path(self) -> Path:
        return self.dir / "observations.jsonl"

    @property
    def findings_path(self) -> Path:
        return self.dir / "findings.jsonl"

    @property
    def dead_ends_path(self) -> Path:
        return self.dir / "dead-ends.md"

    @property
    def log_path(self) -> Path:
        return self.dir / "session.log"

    @property
    def surface_path(self) -> Path:
        return self.dir / "attack_surface.json"

    @property
    def code_path(self) -> Path:
        return self.dir / "code_report.json"

    @property
    def screenshots(self) -> Path:
        return self.dir / "screenshots"

    @property
    def storage(self) -> Path:
        return self.dir / "storage"

    # ---- factory ----
    @classmethod
    def open(cls, package: str, root: Path | None = None) -> Session:
        base = (root or DEFAULT_ROOT).expanduser()
        return cls(base / package, package)

    # ---- state ----
    def load_state(self) -> SessionState | None:
        if not self.state_path.exists():
            return None
        try:
            return SessionState.from_dict(json.loads(self.state_path.read_text()))
        except (json.JSONDecodeError, TypeError, OSError) as exc:
            log.warn(f"state.json unreadable ({exc}) — starting fresh")
            return None

    def save_state(self, state: SessionState) -> None:
        state.updated_at = utcnow()
        state.observations_count = self.count_observations()
        state.findings_count = self.count_findings()
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(state.to_dict(), indent=2))
        tmp.replace(self.state_path)

    def mark_step(self, state: SessionState, step: str) -> None:
        if step not in state.steps_done:
            state.steps_done.append(step)
        self.save_state(state)

    # ---- artifacts ----
    def write_surface(self, surface: AttackSurface) -> None:
        self.surface_path.write_text(json.dumps(surface.to_dict(), indent=2))

    def read_surface(self) -> AttackSurface | None:
        if not self.surface_path.exists():
            return None
        return AttackSurface.from_dict(json.loads(self.surface_path.read_text()))

    def write_code_report(self, data: dict) -> None:
        self.code_path.write_text(json.dumps(data, indent=2))

    def read_code_report(self) -> dict | None:
        if not self.code_path.exists():
            return None
        try:
            return json.loads(self.code_path.read_text())
        except json.JSONDecodeError:
            return None

    def add_observation(self, obs: Observation) -> None:
        jsonl_append(self.observations_path, obs.to_dict())

    def add_finding(self, finding: Finding) -> None:
        jsonl_append(self.findings_path, finding.to_dict())

    def add_dead_end(self, what: str, why: str) -> None:
        """Dead ends prevent the next run (or the next operator) repeating dry work."""
        first = not self.dead_ends_path.exists()
        with self.dead_ends_path.open("a", encoding="utf-8") as fh:
            if first:
                fh.write(f"# Dead ends — {self.package}\n\n"
                         f"Approaches attempted that yielded nothing. Do not repeat these.\n\n")
            fh.write(f"- **{what}** — {why}  \n  _{utcnow()}_\n")

    # ---- reads ----
    def observations(self) -> list[Observation]:
        return [Observation.from_dict(d) for d in _read_jsonl(self.observations_path)]

    def findings(self) -> list[Finding]:
        return [Finding.from_dict(d) for d in _read_jsonl(self.findings_path)]

    def count_observations(self) -> int:
        return _count_lines(self.observations_path)

    def count_findings(self) -> int:
        return _count_lines(self.findings_path)

    def next_finding_id(self) -> str:
        return f"F{self.count_findings() + 1:03d}"


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(errors="replace").splitlines() if line.strip())
