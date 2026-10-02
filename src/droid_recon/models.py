"""Core data model.

The load-bearing concept here is `reachable_from` on Component/Observation.

`adb shell` holds START_ANY_ACTIVITY and runs as the shell UID, which is far more
privileged than any third-party app. So a successful `am start` against an unexported
activity, or a successful `content query` against a permission-guarded provider, proves
NOTHING about real-world reachability — it is guaranteed to work on every device.

Therefore: reachability is computed from manifest facts only. Probes confirm *effect*
(did it crash, what did it leak, what came back), never *reach*.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Protocol

# Who can actually trigger this component on a stock, non-rooted device.
Reach = Literal["browser", "third_party_app", "shell", "none"]

ComponentType = Literal["activity", "activity-alias", "service", "receiver", "provider"]

Severity = Literal["critical", "high", "medium", "low", "info"]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ---- signature-only protections ----
# A component guarded by one of these is not reachable by an arbitrary third-party app,
# because the caller would have to be signed with the same key (or be the platform).
_PRIVILEGED_PROTECTIONS = ("signature", "signatureorsystem", "privileged", "internal")


def classify_reach(
    *,
    exported: bool,
    permission: str | None,
    permission_protection: str | None,
    browsable: bool = False,
    enabled: bool = True,
) -> Reach:
    """Compute who can reach a component. Manifest facts only — never probe results."""
    if not enabled:
        # A disabled component cannot be launched until package state changes.
        return "none"
    if not exported:
        # Still reachable from adb shell, which is why probes against it are not findings.
        return "shell"
    if permission:
        prot = (permission_protection or "").lower()
        # Unknown protection level on a permission we cannot resolve: assume the worst
        # for the defender (i.e. it might be `normal`), but only if it is not clearly
        # signature-gated. `normal`/`dangerous` are both obtainable by any app.
        if any(p in prot for p in _PRIVILEGED_PROTECTIONS):
            return "none"
    if browsable:
        return "browser"
    return "third_party_app"


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data: list[dict[str, str]] = field(default_factory=list)

    @property
    def browsable(self) -> bool:
        return (
            "android.intent.action.VIEW" in self.actions
            and "android.intent.category.BROWSABLE" in self.categories
            and any(d.get("scheme") for d in self.data)
        )

    def deeplinks(self) -> list[str]:
        """Concrete-ish URIs this filter would match, for probing."""
        if not self.browsable:
            return []
        out: list[str] = []
        for d in self.data:
            scheme = d.get("scheme")
            if not scheme:
                continue
            host = d.get("host") or "example.com"
            path = d.get("path") or d.get("pathPrefix") or ""
            if d.get("pathPattern") and not path:
                path = d["pathPattern"].replace(".*", "x").replace("*", "")
            if not path.startswith("/") and path:
                path = "/" + path
            out.append(f"{scheme}://{host}{path}")
        return out

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> IntentFilter:
        return cls(
            actions=list(d.get("actions", [])),
            categories=list(d.get("categories", [])),
            data=list(d.get("data", [])),
        )


@dataclass
class Component:
    name: str
    type: ComponentType
    exported: bool
    exported_source: str = "explicit"  # explicit | inferred-from-intent-filter | default
    permission: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None
    authorities: list[str] = field(default_factory=list)
    grant_uri_permissions: bool = False
    enabled: bool = True
    intent_filters: list[IntentFilter] = field(default_factory=list)
    reachable_from: Reach = "shell"
    issues: list[str] = field(default_factory=list)
    target_activity: str | None = None  # activity-alias
    source_apk: str | None = None  # APK whose manifest declared this component
    source_split: str | None = None  # None for the base APK
    # `reachable_from` remains the provider's read reach for compatibility.
    # The operation-specific values prevent read and write guards being conflated.
    read_reachable_from: Reach | None = None
    write_reachable_from: Reach | None = None
    call_reachable_from: Reach | None = None

    @property
    def browsable(self) -> bool:
        return (self.enabled and self.exported
                and self.type in ("activity", "activity-alias")
                and any(f.browsable for f in self.intent_filters))

    def provider_reach(self, operation: str) -> Reach:
        """Reach for a provider operation, falling back for older saved surfaces."""
        if self.type != "provider":
            return self.reachable_from
        if operation == "read":
            return self.read_reachable_from or self.reachable_from
        if operation == "write":
            return self.write_reachable_from or self.reachable_from
        if operation == "call":
            return self.call_reachable_from or self.reachable_from
        raise ValueError(f"unknown provider operation: {operation}")

    @property
    def publicly_reachable(self) -> bool:
        """Whether any manifest-declared operation admits an ordinary caller."""
        public = ("third_party_app", "browser")
        if self.type == "provider":
            return any(self.provider_reach(operation) in public
                       for operation in ("read", "write", "call"))
        return self.reachable_from in public

    @property
    def send_target(self) -> bool:
        return self.enabled and self.exported and any(
            a in ("android.intent.action.SEND", "android.intent.action.SEND_MULTIPLE")
            for f in self.intent_filters
            for a in f.actions
        )

    def deeplinks(self) -> list[str]:
        if not self.browsable:
            return []
        seen: list[str] = []
        for f in self.intent_filters:
            for uri in f.deeplinks():
                if uri not in seen:
                    seen.append(uri)
        return seen

    def to_dict(self) -> dict:
        d = asdict(self)
        d["intent_filters"] = [f.to_dict() for f in self.intent_filters]
        d["browsable"] = self.browsable
        d["send_target"] = self.send_target
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Component:
        d = dict(d)
        d.pop("browsable", None)
        d.pop("send_target", None)
        d["intent_filters"] = [IntentFilter.from_dict(f) for f in d.get("intent_filters", [])]
        return cls(**d)


@dataclass
class DeclaredPermission:
    name: str
    protection_level: str = "normal"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackSurface:
    package: str
    apk_paths: list[str] = field(default_factory=list)
    apk_sha256: str = ""
    apk_sha256s: dict[str, str] = field(default_factory=dict)
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    shared_user_id: str | None = None
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    uses_permissions: list[str] = field(default_factory=list)
    declared_permissions: list[DeclaredPermission] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    fileprovider_paths: list[dict] = field(default_factory=list)
    permission_misconfigs: list[dict] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    app_issues: list[str] = field(default_factory=list)
    analyzed_at: str = field(default_factory=utcnow)

    def by_type(self, t: ComponentType) -> list[Component]:
        return [c for c in self.components if c.type == t]

    @property
    def exported(self) -> list[Component]:
        return [c for c in self.components if c.exported]

    def summary(self) -> dict:
        return {
            "package": self.package,
            "total_components": len(self.components),
            "exported_components": len(self.exported),
            "reachable_third_party": sum(
                1 for c in self.components if c.publicly_reachable
            ),
            "activities": len(self.by_type("activity")) + len(self.by_type("activity-alias")),
            "services": len(self.by_type("service")),
            "receivers": len(self.by_type("receiver")),
            "providers": len(self.by_type("provider")),
            "providers_read_reachable": sum(
                1 for c in self.by_type("provider")
                if c.provider_reach("read") in ("third_party_app", "browser")
            ),
            "providers_write_reachable": sum(
                1 for c in self.by_type("provider")
                if c.provider_reach("write") in ("third_party_app", "browser")
            ),
            "providers_call_reachable": sum(
                1 for c in self.by_type("provider")
                if c.provider_reach("call") in ("third_party_app", "browser")
            ),
            "components_with_issues": sum(1 for c in self.components if c.issues),
            "fileprovider_paths": len(self.fileprovider_paths),
            "permission_misconfigs": len(self.permission_misconfigs),
            "native_libs": len(self.native_libs),
            "has_browsable": any(c.browsable for c in self.components),
            "has_send_target": any(c.send_target for c in self.components),
            "has_grant_uri": any(c.grant_uri_permissions for c in self.components),
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
        }

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "apk_paths": self.apk_paths,
            "apk_sha256": self.apk_sha256,
            "apk_sha256s": self.apk_sha256s,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "shared_user_id": self.shared_user_id,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "network_security_config": self.network_security_config,
            "uses_permissions": self.uses_permissions,
            "declared_permissions": [p.to_dict() for p in self.declared_permissions],
            "components": [c.to_dict() for c in self.components],
            "fileprovider_paths": self.fileprovider_paths,
            "permission_misconfigs": self.permission_misconfigs,
            "native_libs": self.native_libs,
            "app_issues": self.app_issues,
            "analyzed_at": self.analyzed_at,
            "summary": self.summary(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> AttackSurface:
        d = dict(d)
        d.pop("summary", None)
        d["components"] = [Component.from_dict(c) for c in d.get("components", [])]
        d["declared_permissions"] = [
            DeclaredPermission(**p) for p in d.get("declared_permissions", [])
        ]
        return cls(**d)


@dataclass
class Observation:
    """A deterministic probe result. High recall, low precision — NOT a finding.

    Observations are promoted to Findings only by triage, and only when a
    source -> sink -> chain story exists and `reachable_from` is not `shell`.
    """

    id: str
    kind: str  # launch_activity | deeplink | broadcast | start_service | query_provider | ...
    package: str
    component: str | None
    reachable_from: Reach
    command: list[str] = field(default_factory=list)
    rc: int = 0
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    signal: str = ""  # short machine label, e.g. "rows_returned", "crash", "denied"
    interesting: bool = False
    logcat_excerpt: str = ""
    screenshot: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Observation:
        return cls(**d)


@dataclass
class Finding:
    """Triage output. Mirrors android-privesc-hunt/prompts/findings-schema.json.

    `source`, `sink` and `chain` are required by design — that requirement is the
    single best false-positive filter in the whole pipeline.
    """

    id: str
    title: str
    severity: Severity
    exploitability: str  # local-zero-click | local-one-click | remote-one-click | ...
    confidence: str  # "85%"
    attack_class: str
    component: dict
    reachable_from: Reach
    source: dict
    sink: dict
    chain: list[str]
    poc: str
    impact: str
    evidence: dict = field(default_factory=dict)
    observations: list[str] = field(default_factory=list)
    cwe: str | None = None
    notes: str = ""
    timestamp: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(**d)


@dataclass
class SessionState:
    session_id: str
    target_package: str
    apk_paths: list[str] = field(default_factory=list)
    phase: str = "init"
    steps_done: list[str] = field(default_factory=list)
    serial: str | None = None
    components_total: int = 0
    components_probed: int = 0
    observations_count: int = 0
    findings_count: int = 0
    dead_ends_count: int = 0
    frida_available: bool = False
    started_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> SessionState:
        return cls(**d)


class Driver(Protocol):
    """Device-control seam. The only surface a future mobilerun/cloud adapter must satisfy."""

    def shell(self, command: list[str], timeout: int = 60) -> Any: ...
    def install(self, apks: list[str]) -> Any: ...
    def screenshot(self, dest: str) -> bool: ...


def jsonl_append(path, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
