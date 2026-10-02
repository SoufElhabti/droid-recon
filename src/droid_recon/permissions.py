"""Tool permission classes shared by model-driven entry points.

Only tools in READ_ONLY may run unattended under the default approval policy.
Reading private app storage is deliberately excluded: its output can contain user
data and credentials even though the operation does not mutate the device.
"""

from __future__ import annotations

READ_ONLY: frozenset[str] = frozenset({
    "device_status", "list_packages", "static_analyze", "code_analyze",
    "ghidra_analyze", "ghidra_decompile", "list_native_libs", "ui_state",
    "triage", "get_report", "session_status",
})


def requires_approval(tool_name: str) -> bool:
    """Unknown tools require approval by default."""
    return tool_name not in READ_ONLY
