"""Transport configuration for device communication.

Three tiers, merged incrementally:
  1. Frida: TCP (preferred) or USB
  2. Device agent: on-device HTTP service replacing adb shell at runtime
  3. ADB: bootstrap-only (push, install, port-forward, emulator lifecycle)
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field


@dataclass
class FridaTransportConfig:
    mode: str = "auto"          # "tcp" | "usb" | "auto"
    host: str = "127.0.0.1"
    port: int = 27042

    def __post_init__(self):
        if self.mode not in ("tcp", "usb", "auto"):
            raise ValueError(f"frida transport mode must be tcp|usb|auto, got {self.mode!r}")


@dataclass
class DeviceAgentConfig:
    host: str = "127.0.0.1"
    port: int = 18080
    secret: str = field(default_factory=lambda: secrets.token_hex(16))
    enabled: bool = True

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


@dataclass
class TransportConfig:
    frida: FridaTransportConfig = field(default_factory=FridaTransportConfig)
    agent: DeviceAgentConfig = field(default_factory=DeviceAgentConfig)

    @classmethod
    def from_cli(cls, args) -> TransportConfig:
        frida_mode = getattr(args, "frida_transport", None) or "auto"
        agent_enabled = not getattr(args, "no_agent", False)
        return cls(
            frida=FridaTransportConfig(mode=frida_mode),
            agent=DeviceAgentConfig(enabled=agent_enabled),
        )
