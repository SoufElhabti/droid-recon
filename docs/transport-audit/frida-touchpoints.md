# Frida Touchpoints Audit

Audit date: 2026-08-11
Branch: `transport/frida-tcp`

## Architecture

Frida is used **exclusively via the CLI binary**, not the Python `frida` library.
There are zero `import frida` statements in the codebase. Device communication
happens through two paths:

1. **frida-server lifecycle** (`frida/server.py`) — pushed and started via `adb shell`
2. **frida CLI invocation** (`frida/server.py:run_script()`) — subprocess call to `frida`

## Touchpoints

### frida/server.py

| Line | Function | What it does | Transport relevance |
|------|----------|-------------|---------------------|
| 38 | `device_arch()` | `adb_shell getprop ro.product.cpu.abi` | ADB bootstrap — unchanged |
| 73 | `is_running()` | `adb_shell pgrep -f frida-server` | ADB bootstrap — unchanged |
| 78 | `ensure_server()` | Push + start frida-server via ADB | **CHANGE**: add `-l 0.0.0.0:{port}`, add `adb forward` |
| 96 | (push) | `adb push <binary> /data/local/tmp/frida-server` | ADB bootstrap — unchanged |
| 102 | (start) | `nohup frida-server -D` | **CHANGE**: add `-l` listen flag |
| 171 | `run_script()` | Build `frida` CLI argv with `-U` or `-D serial` | **CHANGE**: support `-H host:port` for TCP |

### frida/native.py

| Line | Function | What it does | Transport relevance |
|------|----------|-------------|---------------------|
| 150 | `list_native_libs()` | `adb_script find /data/app ...` | ADB runtime — Branch 2 |
| 159 | `loaded_modules()` | `adb_shell pidof` + `adb_script cat /proc/maps` | ADB runtime — Branch 2 |
| 186 | `trace()` | Calls `frida_server.ensure_server()` + `run_script()` | Inherits transport from server.py |

### cli.py

| Line | Function | What it does | Transport relevance |
|------|----------|-------------|---------------------|
| 467 | `cmd_frida()` | Entry point for `frida setup` and `frida run` | **CHANGE**: accept `--frida-transport` |
| 485 | (run) | Calls `frida_server.run_script()` | Passes transport config through |

## Changes Required

1. Add `src/droid_recon/transport.py` — `FridaTransportConfig` dataclass
2. Modify `frida/server.py:ensure_server()` — TCP listen + port forward
3. Modify `frida/server.py:run_script()` — `-H` flag for TCP
4. Modify `cli.py` — `--frida-transport` CLI flag on frida and native subcommands
5. Tests for TCP connect, auto fallback, SSL unpin equivalence
