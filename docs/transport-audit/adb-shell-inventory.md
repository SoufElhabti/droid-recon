# ADB Shell Inventory

Audit date: 2026-08-11
Branch: `transport/device-agent`

Every `adb shell` / `adb_shell` / `adb_script` call in the runtime, classified by
whether it is bootstrap-only or a runtime call that the device-agent should replace.

## Bootstrap (keep in ADB — branch 3 consolidates these)

| Module | Function | Command | Notes |
|--------|----------|---------|-------|
| frida/server.py | ensure_server | `adb push frida-server` | file transfer |
| frida/server.py | ensure_server | `chmod 755`, `pgrep`, `whoami`, `getenforce` | server lifecycle |
| frida/server.py | ensure_server | `nohup frida-server -l ...` | start daemon |
| frida/server.py | device_arch | `getprop ro.product.cpu.abi` | one-time query |
| device/emulator.py | become_root | `adb root`, `adb wait-for-device` | bootstrap |
| device/emulator.py | wait_ready | `getprop sys.boot_completed`, `pm path android` | boot wait |
| device/emulator.py | shutdown | `adb emu kill` | lifecycle |
| device/emulator.py | device_info | `getprop` (6 props), `getenforce`, `whoami` | one-time query |
| device/install.py | install | `adb install` / `adb install-multiple` | APK push |
| device/install.py | uninstall | `adb uninstall` | package mgmt |
| device/install.py | pull_installed_apk | `adb pull`, `pm path` | file transfer |
| device/install.py | is_installed | `pm path` | one-time check |
| device/install.py | list_packages | `pm list packages` | one-time query |
| device/install.py | clear_data | `pm clear` | state reset |
| device/install.py | stop | `am force-stop` | state reset |
| device/certs.py | install_system_ca | `adb push`, `mount`, `nsenter`, `restorecon` | trust store |
| device/network.py | set_device_proxy | `settings put global http_proxy` | one-time |
| device/network.py | clear_device_proxy | `settings delete global http_proxy` | one-time |

## Runtime — IPC probing (device-agent: `/ipc/*` + `/exec`)

| Module | Function | Command | Priority |
|--------|----------|---------|----------|
| device/probes.py | _run_probe | `adb_shell <argv>` (generic) | **HIGH** — all probes go through this |
| device/probes.py | launch_activity | `am start -W -n pkg/Comp` | HIGH |
| device/probes.py | launch_deeplink | `am start -a VIEW -c BROWSABLE -d <uri>` | HIGH |
| device/probes.py | send_broadcast | `am broadcast -a action -n pkg/Comp` | HIGH |
| device/probes.py | start_service | `am start-service -n pkg/Comp` | HIGH |
| device/probes.py | query_provider | `content query --uri <uri>` | HIGH |
| device/probes.py | call_provider | `content call --uri <uri> --method <m>` | HIGH |
| device/probes.py | read_provider_file | `content read --uri <uri>` | HIGH |
| device/probes.py | dumpsys_package | `dumpsys package <pkg>` | MEDIUM |
| device/probes.py | runtime_permissions | `dumpsys package <pkg>` | MEDIUM |
| device/probes.py | resolve_authorities | `dumpsys package <pkg>` | MEDIUM |
| device/exploit.py | run_payload | `adb_shell <argv>` | HIGH |
| device/exploit.py | probe_provider_sqli | `content query --uri ... --where <sel>` | HIGH |
| device/exploit.py | probe_provider_traversal | `content read --uri <uri>` | HIGH |

## Runtime — UI / screen (device-agent: `/ui/*`)

| Module | Function | Command | Priority |
|--------|----------|---------|----------|
| device/screen.py | capture | `screencap -p`, `adb pull`, `rm -f` | MEDIUM |
| device/screen.py | ui_tree_xml | `uiautomator dump`, `cat`, `rm -f` | MEDIUM |
| device/screen.py | current_focus | `dumpsys window` | MEDIUM |
| device/screen.py | dismiss_system_dialogs | `am broadcast CLOSE_SYSTEM_DIALOGS`, `input keyevent 4` | MEDIUM |
| device/explorer.py | authenticate | `input tap`, `input text`, UI automation | MEDIUM |
| device/explorer.py | explore | UI crawl via `uiautomator`, `input tap` | MEDIUM |

## Runtime — filesystem (device-agent: `/fs/*`)

| Module | Function | Command | Priority |
|--------|----------|---------|----------|
| device/storage.py | pull_private_data | `cp -r`, `chmod`, `adb pull`, `rm -rf` | HIGH |
| device/storage.py | world_readable_scan | `find /data/data/pkg -perm -o+r` | HIGH |
| device/storage.py | dump_db_tables | `sqlite3 <db> .tables` | MEDIUM |
| device/storage.py | _ls | `ls -la <path>` | LOW |

## Runtime — logcat (device-agent: `/logcat/*`)

| Module | Function | Command | Priority |
|--------|----------|---------|----------|
| device/logcat.py | clear | `adb logcat -c` | HIGH |
| device/logcat.py | dump | `adb logcat -d -v brief -t N` | HIGH |

## Runtime — process state (device-agent: `/process/*`)

| Module | Function | Command | Priority |
|--------|----------|---------|----------|
| device/oracle.py | snapshot | `pidof <pkg>` | HIGH |
| device/oracle.py | snapshot | `dumpsys window` (via screen.current_focus) | HIGH |

## Runtime — native (device-agent: `/exec`)

| Module | Function | Command | Priority |
|--------|----------|---------|----------|
| frida/native.py | list_native_libs | `find /data/app -path '*pkg*' -name '*.so'` | LOW |
| frida/native.py | loaded_modules | `pidof <pkg>`, `cat /proc/PID/maps` | LOW |

## Migration order

1. IPC probing (probes.py, exploit.py) — highest value, most calls
2. Logcat (logcat.py) — used by every probe
3. Process/state (oracle.py, screen.py) — used by exploit verification
4. Filesystem (storage.py) — less frequent but data-bearing
5. UI automation (explorer.py) — lower priority, complex
6. Native queries (native.py) — lowest priority, simple
