"""MCP stdio server — exposes droid-recon to Claude Code, Codex, and any MCP client.

Transport note, because the obvious prior art is wrong: MCP stdio framing is
**newline-delimited JSON-RPC 2.0**, one message per line. It is NOT LSP's
`Content-Length:` header framing. A server using LSP framing connects and then silently
never responds.

Design constraints that matter for agent use:

  * Every response is bounded. Tools return summaries plus an `artifact` path; the agent
    reads the artifact only when it needs detail. A 74 KB code report returned inline
    would consume the caller's context for nothing.
  * Long operations (jadx, ghidra, crawling) are explicit separate tools, so the agent
    chooses when to pay for them rather than having one mega-tool block for 15 minutes.
  * Nothing here holds state between calls except the session directory on disk, so a
    crashed or restarted agent resumes cleanly.
"""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

from . import report as report_mod
from . import chains as chains_mod
from . import triage as triage_mod
from .device import (certs, emulator, exploit, explorer, install, network, oracle,
                     payloads, probes, screen, storage)
from .frida import native as native_mod
from .frida import server as frida_server
from .models import Component
from .session import DEFAULT_ROOT, Session
from .static import decompile, ghidra, manifest, resources, sweep, urimatcher

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "droid-recon", "version": "0.2.0"}

_SESSIONS_ROOT = Path(DEFAULT_ROOT)

# ---------------------------------------------------------------- tool registry

TOOLS: list[dict] = []
_HANDLERS: dict[str, Callable[[dict], Any]] = {}


def tool(name: str, description: str, schema: dict):
    def deco(fn):
        TOOLS.append({"name": name, "description": description, "inputSchema": schema})
        _HANDLERS[name] = fn
        return fn
    return deco


def _obj(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or []}


_S = {"type": "string"}
_I = {"type": "integer"}
_B = {"type": "boolean"}


def _session(package: str) -> Session:
    return Session.open(package, _SESSIONS_ROOT)


def _surface_for(target: str):
    apks = manifest.resolve_apks(target)
    return manifest.analyze(apks[0].parent if len(apks) > 1 else apks[0]), apks


# ---------------------------------------------------------------- device tools

@tool("device_status",
      "Device/emulator status: attached serials, available AVDs, root, SELinux, API level, "
      "and whether frida-server and the mitmproxy CA are in place. Call this first — most "
      "other failures trace back to something here.",
      _obj({}))
def _device_status(args: dict) -> dict:
    serial = emulator.running_serial()
    out: dict = {"avds": emulator.list_avds(), "attached": serial}
    if serial:
        out["device"] = emulator.device_info(serial)
        out["frida_running"] = frida_server.is_running(serial)
        out["trust_store"] = certs.trust_status(serial)
        out["proxy"] = network.device_proxy(serial)
    else:
        out["hint"] = "no device attached — call device_up"
    return out


@tool("device_up",
      "Boot the AVD headless, wait until the package manager is genuinely ready, and "
      "`adb root`. Takes ~25s cold. Safe to call when already booted. Pass "
      "http_proxy='10.0.2.2:8080' to route ALL traffic through the proxy at boot — "
      "required for WebView, which ignores the runtime proxy setting.",
      _obj({"avd": _S, "window": _B, "http_proxy": _S}))
def _device_up(args: dict) -> dict:
    serial = emulator.boot(args.get("avd") or "webview_lab",
                           headless=not args.get("window", False),
                           http_proxy=args.get("http_proxy"))
    if not serial:
        return {"ok": False, "error": "emulator did not become ready"}
    rooted = emulator.become_root(serial)
    return {"ok": True, "serial": serial, "root": rooted,
            "device": emulator.device_info(serial)}


@tool("list_packages", "Installed packages on the device.",
      _obj({"third_party_only": _B}))
def _list_packages(args: dict) -> dict:
    serial = emulator.running_serial()
    pkgs = install.list_packages(serial, third_party_only=args.get("third_party_only", False))
    return {"count": len(pkgs), "packages": pkgs}


@tool("pull_apk",
      "Pull an installed package's APKs off the device (splits included). Use this to get "
      "a real target without downloading anything.",
      _obj({"package": _S, "out_dir": _S}, ["package"]))
def _pull_apk(args: dict) -> dict:
    serial = emulator.running_serial()
    dest = Path(args.get("out_dir") or "./targets")
    pulled = install.pull_installed_apk(args["package"], dest, serial)
    return {"package": args["package"], "apks": [str(p) for p in pulled]}


@tool("install_apk", "Install an APK or split set on the device (grants permissions).",
      _obj({"target": _S}, ["target"]))
def _install_apk(args: dict) -> dict:
    serial = emulator.running_serial()
    apks = manifest.resolve_apks(args["target"])
    good, msg = install.install(apks, serial)
    return {"ok": good, "message": msg[:400], "apks": [str(a) for a in apks]}


# ---------------------------------------------------------------- static tools

@tool("static_analyze",
      "Parse the manifest into an attack surface: every component with exported state, "
      "HOW that was determined, reachable_from, deep links, provider authorities, and a "
      "triage verdict. ~2s, no device needed. ALWAYS start here.",
      _obj({"target": _S, "skip_resources": _B}, ["target"]))
def _static_analyze(args: dict) -> dict:
    surface, apks = _surface_for(args["target"])
    if not args.get("skip_resources"):
        res_root = decompile.DEFAULT_CACHE.parent / "res" / surface.apk_sha256[:16]
        if resources.extract_resources(apks[0], res_root):
            surface.fileprovider_paths = resources.find_fileprovider_paths(res_root)
            nsc = resources.find_network_security_config(res_root)
            if nsc and nsc["issues"]:
                surface.app_issues += [f"networkSecurityConfig: {i}" for i in nsc["issues"]]
    sess = _session(surface.package)
    sess.write_surface(surface)
    return {
        "package": surface.package,
        "verdict": sweep.verdict(surface),
        "summary": surface.summary(),
        "app_issues": surface.app_issues,
        "reachable_components": [
            {"name": c.name, "type": c.type, "reachable_from": c.reachable_from,
             "permission": c.read_permission or c.permission,
             "authorities": c.authorities, "deeplinks": c.deeplinks()[:4],
             "issues": c.issues}
            for c in surface.components
            if c.reachable_from in ("third_party_app", "browser")
        ][:40],
        "artifact": str(sess.surface_path),
        "session_dir": str(sess.dir),
    }


@tool("code_analyze",
      "Decompile with jadx (cached by APK hash, ~15s/18MB) and sweep for sinks/sources, "
      "hardcoded secrets, and — most importantly — ContentProvider URI paths and call() "
      "methods recovered from UriMatcher.addURI literals. Provider probing barely works "
      "without this.",
      _obj({"target": _S, "force": _B, "top": _I}, ["target"]))
def _code_analyze(args: dict) -> dict:
    surface, apks = _surface_for(args["target"])
    sess = _session(surface.package)
    surface = sess.read_surface() or surface
    tree = decompile.decompile(apks[0], surface.apk_sha256, force=args.get("force", False))
    if tree is None:
        return {"ok": False, "error": "jadx produced no sources"}
    code = sweep.sweep(tree, surface)
    auths = sorted({a for c in surface.components for a in c.authorities})
    code.provider_paths = urimatcher.extract(tree, auths)
    doc = code.to_dict()
    doc["focused"] = sweep.focused(code, surface, top_n=args.get("top", 40))
    doc["verdict"] = sweep.verdict(surface, code)
    sess.write_code_report(doc)
    return {
        "package": surface.package,
        "verdict": doc["verdict"],
        "summary": code.summary(),
        "provider_paths": code.provider_paths.get("paths", {}),
        "provider_call_methods": code.provider_paths.get("call_methods", []),
        "focused_sinks": doc["focused"].get("sinks", [])[:15],
        "secrets": doc["focused"].get("secrets", [])[:10],
        "artifact": str(sess.code_path),
    }


@tool("ghidra_analyze",
      "Headless Ghidra over the APK's native .so libraries: JNI entry points (the surface "
      "reachable from Java), dangerous imports (system/exec/dlopen/strcpy/ptrace), embedded "
      "secrets and endpoints. Slow (minutes per library) — call it when static analysis "
      "shows native libs that matter.",
      _obj({"target": _S, "abi": _S, "max_libs": _I, "force": _B}, ["target"]))
def _ghidra_analyze(args: dict) -> dict:
    if not ghidra.available():
        return {"ok": False,
                "error": "Ghidra analyzeHeadless not found; set GHIDRA_INSTALL_DIR"}
    surface, apks = _surface_for(args["target"])
    sess = _session(surface.package)
    work = sess.dir / "native"
    libs = ghidra.extract_native_libs(apks[0], work / "libs", args.get("abi") or "arm64-v8a")
    if not libs:
        return {"ok": True, "libraries": [], "note": "no native libraries for this ABI"}
    results = []
    for so in libs[: args.get("max_libs", 3)]:
        blob = ghidra.analyse(so, work, force=args.get("force", False))
        if blob:
            results.append({"library": so.name,
                            "functions": blob.get("functions_total"),
                            "findings": blob.get("findings", {})})
    (sess.dir / "ghidra.json").write_text(json.dumps(results, indent=2))
    return {"package": surface.package, "libraries_found": [p.name for p in libs],
            "analysed": results, "artifact": str(sess.dir / "ghidra.json")}


@tool("ghidra_decompile", "Decompile one native function to C by name.",
      _obj({"so_path": _S, "function": _S, "package": _S}, ["so_path", "function"]))
def _ghidra_decompile(args: dict) -> dict:
    sess = _session(args.get("package") or "_scratch")
    c = ghidra.decompile_function(Path(args["so_path"]), args["function"], sess.dir / "native")
    return {"function": args["function"], "c": c or "", "ok": bool(c)}


# ---------------------------------------------------------------- dynamic tools

@tool("probe_ipc",
      "Probe the IPC surface: launch activities, fire declared deep links, broadcast to "
      "receivers, start services, query providers over code-recovered paths. Writes "
      "observations. Reachability always comes from the manifest, never from exit codes.",
      _obj({"target": _S, "types": {"type": "array", "items": _S},
            "include_shell_only": _B, "traversal": _B, "limit": _I}, ["target"]))
def _probe_ipc(args: dict) -> dict:
    surface, apks = _surface_for(args["target"])
    sess = _session(surface.package)
    surface = sess.read_surface() or surface
    serial = emulator.running_serial()
    if not serial:
        return {"ok": False, "error": "no device — call device_up"}

    code = sess.read_code_report() or {}
    pp = code.get("provider_paths") or {}
    ctx = probes.ProbeContext(package=surface.package, serial=serial)

    wanted = set(args.get("types") or ["activity", "provider", "receiver", "service"])
    if "activity" in wanted:
        wanted.add("activity-alias")
    targets = [c for c in surface.components
               if c.type in wanted
               and (args.get("include_shell_only")
                    or c.reachable_from in ("third_party_app", "browser"))]
    limit = args.get("limit") or 0
    if limit:
        targets = targets[:limit]

    made = 0
    for comp in targets:
        if comp.type == "provider":
            known = pp.get("paths", {})
            floating = pp.get("floating_paths", [])
            for auth in comp.authorities:
                paths = known.get(auth) or (floating[:4] + list(urimatcher.FALLBACK_PATHS[:8]))
                for p in paths[:14]:
                    sess.add_observation(probes.query_provider(ctx, comp, auth, p)); made += 1
                for m in (pp.get("call_methods") or [])[:6]:
                    sess.add_observation(probes.call_provider(ctx, comp, auth, m)); made += 1
                if args.get("traversal"):
                    for t in urimatcher.TRAVERSAL_PATHS:
                        sess.add_observation(probes.read_provider_file(ctx, comp, auth, t))
                        made += 1
        elif comp.type in ("activity", "activity-alias"):
            sess.add_observation(probes.launch_activity(ctx, comp)); made += 1
            for uri in comp.deeplinks()[:5]:
                sess.add_observation(probes.launch_deeplink(ctx, comp, uri)); made += 1
        elif comp.type == "receiver":
            for f in comp.intent_filters:
                for a in f.actions[:4]:
                    sess.add_observation(probes.send_broadcast(ctx, comp, a)); made += 1
        elif comp.type == "service":
            sess.add_observation(probes.start_service(ctx, comp)); made += 1

    obs = sess.observations()
    return {"package": surface.package, "components_probed": len(targets),
            "observations_added": made, "total_observations": len(obs),
            "interesting": [o.to_dict() for o in obs if o.interesting][:15],
            "artifact": str(sess.observations_path)}


@tool("send_payload",
      "Send ONE crafted IPC payload at a component and verify whether it landed, using the "
      "before/after oracle (logcat + UI + process + traffic + canary). This is the tool for "
      "targeted exploitation once you know what you're aiming at.",
      _obj({"package": _S, "component": _S, "payload_name": _S,
            "extras": {"type": "array", "items": _obj({"key": _S, "value": _S, "type": _S})},
            "action": _S, "data_uri": _S, "verb": _S, "expect_crash": _B}, ["package", "component"]))
def _send_payload(args: dict) -> dict:
    serial = emulator.running_serial()
    if not serial:
        return {"ok": False, "error": "no device"}
    sess = _session(args["package"])
    surface = sess.read_surface()
    comp = next((c for c in (surface.components if surface else [])
                 if c.name == args["component"]), None)
    if comp is None:
        comp = Component(name=args["component"], type="activity", exported=True,
                         reachable_from="shell")

    extras = [payloads.Extra(e["key"], e.get("value", ""), e.get("type", "string"))
              for e in (args.get("extras") or [])]
    p = payloads.Payload(
        name=args.get("payload_name") or "manual",
        attack_class="manual payload",
        extras=extras,
        action=args.get("action"),
        data_uri=args.get("data_uri"),
        expect={"crash": True} if args.get("expect_crash") else {},
        why="operator-supplied payload",
    )
    verb = args.get("verb") or {"activity": "start", "activity-alias": "start",
                                "receiver": "broadcast",
                                "service": "start-service"}.get(comp.type, "start")
    att = exploit.run_payload(args["package"], comp, p, serial=serial, verb=verb,
                              screenshots_dir=sess.screenshots)
    sess.add_observation(att.to_observation(f"O{sess.count_observations()+1:04d}", args["package"]))
    return att.to_dict()


@tool("exploit_campaign",
      "Send the full payload battery (intent redirection, WebView URL injection, fuzzing) "
      "at every reachable component and verify each with the oracle. Writes exploits.jsonl. "
      "This is the autonomous exploitation pass.",
      _obj({"target": _S, "max_payloads": _I, "types": {"type": "array", "items": _S}},
           ["target"]))
def _exploit_campaign(args: dict) -> dict:
    surface, _ = _surface_for(args["target"])
    sess = _session(surface.package)
    surface = sess.read_surface() or surface
    serial = emulator.running_serial()
    if not serial:
        return {"ok": False, "error": "no device"}

    wanted = set(args.get("types") or ["activity", "receiver", "service"])
    if "activity" in wanted:
        wanted.add("activity-alias")
    comps = [c for c in surface.components
             if c.type in wanted and c.reachable_from in ("third_party_app", "browser")]
    if not comps:
        return {"ok": True, "attempts": 0,
                "note": "no third-party-reachable components of these types"}

    hosts_seen: list[str] = []
    attempts = exploit.run_campaign(
        surface.package, comps, serial=serial, screenshots_dir=sess.screenshots,
        traffic_hosts_fn=lambda: hosts_seen,
        max_payloads_per_component=args.get("max_payloads", 10),
    )
    path = sess.dir / "exploits.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        for a in attempts:
            fh.write(json.dumps(a.to_dict()) + "\n")
    for a in attempts:
        sess.add_observation(a.to_observation(
            f"O{sess.count_observations()+1:04d}", surface.package))

    hits = [a for a in attempts if a.verdict.hit]
    return {
        "package": surface.package,
        "attempts": len(attempts),
        "landed": len(hits),
        "confirmed": sum(1 for a in hits if a.verdict.confidence == "confirmed"),
        "hits": [a.to_dict() for a in hits][:12],
        "artifact": str(path),
    }


@tool("provider_sqli",
      "Test a content provider's selection clause for unparameterised SQL. A SQLite parse "
      "error proves the string reached the query engine rather than a bound parameter.",
      _obj({"package": _S, "authority": _S, "path": _S}, ["package", "authority"]))
def _provider_sqli(args: dict) -> dict:
    serial = emulator.running_serial()
    sess = _session(args["package"])
    surface = sess.read_surface()
    comp = next((c for c in (surface.components if surface else [])
                 if args["authority"] in c.authorities), None) or Component(
        name=args["authority"], type="provider", exported=True, reachable_from="shell")
    res = exploit.probe_provider_sqli(args["package"], comp, args["authority"],
                                      args.get("path", ""), serial)
    return {"authority": args["authority"], "results": res,
            "sql_reached_engine": any(r["sql_error"] for r in res)}


# ---------------------------------------------------------------- network tools

@tool("network_setup",
      "Install the mitmproxy CA into the Android 14 system trust store (conscrypt APEX "
      "tmpfs overlay + nsenter propagation into every app mount namespace) so HTTPS is "
      "decryptable. Required before capture on API 29+.",
      _obj({}))
def _network_setup(args: dict) -> dict:
    serial = emulator.running_serial()
    ca = network.ensure_ca()
    if not ca:
        return {"ok": False, "error": "could not obtain the mitmproxy CA"}
    good, msg = certs.install_system_ca(ca, serial)
    return {"ok": good, "message": msg, "ca": str(ca),
            "trust_store": certs.trust_status(serial)}


@tool("network_capture",
      "Run a TLS-intercepting capture for N seconds while exercising the app, then analyse: "
      "cleartext HTTP, credentials in traffic, IDOR candidates, and TLS handshake failures. "
      "Reports WHY a capture is empty rather than returning a bare zero.",
      _obj({"package": _S, "duration": _I, "launch": _B, "port": _I}, ["package"]))
def _network_capture(args: dict) -> dict:
    import time
    serial = emulator.running_serial()
    if not serial:
        return {"ok": False, "error": "no device"}
    sess = _session(args["package"])
    out = sess.dir / "network"
    port = args.get("port", network.DEFAULT_PORT)

    cap = network.start_capture(out, port=port)
    if cap is None:
        return {"ok": False, "error": "mitmdump failed to start"}
    network.set_device_proxy(port, serial)
    from . import shell as _sh
    _sh.adb_shell(["am", "broadcast", "-a", "android.intent.action.PROXY_CHANGE"],
                  serial=serial, timeout=20)
    if args.get("launch", True):
        _sh.adb_shell(["monkey", "-p", args["package"], "-c",
                       "android.intent.category.LAUNCHER", "1"], serial=serial, timeout=30)
    time.sleep(max(5, args.get("duration", 25)))
    cap.stop()
    network.clear_device_proxy(serial)

    recs = network.read_flows(cap.flows_path)
    analysis = network.analyse(recs, args["package"])
    network.export_har(recs, out / "traffic.har")
    (out / "analysis.json").write_text(json.dumps(analysis, indent=2))
    return {**analysis, "har": str(out / "traffic.har"),
            "flows_artifact": str(cap.flows_path)}


# ---------------------------------------------------------------- frida tools

@tool("frida_setup", "Push and start a version-matched frida-server. Needed after reboot.",
      _obj({}))
def _frida_setup(args: dict) -> dict:
    good, msg = frida_server.ensure_server(emulator.running_serial())
    return {"ok": good, "message": msg, "scripts": sorted(frida_server.list_scripts())}


@tool("frida_run",
      "Run a Frida script against a package. Built-ins: ssl_unpin (defeat certificate "
      "pinning before a capture), crypto_logger (keys/IVs/algorithms), webview_hooks "
      "(loadUrl / addJavascriptInterface / file-access settings).",
      _obj({"package": _S, "script": _S, "duration": _I, "attach": _B}, ["package"]))
def _frida_run(args: dict) -> dict:
    serial = emulator.running_serial()
    scripts = frida_server.list_scripts()
    name = args.get("script") or "ssl_unpin"
    path = scripts.get(name) or Path(name)
    good, out = frida_server.run_script(args["package"], path, serial,
                                        spawn=not args.get("attach", False),
                                        duration=args.get("duration", 25))
    return {"ok": good, "script": str(path), "output": out[:6000]}


@tool("native_trace",
      "Trace the native layer. mode=jni recovers the Java<->native mapping including "
      "dynamically-registered methods that appear NOWHERE in jadx output; mode=libc shows "
      "files/sockets/commands the native code touches; mode=exports hooks every export of "
      "the app's own .so files.",
      _obj({"package": _S, "mode": _S, "duration": _I, "modules": {"type": "array", "items": _S},
            "attach": _B}, ["package"]))
def _native_trace(args: dict) -> dict:
    serial = emulator.running_serial()
    sess = _session(args["package"])
    good, res = native_mod.trace(
        args["package"], args.get("mode", "jni"), serial=serial,
        modules=args.get("modules"), duration=args.get("duration", 25),
        spawn=not args.get("attach", False), out_dir=sess.dir / "native",
    )
    if good:
        (sess.dir / f"native_{args.get('mode','jni')}.json").write_text(json.dumps(res, indent=2))
    return {"ok": good, **res}


@tool("list_native_libs", "Native .so libraries shipped by, and currently loaded in, the app.",
      _obj({"package": _S}, ["package"]))
def _list_native_libs(args: dict) -> dict:
    serial = emulator.running_serial()
    return {"package": args["package"],
            "shipped": native_mod.list_native_libs(args["package"], serial),
            "loaded": native_mod.loaded_modules(args["package"], serial)}


# ---------------------------------------------------------------- UI tools

@tool("app_authenticate",
      "Log into the app with supplied credentials by driving the real UI, then verify we "
      "actually got past the login wall. Credentials come from a JSON file or "
      "DROID_RECON_USER/DROID_RECON_PASS and are redacted from all artifacts.",
      _obj({"package": _S, "credentials_file": _S, "username": _S, "password": _S},
           ["package"]))
def _app_authenticate(args: dict) -> dict:
    serial = emulator.running_serial()
    sess = _session(args["package"])
    if args.get("username") and args.get("password"):
        creds = explorer.Credentials(args["username"], args["password"])
    else:
        creds = explorer.Credentials.load(args.get("credentials_file"))
    from . import shell as _sh
    _sh.adb_shell(["monkey", "-p", args["package"], "-c",
                   "android.intent.category.LAUNCHER", "1"], serial=serial, timeout=30)
    import time
    time.sleep(3)
    return explorer.authenticate(args["package"], creds, serial, sess.screenshots)


@tool("explore_app",
      "Crawl the app's screens breadth-first from the current state, capturing a screenshot "
      "per screen and a transition graph. Run AFTER app_authenticate to reach post-login "
      "features. Destructive controls (logout/delete/purchase) are skipped by design.",
      _obj({"package": _S, "max_screens": _I, "max_depth": _I}, ["package"]))
def _explore_app(args: dict) -> dict:
    serial = emulator.running_serial()
    sess = _session(args["package"])
    res = explorer.explore(args["package"], serial,
                           max_screens=args.get("max_screens", 20),
                           max_depth=args.get("max_depth", 3),
                           shots=sess.screenshots)
    (sess.dir / "screen_graph.json").write_text(json.dumps(res, indent=2))
    return {**res, "artifact": str(sess.dir / "screen_graph.json")}


@tool("ui_state",
      "Current screen: focused activity, visible text, clickable elements, and a screenshot "
      "path you can read directly to see what is on screen.",
      _obj({"package": _S, "screenshot": _B}))
def _ui_state(args: dict) -> dict:
    serial = emulator.running_serial()
    xml = screen.ui_tree_xml(serial)
    items = screen.ui_summary(xml or "", max_items=60)
    shot = None
    if args.get("screenshot", True):
        sess = _session(args.get("package") or "_scratch")
        p = screen.capture(sess.screenshots, "ui_state", serial)
        shot = str(p) if p else None
    return {"focus": screen.current_focus(serial), "elements": items, "screenshot": shot}


@tool("tap", "Tap a screen coordinate.", _obj({"x": _I, "y": _I}, ["x", "y"]))
def _tap(args: dict) -> dict:
    from . import shell as _sh
    _sh.adb_shell(["input", "tap", str(args["x"]), str(args["y"])],
                  serial=emulator.running_serial(), timeout=25)
    return {"ok": True}


@tool("input_text", "Type text into the focused field.", _obj({"text": _S}, ["text"]))
def _input_text(args: dict) -> dict:
    from . import shell as _sh
    _sh.adb_shell(["input", "text", explorer._escape(args["text"])],
                  serial=emulator.running_serial(), timeout=25)
    return {"ok": True}


# ---------------------------------------------------------------- storage / analysis

@tool("read_app_storage",
      "Pull the app's private storage (shared_prefs, databases, files) and scan for "
      "credential-shaped entries, plus a world-readable scan that holds WITHOUT root.",
      _obj({"package": _S}, ["package"]))
def _read_app_storage(args: dict) -> dict:
    serial = emulator.running_serial()
    sess = _session(args["package"])
    pulled = storage.pull_private_data(args["package"], sess.storage, serial)
    return {
        "pulled": pulled,
        "prefs_secrets": storage.scan_prefs_for_secrets(sess.storage)[:30],
        "databases": storage.list_databases(sess.storage),
        "world_readable": storage.world_readable_scan(args["package"], serial)[:25],
        "note": ("shared_prefs/database contents need root to read, so they matter only "
                 "under a rooted-device or backup threat model. world_readable entries "
                 "are reachable by any app with no root at all."),
    }


@tool("build_chains",
      "Correlate every layer (manifest + code + exploits + traffic + native) into attack "
      "chains, then optionally re-run each PoC to confirm the effect reproduces. A chain "
      "needs BOTH manifest reachability and an observed effect to count.",
      _obj({"package": _S, "verify": _B}, ["package"]))
def _build_chains(args: dict) -> dict:
    sess = _session(args["package"])
    surface = sess.read_surface()
    if not surface:
        return {"ok": False, "error": "run static_analyze first"}
    exploits = []
    ep = sess.dir / "exploits.jsonl"
    if ep.exists():
        for line in ep.read_text(errors="replace").splitlines():
            if line.strip():
                try:
                    exploits.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    traffic = None
    tp = sess.dir / "network" / "analysis.json"
    if tp.exists():
        traffic = json.loads(tp.read_text())
    native = None
    gp = sess.dir / "ghidra.json"
    if gp.exists():
        blobs = json.loads(gp.read_text())
        if blobs:
            native = {"program": blobs[0].get("library"), "findings": blobs[0].get("findings")}

    built = chains_mod.build(surface, code_report=sess.read_code_report(),
                             exploit_attempts=exploits, traffic=traffic, native=native)
    if args.get("verify", True):
        serial = emulator.running_serial()
        built = [chains_mod.verify(c, package=args["package"], serial=serial)
                 for c in built]
    (sess.dir / "chains.json").write_text(
        json.dumps([c.to_dict() for c in built], indent=2))
    return {"summary": chains_mod.summarise(built),
            "chains": [c.to_dict() for c in built][:15],
            "artifact": str(sess.dir / "chains.json")}


@tool("triage", "Apply the three gates (manifest reachability + real effect + "
                "source->sink->chain) to promote observations into findings.",
      _obj({"package": _S}, ["package"]))
def _triage(args: dict) -> dict:
    sess = _session(args["package"])
    surface = sess.read_surface()
    if not surface:
        return {"ok": False, "error": "run static_analyze first"}
    res = triage_mod.triage(surface, sess.observations(), start_index=sess.count_findings())
    for f in res.findings:
        sess.add_finding(f)
    (sess.dir / "triage_candidates.json").write_text(
        json.dumps({"candidates": res.candidates, "rejected": res.rejected[:150]}, indent=2))
    return {**res.summary(),
            "findings": [f.to_dict() for f in res.findings][:15],
            "candidates": res.candidates[:15]}


@tool("get_report", "Bounded audit digest (markdown or json). Read this rather than the "
                    "raw JSONL artifacts.",
      _obj({"package": _S, "format": _S}, ["package"]))
def _get_report(args: dict) -> dict:
    sess = _session(args["package"])
    md, js, doc = report_mod.write(sess)
    if args.get("format") == "json":
        return doc
    return {"markdown": md.read_text(), "json_artifact": str(js)}


@tool("session_status", "What has been done for this package so far, and what to do next.",
      _obj({"package": _S}, ["package"]))
def _session_status(args: dict) -> dict:
    sess = _session(args["package"])
    st = sess.load_state()
    have = {
        "attack_surface": sess.surface_path.exists(),
        "code_report": sess.code_path.exists(),
        "observations": sess.count_observations(),
        "exploits": (sess.dir / "exploits.jsonl").exists(),
        "network": (sess.dir / "network" / "analysis.json").exists(),
        "native": (sess.dir / "ghidra.json").exists(),
        "chains": (sess.dir / "chains.json").exists(),
        "findings": sess.count_findings(),
    }
    nxt = []
    if not have["attack_surface"]:
        nxt.append("static_analyze")
    elif not have["code_report"]:
        nxt.append("code_analyze")
    elif not have["observations"]:
        nxt.append("probe_ipc")
    elif not have["exploits"]:
        nxt.append("exploit_campaign")
    elif not have["network"]:
        nxt.append("network_setup then network_capture")
    elif not have["chains"]:
        nxt.append("build_chains")
    else:
        nxt.append("triage then get_report")
    return {"package": args["package"], "session_dir": str(sess.dir),
            "state": st.to_dict() if st else None, "artifacts": have,
            "suggested_next": nxt}


# ---------------------------------------------------------------- JSON-RPC loop

def _result(rid, payload) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": payload}


def _error(rid, code, message) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def handle(msg: dict) -> dict | None:
    method = msg.get("method")
    rid = msg.get("id")

    if method == "initialize":
        return _result(rid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        })
    if method in ("notifications/initialized", "initialized"):
        return None  # notification: no reply
    if method == "tools/list":
        return _result(rid, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        fn = _HANDLERS.get(name)
        if fn is None:
            return _error(rid, -32601, f"unknown tool: {name}")
        try:
            out = fn(params.get("arguments") or {})
            return _result(rid, {
                "content": [{"type": "text",
                             "text": json.dumps(out, indent=2, default=str)}]
            })
        except Exception as exc:  # noqa: BLE001 - report tool errors to the agent
            return _result(rid, {
                "content": [{"type": "text", "text": json.dumps({
                    "error": str(exc),
                    "traceback": traceback.format_exc()[-1500:],
                }, indent=2)}],
                "isError": True,
            })
    if method == "ping":
        return _result(rid, {})
    if rid is None:
        return None
    return _error(rid, -32601, f"unknown method: {method}")


def serve(sessions_root: Path | None = None) -> int:
    """Newline-delimited JSON-RPC over stdio. NOT LSP Content-Length framing."""
    global _SESSIONS_ROOT
    if sessions_root:
        _SESSIONS_ROOT = sessions_root

    # Progress output would corrupt the protocol stream — silence it.
    from . import log as log_mod
    log_mod.set_quiet(True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        reply = handle(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
    return 0
