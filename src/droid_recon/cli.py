"""droid-recon CLI.

Design note: every subcommand prints machine-readable JSON to **stdout** and human
progress to **stderr**, and every long output is top-N bounded. That is what lets an
orchestrator (Claude Code, a shell script, CI) drive this without a dedicated protocol —
no MCP server or LLM client is needed in this process.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import log, report, shell, triage
from .device import emulator, install, probes, screen, storage
from .log import die, ok, say, warn
from .models import SessionState
from .session import DEFAULT_ROOT, Session
from .static import decompile, manifest, resources, sweep, urimatcher


# ---- helpers ----

def _emit(obj: dict) -> None:
    json.dump(obj, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _resolve_target(target: str) -> list[Path]:
    try:
        return manifest.resolve_apks(target)
    except ValueError as exc:
        die(str(exc), 2)
        raise  # unreachable; keeps type checkers happy


def _session_for(surface, args) -> Session:
    return Session.open(surface.package, Path(args.sessions))


def _pick_serial(args) -> str | None:
    if getattr(args, "serial", None):
        return args.serial
    serial = emulator.running_serial()
    if not serial:
        die("no device attached — run `droid-recon device up` first", 3)
    return serial


# ---- static ----

def cmd_static(args) -> int:
    apks = _resolve_target(args.target)
    surface = manifest.analyze(apks[0].parent if len(apks) > 1 else apks[0])
    session = _session_for(surface, args)

    if not args.no_resources:
        res_root = decompile.DEFAULT_CACHE.parent / "res" / surface.apk_sha256[:16]
        if resources.extract_resources(apks[0], res_root):
            surface.fileprovider_paths = resources.find_fileprovider_paths(res_root)
            nsc = resources.find_network_security_config(res_root)
            if nsc and nsc["issues"]:
                surface.app_issues.extend(f"networkSecurityConfig: {i}" for i in nsc["issues"])

    session.write_surface(surface)

    state = session.load_state() or SessionState(
        session_id=f"{surface.package}-{surface.analyzed_at[:10]}",
        target_package=surface.package,
        apk_paths=[str(a) for a in apks],
    )
    state.phase = "static"
    state.components_total = len(surface.components)
    session.mark_step(state, "static")

    verdict = sweep.verdict(surface)
    ok(f"{surface.package}: {verdict}")

    _emit({
        "package": surface.package,
        "session_dir": str(session.dir),
        "verdict": verdict,
        "summary": surface.summary(),
        "app_issues": surface.app_issues,
        "third_party_reachable": [
            {"name": c.name, "type": c.type, "reachable_from": c.reachable_from,
             "authorities": c.authorities, "deeplinks": c.deeplinks()[:5], "issues": c.issues}
            for c in surface.components
            if c.reachable_from in ("third_party_app", "browser")
        ][:40],
        "artifact": str(session.surface_path),
    })
    return 0


# ---- code ----

def cmd_code(args) -> int:
    apks = _resolve_target(args.target)
    surface = manifest.analyze(apks[0].parent if len(apks) > 1 else apks[0])
    session = _session_for(surface, args)

    existing = session.read_surface()
    if existing:
        surface = existing

    tree = decompile.decompile(apks[0], surface.apk_sha256, force=args.force,
                               timeout=args.timeout)
    if tree is None:
        session.add_dead_end("jadx decompile", "produced no sources — code sweep skipped")
        _emit({"package": surface.package, "error": "decompile failed", "code_report": None})
        return 1

    code = sweep.sweep(tree, surface)
    authorities = sorted({a for c in surface.components for a in c.authorities})
    code.provider_paths = urimatcher.extract(tree, authorities)

    doc = code.to_dict()
    doc["focused"] = sweep.focused(code, surface, top_n=args.top)
    doc["verdict"] = sweep.verdict(surface, code)
    session.write_code_report(doc)

    state = session.load_state() or SessionState(
        session_id=f"{surface.package}-code", target_package=surface.package
    )
    state.phase = "code"
    session.mark_step(state, "code")

    ok(f"{surface.package}: {doc['verdict']}")
    _emit({
        "package": surface.package,
        "verdict": doc["verdict"],
        "summary": code.summary(),
        "provider_paths": code.provider_paths.get("paths", {}),
        "focused": doc["focused"],
        "artifact": str(session.code_path),
    })
    return 0


# ---- device ----

def cmd_device(args) -> int:
    if args.device_action == "up":
        serial = emulator.boot(args.avd, headless=not args.window,
                               log_path=Path(args.emulator_log) if args.emulator_log else None)
        if not serial:
            die("emulator failed to become ready", 3)
        rooted = emulator.become_root(serial)
        info = emulator.device_info(serial)
        info["root"] = rooted
        _emit(info)
        return 0

    if args.device_action == "info":
        serial = _pick_serial(args)
        _emit(emulator.device_info(serial))
        return 0

    if args.device_action == "list":
        _emit({"avds": emulator.list_avds(), "attached": shell.devices()})
        return 0

    if args.device_action == "packages":
        serial = _pick_serial(args)
        pkgs = install.list_packages(serial, third_party_only=args.third_party)
        _emit({"serial": serial, "count": len(pkgs), "packages": pkgs})
        return 0

    if args.device_action == "pull":
        serial = _pick_serial(args)
        dest = Path(args.out).expanduser()
        pulled = install.pull_installed_apk(args.package, dest, serial)
        if not pulled:
            die(f"could not pull {args.package} from {serial}", 4)
        ok(f"pulled {len(pulled)} apk(s) to {dest}")
        _emit({"package": args.package, "apks": [str(p) for p in pulled]})
        return 0

    if args.device_action == "down":
        serial = _pick_serial(args)
        emulator.shutdown(serial)
        ok(f"shut down {serial}")
        return 0

    return 1


# ---- dynamic ----

def cmd_dynamic(args) -> int:
    apks = _resolve_target(args.target)
    surface = manifest.analyze(apks[0].parent if len(apks) > 1 else apks[0])
    session = _session_for(surface, args)

    cached = session.read_surface()
    if cached and cached.package == surface.package:
        surface = cached
    else:
        session.write_surface(surface)

    serial = _pick_serial(args)
    pkg = surface.package

    state = session.load_state() or SessionState(
        session_id=f"{pkg}-dynamic", target_package=pkg, apk_paths=[str(a) for a in apks]
    )
    state.serial = serial
    state.phase = "dynamic"
    state.components_total = len(surface.components)

    # --- install (skip if already present, e.g. a system app pulled off the device) ---
    if args.no_install:
        say("device", "skipping install (--no-install)")
    elif install.is_installed(pkg, serial) and not args.reinstall:
        say("device", f"{pkg} already installed — skipping install")
    else:
        installed, msg = install.install(apks, serial)
        if not installed:
            session.add_dead_end("install", msg[:300])
            warn(f"install failed: {msg[:200]}")
            if not args.keep_going:
                die("install failed and --keep-going not set", 5)
    session.mark_step(state, "install")

    ctx = probes.ProbeContext(package=pkg, serial=serial,
                              capture_logcat=not args.no_logcat)

    code = session.read_code_report() or {}
    known_paths: dict = (code.get("provider_paths") or {}).get("paths", {})

    targets = [c for c in surface.components
               if args.include_shell_only or c.reachable_from in ("third_party_app", "browser")]
    if args.type:
        wanted = set(args.type)
        if "activity" in wanted:
            wanted.add("activity-alias")
        targets = [c for c in targets if c.type in wanted]
    # Providers first: they return data, so they yield findings rather than "Status: ok".
    _ORDER = {"provider": 0, "activity": 1, "activity-alias": 1, "receiver": 2, "service": 3}
    targets.sort(key=lambda c: (_ORDER.get(c.type, 9), c.name))
    if not targets:
        warn("no third-party-reachable components — nothing an attacker could trigger. "
             "Use --include-shell-only to probe anyway (results will not be findings).")
    say("dynamic", f"probing {len(targets)} component(s) of {len(surface.components)}")

    probed = 0
    for comp in targets:
        if args.limit and probed >= args.limit:
            say("dynamic", f"stopping at --limit {args.limit}")
            break

        if comp.type == "provider":
            _probe_provider(ctx, session, comp, known_paths, args)
        elif comp.type in ("activity", "activity-alias"):
            _probe_activity(ctx, session, comp, args)
        elif comp.type == "receiver":
            for f in comp.intent_filters:
                for action in f.actions[:5]:
                    session.add_observation(probes.send_broadcast(ctx, comp, action))
        elif comp.type == "service":
            session.add_observation(probes.start_service(ctx, comp))

        probed += 1
        state.components_probed = probed
        session.save_state(state)

    session.mark_step(state, "probes")

    # --- storage ---
    if not args.no_storage:
        say("dynamic", "inspecting app storage")
        pulled = storage.pull_private_data(pkg, session.storage, serial)
        secrets = storage.scan_prefs_for_secrets(session.storage)
        world = storage.world_readable_scan(pkg, serial)
        session.write_code_report({
            **(session.read_code_report() or {}),
            "storage": {
                "pulled": pulled,
                "prefs_secrets": secrets[:50],
                "databases": storage.list_databases(session.storage),
                "world_readable": world[:50],
            },
        })
        if secrets:
            warn(f"{len(secrets)} credential-shaped entries in SharedPreferences "
                 f"(root-only visibility — see report for reachability caveats)")
        if world:
            warn(f"{len(world)} world-readable / shared-storage paths (reachable without root)")
        session.mark_step(state, "storage")

    install.stop(pkg, serial)
    state.phase = "dynamic-done"
    session.save_state(state)

    obs = session.observations()
    ok(f"{len(obs)} observations ({sum(1 for o in obs if o.interesting)} interesting)")
    _emit({
        "package": pkg,
        "serial": serial,
        "observations": len(obs),
        "interesting": sum(1 for o in obs if o.interesting),
        "session_dir": str(session.dir),
        "next": f"droid-recon triage {pkg} && droid-recon report {pkg}",
    })
    return 0


def _probe_activity(ctx, session, comp, args) -> None:
    obs = probes.launch_activity(ctx, comp)
    if args.screenshots:
        shot = screen.capture(session.screenshots, comp.name.split(".")[-1], ctx.serial)
        if shot:
            obs.screenshot = str(shot)
    session.add_observation(obs)

    for uri in comp.deeplinks()[:6]:
        d = probes.launch_deeplink(ctx, comp, uri)
        if args.screenshots and d.signal in ("ok", "crash"):
            shot = screen.capture(session.screenshots, f"deeplink_{comp.name.split('.')[-1]}",
                                  ctx.serial)
            if shot:
                d.screenshot = str(shot)
        session.add_observation(d)

    screen.dismiss_system_dialogs(ctx.serial)


def _probe_provider(ctx, session, comp, provider_paths: dict, args) -> None:
    known = provider_paths.get("paths", {})
    # Paths recovered from an addURI whose authority we couldn't resolve — worth trying
    # against any provider, but never presented as belonging to a specific one.
    floating = provider_paths.get("floating_paths", [])

    for authority in comp.authorities:
        paths = list(known.get(authority, []))
        if paths:
            paths += [p for p in floating if p not in paths][:6]
        else:
            paths = list(floating[:6]) + list(urimatcher.FALLBACK_PATHS[: args.provider_fallbacks])
            session.add_dead_end(
                f"provider {authority}",
                "no UriMatcher.addURI literals resolved to this authority — fell back to "
                "floating paths + generic guesses, which mostly return provider_error",
            )
        for path in paths[:20]:
            session.add_observation(probes.query_provider(ctx, comp, authority, path))

        # ContentProvider.call() is a distinct, commonly-forgotten entry point: it
        # bypasses the UriMatcher entirely and is frequently unguarded even when query()
        # is not. Only worth probing when we recovered real method names from the code.
        for method in provider_paths.get("call_methods", [])[:8]:
            session.add_observation(probes.call_provider(ctx, comp, authority, method))

        if args.traversal:
            for tpath in urimatcher.TRAVERSAL_PATHS:
                session.add_observation(probes.read_provider_file(ctx, comp, authority, tpath))


# ---- triage ----

def cmd_triage(args) -> int:
    session = Session.open(args.package, Path(args.sessions))
    surface = session.read_surface()
    if surface is None:
        die(f"no attack_surface.json in {session.dir} — run `droid-recon static` first", 6)

    observations = session.observations()
    if not observations:
        warn("no observations to triage — run `droid-recon dynamic` first")

    result = triage.triage(surface, observations, start_index=session.count_findings())
    for f in result.findings:
        session.add_finding(f)

    (session.dir / "triage_candidates.json").write_text(
        json.dumps({"candidates": result.candidates, "rejected": result.rejected[:200]}, indent=2)
    )

    state = session.load_state()
    if state:
        state.phase = "triaged"
        session.mark_step(state, "triage")

    ok(f"{len(result.findings)} finding(s), {len(result.candidates)} candidate(s), "
       f"{len(result.rejected)} rejected")
    _emit({
        "package": args.package,
        **result.summary(),
        "findings": [{"id": f.id, "title": f.title, "severity": f.severity,
                      "reachable_from": f.reachable_from, "poc": f.poc}
                     for f in result.findings],
        "candidates": result.candidates[:20],
        "artifact": str(session.findings_path),
    })
    return 0


# ---- report ----

def cmd_report(args) -> int:
    session = Session.open(args.package, Path(args.sessions))
    if not session.dir.exists():
        die(f"no session for {args.package} in {args.sessions}", 6)

    md_path, json_path, doc = report.write(session, top_n=args.top)
    ok(f"report -> {md_path}")

    if args.format == "markdown":
        sys.stdout.write(md_path.read_text())
    else:
        _emit(doc)
    return 0


# ---- audit (full pipeline) ----

def cmd_audit(args) -> int:
    say("audit", "phase 1/5 — static manifest analysis")
    rc = cmd_static(args)
    if rc != 0:
        return rc

    apks = _resolve_target(args.target)
    surface = manifest.analyze(apks[0].parent if len(apks) > 1 else apks[0])
    args.package = surface.package

    if not args.skip_code:
        say("audit", "phase 2/5 — decompile + code sweep")
        try:
            cmd_code(args)
        except SystemExit:
            warn("code phase failed — continuing without it")

    say("audit", "phase 3/5 — device")
    if not emulator.running_serial():
        serial = emulator.boot(args.avd, headless=not args.window)
        if serial:
            emulator.become_root(serial)
        else:
            warn("no device — stopping after static analysis")
            return cmd_report(args)
    else:
        emulator.become_root(emulator.running_serial())

    say("audit", "phase 4/5 — dynamic probes")
    try:
        cmd_dynamic(args)
    except SystemExit as exc:
        warn(f"dynamic phase exited ({exc.code}) — reporting what we have")

    say("audit", "phase 5/5 — triage + report")
    cmd_triage(args)
    return cmd_report(args)


# ---- frida ----

def cmd_frida(args) -> int:
    from .frida import server as frida_server

    serial = _pick_serial(args)
    if args.frida_action == "setup":
        available, msg = frida_server.ensure_server(serial)
        _emit({"available": available, "message": msg,
               "scripts": sorted(frida_server.list_scripts())})
        return 0 if available else 7

    if args.frida_action == "run":
        available, msg = frida_server.ensure_server(serial)
        if not available:
            warn(f"frida unavailable: {msg}")
            _emit({"available": False, "message": msg})
            return 7
        scripts = frida_server.list_scripts()
        script = scripts.get(args.script) or Path(args.script)
        succeeded, output = frida_server.run_script(
            args.package, script, serial, spawn=not args.attach, duration=args.duration
        )
        _emit({"ok": succeeded, "script": str(script), "output": output})
        return 0 if succeeded else 7

    return 1


# ---- parser ----

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="droid-recon",
        description="Android offensive-security audit engine: static attack-surface "
                    "mapping and dynamic IPC probing.",
        epilog="Reachability comes from the manifest, never from a probe's exit code — "
               "adb shell holds START_ANY_ACTIVITY and can trigger anything.",
    )
    p.add_argument("--sessions", default=str(DEFAULT_ROOT),
                   help="session root directory (default: ./sessions)")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress on stderr")
    sub = p.add_subparsers(dest="command", required=True)

    def add_target(sp):
        sp.add_argument("target", help="path to an .apk, or a directory holding a split set")

    # static
    sp = sub.add_parser("static", help="manifest -> attack surface (no device, <2s)")
    add_target(sp)
    sp.add_argument("--no-resources", action="store_true",
                    help="skip apktool resource decode (FileProvider paths)")
    sp.set_defaults(func=cmd_static)

    # code
    sp = sub.add_parser("code", help="jadx decompile + sink/source sweep + provider paths")
    add_target(sp)
    sp.add_argument("--force", action="store_true", help="ignore the jadx cache")
    sp.add_argument("--timeout", type=int, default=decompile.JADX_TIMEOUT)
    sp.add_argument("--top", type=int, default=40, help="hits to keep in the focused view")
    sp.set_defaults(func=cmd_code)

    # device
    sp = sub.add_parser("device", help="emulator lifecycle and device queries")
    dsub = sp.add_subparsers(dest="device_action", required=True)
    up = dsub.add_parser("up", help="boot the AVD and wait until genuinely ready")
    up.add_argument("--avd", default="webview_lab")
    up.add_argument("--window", action="store_true", help="show the emulator window")
    up.add_argument("--emulator-log", default=None)
    dsub.add_parser("info", help="device properties")
    dsub.add_parser("list", help="available AVDs and attached devices")
    pk = dsub.add_parser("packages", help="installed packages")
    pk.add_argument("--third-party", action="store_true")
    pl = dsub.add_parser("pull", help="pull an installed package's APKs off the device")
    pl.add_argument("package")
    pl.add_argument("--out", default="./targets")
    dsub.add_parser("down", help="shut the emulator down")
    sp.add_argument("--serial", default=None)
    sp.set_defaults(func=cmd_device)

    # dynamic
    sp = sub.add_parser("dynamic", help="install + probe IPC surface on a device")
    add_target(sp)
    sp.add_argument("--serial", default=None)
    sp.add_argument("--no-install", action="store_true")
    sp.add_argument("--reinstall", action="store_true")
    sp.add_argument("--no-logcat", action="store_true")
    sp.add_argument("--no-storage", action="store_true")
    sp.add_argument("--screenshots", action="store_true",
                    help="capture a PNG per activity (the orchestrator reads these directly)")
    sp.add_argument("--traversal", action="store_true",
                    help="also try FileProvider path-traversal reads")
    sp.add_argument("--include-shell-only", action="store_true",
                    help="probe components only adb shell can reach (never becomes a finding)")
    sp.add_argument("--provider-fallbacks", type=int, default=8,
                    help="generic provider paths to try when code yields none")
    sp.add_argument("--type", action="append",
                    choices=["activity", "service", "receiver", "provider"],
                    help="restrict probing to a component type (repeatable)")
    sp.add_argument("--limit", type=int, default=0, help="max components to probe (0 = all)")
    sp.add_argument("--keep-going", action="store_true", help="continue past install failure")
    sp.set_defaults(func=cmd_dynamic)

    # triage
    sp = sub.add_parser("triage", help="promote observations to findings (3-gate filter)")
    sp.add_argument("package")
    sp.set_defaults(func=cmd_triage)

    # report
    sp = sub.add_parser("report", help="bounded audit digest (markdown or json)")
    sp.add_argument("package")
    sp.add_argument("--format", choices=["markdown", "json"], default="markdown")
    sp.add_argument("--top", type=int, default=report.TOP_N)
    sp.set_defaults(func=cmd_report)

    # audit
    sp = sub.add_parser("audit", help="full pipeline: static -> code -> device -> probe -> report")
    add_target(sp)
    sp.add_argument("--avd", default="webview_lab")
    sp.add_argument("--window", action="store_true")
    sp.add_argument("--serial", default=None)
    sp.add_argument("--skip-code", action="store_true", help="skip jadx (much faster)")
    sp.add_argument("--no-resources", action="store_true")
    sp.add_argument("--no-install", action="store_true")
    sp.add_argument("--reinstall", action="store_true")
    sp.add_argument("--no-logcat", action="store_true")
    sp.add_argument("--no-storage", action="store_true")
    sp.add_argument("--screenshots", action="store_true")
    sp.add_argument("--traversal", action="store_true")
    sp.add_argument("--include-shell-only", action="store_true")
    sp.add_argument("--provider-fallbacks", type=int, default=8)
    sp.add_argument("--type", action="append",
                    choices=["activity", "service", "receiver", "provider"])
    sp.add_argument("--limit", type=int, default=0)
    sp.add_argument("--keep-going", action="store_true", default=True)
    sp.add_argument("--force", action="store_true")
    sp.add_argument("--timeout", type=int, default=decompile.JADX_TIMEOUT)
    sp.add_argument("--top", type=int, default=report.TOP_N)
    sp.add_argument("--format", choices=["markdown", "json"], default="markdown")
    sp.set_defaults(func=cmd_audit)

    # frida
    sp = sub.add_parser("frida", help="optional Frida instrumentation (fails soft)")
    fsub = sp.add_subparsers(dest="frida_action", required=True)
    fsub.add_parser("setup", help="push and start a matching frida-server")
    fr = fsub.add_parser("run", help="run a script against a package")
    fr.add_argument("package")
    fr.add_argument("--script", default="ssl_unpin",
                    help="built-in name (ssl_unpin, crypto_logger, webview_hooks) or a path")
    fr.add_argument("--attach", action="store_true", help="attach instead of spawn")
    fr.add_argument("--duration", type=int, default=25, help="collection window in seconds")
    sp.add_argument("--serial", default=None)
    sp.set_defaults(func=cmd_frida)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    log.set_quiet(args.quiet)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        warn("interrupted — state.json is up to date; re-run to resume")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
