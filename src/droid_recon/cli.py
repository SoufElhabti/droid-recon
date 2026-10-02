"""droid-recon CLI.

Design note: every subcommand prints machine-readable JSON to **stdout** and human
progress to **stderr**, and every long output is top-N bounded. That is what lets an
orchestrator (Claude Code, a shell script, CI) drive this without a dedicated protocol —
no MCP server or LLM client is needed in this process.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
from pathlib import Path

from . import diff as apk_diff
from . import apk_identity, doctor, evidence, log, report, runs, shell, triage
from .device import (bootstrap, certs, emulator, exploit, explorer, install, network, ordinary,
                     payloads, probes, screen, storage)
from .log import die, ok, say, warn
from .models import SessionState
from .session import DEFAULT_ROOT, Session
from .static import decompile, flows, ghidra, intents, lottie, manifest, resources, sweep, urimatcher
from . import chains as chains_mod
from .transport import FridaTransportConfig, TransportConfig
from .device_agent.deploy import ensure_agent


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
    surface = manifest.analyze(apks)
    session = _session_for(surface, args)
    session.begin_coverage_run()

    if not args.no_resources:
        decoded = resources.analyze_all(apks, decompile.DEFAULT_CACHE.parent / "res")
        surface.fileprovider_paths = decoded["fileprovider_paths"]
        for nsc in decoded["network_configs"]:
            surface.app_issues.extend(
                f"networkSecurityConfig ({Path(nsc['source_apk']).name}): {issue}"
                for issue in nsc["issues"]
            )
        for entry in decoded["status"]:
            session.record_coverage(
                "resources", entry["status"], component=entry["apk"],
                reason=entry.get("reason"),
            )
    else:
        session.record_coverage("resources", "skipped", reason="--no-resources")

    session.write_surface(surface)
    evidence.record(session.dir, surface, args=args)
    for component in surface.components:
        session.record_coverage(
            "manifest", "tested", component=component.name,
            result_state=("STATIC_CANDIDATE" if component.issues and
                          component.reachable_from in ("browser", "third_party_app")
                          else None),
        )

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
             "authorities": c.authorities, "deeplinks": c.deeplinks()[:5], "issues": c.issues,
             "provider_reach": ({operation: c.provider_reach(operation)
                                 for operation in ("read", "write", "call")}
                                if c.type == "provider" else None)}
            for c in surface.components
            if c.publicly_reachable
        ][:40],
        "artifact": str(session.surface_path),
    })
    return 0


# ---- code ----

def cmd_code(args) -> int:
    apks = _resolve_target(args.target)
    surface = manifest.analyze(apks)
    session = _session_for(surface, args)

    existing = session.read_surface()
    if existing and apk_identity.same_surface(existing, surface):
        surface = existing
    else:
        session.write_surface(surface)

    tree = decompile.decompile(apks, surface.apk_sha256, force=args.force,
                               timeout=args.timeout)
    if tree is None:
        session.add_dead_end("jadx decompile", "produced no sources — code sweep skipped")
        session.record_coverage("code", "unsupported",
                                reason="jadx unavailable or produced no sources")
        _emit({"package": surface.package, "error": "decompile failed", "code_report": None})
        return 1

    code = sweep.sweep(tree, surface)
    authorities = sorted({a for c in surface.components for a in c.authorities})
    code.provider_paths = urimatcher.extract(tree, authorities)
    intent_extras = intents.extract(tree, [c.name for c in surface.components])
    code.lottie = lottie.analyze(tree, apks)

    doc = code.to_dict()
    doc["apk_sha256"] = surface.apk_sha256
    doc["apk_sha256s"] = surface.apk_sha256s
    doc["intent_extras"] = intent_extras
    doc["flow_candidates"] = flows.analyze(tree, surface)
    doc["focused"] = sweep.focused(code, surface, top_n=args.top)
    doc["verdict"] = sweep.verdict(surface, code)
    session.write_code_report(doc)
    session.record_coverage("code", "tested", check="jadx/source sweep",
                            result_state=("STATIC_CANDIDATE" if
                                          code.summary()["sink_hits_app"] else None))
    session.record_coverage("code", "tested", check="Intent extra extraction")
    session.record_coverage("code", "tested", check="ContentProvider path extraction")
    session.record_coverage(
        "code", "tested", check="source-to-sink candidate analysis",
        result_state=("STATIC_CANDIDATE" if doc["flow_candidates"]["candidates"] else None),
    )

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
        "intent_extras": {
            "components": len(intent_extras["by_component"]),
            "unique_keys": len(intent_extras["global_keys"]),
        },
        "lottie": lottie.brief(code.lottie),
        "focused": doc["focused"],
        "artifact": str(session.code_path),
    })
    return 0


# ---- device ----

def cmd_device(args) -> int:
    if args.device_action == "up":
        serial = emulator.boot(args.avd, headless=not args.window,
                               log_path=Path(args.emulator_log) if args.emulator_log else None,
                               http_proxy=args.http_proxy)
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
    surface = manifest.analyze(apks)
    session = _session_for(surface, args)

    cached = session.read_surface()
    if cached and apk_identity.same_surface(cached, surface):
        surface = cached
    else:
        session.write_surface(surface)

    serial = _pick_serial(args)
    pkg = surface.package
    evidence.record(session.dir, surface, args=args, serial=serial,
                    execution_context="adb_shell")
    tc = TransportConfig.from_cli(args)
    agent = ensure_agent(tc.agent, serial)
    if agent:
        say("dynamic", f"device agent active on :{tc.agent.port}")
    else:
        say("dynamic", "device agent not available — using adb shell")

    state = session.load_state() or SessionState(
        session_id=f"{pkg}-dynamic", target_package=pkg, apk_paths=[str(a) for a in apks]
    )
    state.serial = serial
    state.phase = "dynamic"
    state.components_total = len(surface.components)

    # --- install (skip if already present, e.g. a system app pulled off the device) ---
    if args.no_install:
        say("device", "skipping install (--no-install)")
        session.record_coverage("install", "skipped", reason="--no-install")
    elif install.is_installed(pkg, serial) and not args.reinstall:
        say("device", f"{pkg} already installed — skipping install")
        session.record_coverage("install", "skipped", reason="already installed")
    else:
        installed, msg = install.install(apks, serial)
        if not installed:
            session.add_dead_end("install", msg[:300])
            session.record_coverage("install", "failed", reason=msg[:300])
            warn(f"install failed: {msg[:200]}")
            if not args.keep_going:
                die("install failed and --keep-going not set", 5)
        else:
            session.record_coverage("install", "tested")
    session.mark_step(state, "install")

    if getattr(args, "reset_app_data", False) and not getattr(args, "resume", False):
        cleared = shell.adb_shell(["pm", "clear", pkg], serial=serial, timeout=45)
        if cleared.ok and "Success" in cleared.stdout:
            session.record_coverage("device_reset", "tested", check="pm clear")
        else:
            session.record_coverage("device_reset", "failed", check="pm clear",
                                    reason=(cleared.stdout + cleared.stderr)[-300:])

    ctx = probes.ProbeContext(package=pkg, serial=serial,
                              capture_logcat=not args.no_logcat,
                              agent=agent)

    code = session.read_code_report() or {}
    provider_paths: dict = code.get("provider_paths") or {}

    targets = [c for c in surface.components
               if args.include_shell_only or c.publicly_reachable]
    if args.type:
        wanted = set(args.type)
        if "activity" in wanted:
            wanted.add("activity-alias")
        targets = [c for c in targets if c.type in wanted]
    target_names = {c.name for c in targets}
    for component in surface.components:
        if component.name not in target_names:
            reason = ("manifest reachability excludes an ordinary caller"
                      if not component.publicly_reachable
                      and not args.include_shell_only else "component type filter")
            session.record_coverage("ipc", "skipped", component=component.name,
                                    reason=reason)
    # Providers first: they return data, so they yield findings rather than "Status: ok".
    _ORDER = {"provider": 0, "activity": 1, "activity-alias": 1, "receiver": 2, "service": 3}
    targets.sort(key=lambda c: (_ORDER.get(c.type, 9), c.name))
    if not targets:
        warn("no third-party-reachable components — nothing an attacker could trigger. "
             "Use --include-shell-only to probe anyway (results will not be findings).")
    say("dynamic", f"probing {len(targets)} component(s) of {len(surface.components)}")

    probed = state.components_probed if getattr(args, "resume", False) else 0
    for index, comp in enumerate(targets):
        if getattr(args, "resume", False) and index < probed:
            continue
        if args.limit and probed >= args.limit:
            say("dynamic", f"stopping at --limit {args.limit}")
            for remaining in targets[index:]:
                session.record_coverage("ipc", "skipped", component=remaining.name,
                                        reason=f"--limit {args.limit}")
            break

        before_count = session.count_observations()
        if comp.type == "provider":
            _probe_provider(ctx, session, comp, provider_paths, args)
        elif comp.type in ("activity", "activity-alias"):
            _probe_activity(ctx, session, comp, args)
        elif comp.type == "receiver":
            for f in comp.intent_filters:
                for action in f.actions[:5]:
                    session.add_observation(probes.send_broadcast(ctx, comp, action))
        elif comp.type == "service":
            session.add_observation(probes.start_service(ctx, comp))

        probed += 1
        observed = session.observations()[before_count:]
        blocked = bool(observed) and all(
            o.detail.get("crash_origin") == "app_initialization" or
            o.detail.get("command_rejected") for o in observed
        )
        if blocked:
            reasons = []
            if any(o.detail.get("crash_origin") == "app_initialization" for o in observed):
                reasons.append("app initialization crashed")
            if any(o.detail.get("command_rejected") for o in observed):
                reasons.append("OS rejected the probe command")
            session.record_coverage(
                "ipc", "failed", component=comp.name,
                reason=" and ".join(reasons) + " before component code executed",
                result_state="BLOCKED", evidence_ids=[o.id for o in observed][:20],
            )
        else:
            session.record_coverage(
                "ipc", "tested", component=comp.name,
                result_state="OBSERVED" if any(o.interesting for o in observed) else
                ("INCONCLUSIVE" if any(o.signal == "crash" for o in observed) else None),
                evidence_ids=[o.id for o in observed if o.interesting or
                              o.signal == "crash"][:20],
            )
        state.components_probed = probed
        session.save_state(state)

    session.mark_step(state, "probes")

    # --- storage ---
    if not args.no_storage:
        say("dynamic", "inspecting app storage")
        pulled = storage.pull_private_data(pkg, session.storage, serial, agent=agent)
        secrets = storage.scan_prefs_for_secrets(session.storage)
        world = storage.world_readable_scan(pkg, serial, agent=agent)
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
        session.record_coverage("storage", "tested", check="private files via root")
    else:
        session.record_coverage("storage", "skipped", reason="--no-storage")

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
        shot = screen.capture(session.screenshots, comp.name.split(".")[-1], ctx.serial,
                              agent=ctx.agent)
        if shot:
            obs.screenshot = str(shot)
    session.add_observation(obs)

    for uri in comp.deeplinks()[:6]:
        d = probes.launch_deeplink(ctx, comp, uri)
        if args.screenshots and d.signal in ("ok", "crash"):
            shot = screen.capture(session.screenshots, f"deeplink_{comp.name.split('.')[-1]}",
                                  ctx.serial, agent=ctx.agent)
            if shot:
                d.screenshot = str(shot)
        session.add_observation(d)

    screen.dismiss_system_dialogs(ctx.serial, agent=ctx.agent)


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

    result = triage.triage(surface, observations)
    session.replace_findings(result.findings)
    for finding in result.findings:
        session.record_coverage(
            "triage", "tested", component=finding.component.get("name"),
            check=finding.evidence.get("stable_id", finding.id),
            result_state="OBSERVED", evidence_ids=finding.observations[:20],
        )
    if not result.findings:
        session.record_coverage("triage", "tested")

    (session.dir / "triage_candidates.json").write_text(
        json.dumps({"candidates": result.candidates, "rejected": result.rejected[:200]}, indent=2),
        encoding="utf-8",
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
        sys.stdout.write(md_path.read_text(encoding="utf-8"))
    else:
        _emit(doc)
    return 0


def cmd_doctor(args) -> int:
    _emit(doctor.inspect())
    return 0


def cmd_diff(args) -> int:
    before = manifest.analyze(args.before)
    after = manifest.analyze(args.after)
    result = apk_diff.compare(before, after)
    if args.output:
        target = Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, indent=2), encoding="utf-8")
        result["artifact"] = str(target)
    _emit(result)
    return 0


def cmd_verify_caller(args) -> int:
    """Check manifest entry points from a real, separate application UID."""
    apks = _resolve_target(args.target)
    surface = manifest.analyze(apks)
    session = _session_for(surface, args)
    serial = _pick_serial(args)
    built = (ordinary.CompanionBuild("built", Path(args.companion_apk))
             if args.companion_apk else ordinary.build_companion())
    if built.status != "built" or built.apk is None:
        session.record_coverage("ordinary_uid", "unsupported", reason=built.message)
        _emit({"package": surface.package, "status": built.status,
               "message": built.message})
        return 4
    installed = ordinary.install_companion(built.apk, serial=serial)
    if installed.status != "installed":
        session.record_coverage("ordinary_uid", "failed", reason=installed.message)
        _emit({"package": surface.package, "status": "install_failed",
               "message": installed.message})
        return 5

    code = session.read_code_report() or {}
    provider_paths = (code.get("provider_paths") or {}).get("paths", {})
    selected = [c for c in surface.components
                if not args.type or c.type in args.type or
                (c.type == "activity-alias" and "activity" in args.type)]
    if args.limit:
        for component in selected[args.limit:]:
            session.record_coverage("ordinary_uid", "skipped", component=component.name,
                                    reason=f"--limit {args.limit}")
        selected = selected[:args.limit]
    artifact = session.dir / "ordinary_results.jsonl"
    completed_requests: set[tuple[str, str, str | None, str | None, str | None]] = set()
    if getattr(args, "resume", False) and artifact.is_file():
        with artifact.open("r", encoding="utf-8", errors="replace") as source:
            for line in source:
                try:
                    previous = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if previous.get("declared_component") and previous.get("operation"):
                    completed_requests.add((
                        previous["declared_component"], previous["operation"],
                        previous.get("requested_uri"), previous.get("requested_method"),
                        previous.get("requested_action"),
                    ))
    results = []
    failures = 0
    for component in selected:
        try:
            uri = None
            if component.type == "provider" and component.authorities:
                authority = component.authorities[0]
                paths = provider_paths.get(authority) or []
                uri = f"content://{authority}/{paths[0].lstrip('/')}" if paths else None
            requests = [ordinary.request_for_component(surface.package, component, uri=uri)]
            if component.type in ("activity", "activity-alias") and component.deeplinks():
                requests.append(ordinary.request_for_component(
                    surface.package, component, operation="deeplink"))
            if component.type == "provider":
                for method in (getattr(args, "provider_method", None) or [])[:5]:
                    requests.append(ordinary.request_for_component(
                        surface.package, component, operation="provider_call",
                        method=method))
            for request in requests:
                request_key = (component.name, request.operation, request.uri,
                               request.method, request.action)
                if request_key in completed_requests:
                    continue
                result = ordinary.run_probe(
                    request, serial=serial, trusted_source=installed.verified_build)
                doc = {"component": (None if request.operation == "deeplink"
                                     else component.name),
                       "declared_component": component.name,
                       "resolution_scope": ("package" if request.operation == "deeplink"
                                            else "component"),
                       "requested_uri": request.uri,
                       "requested_method": request.method,
                       "requested_action": request.action,
                       **result.to_dict()}
                with artifact.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(doc, ensure_ascii=False) + "\n")
                results.append(doc)
                session.record_coverage(
                    "ordinary_uid", "tested",
                    component=(None if request.operation == "deeplink" else component.name),
                    check=(f"deeplink candidate {component.name}"
                           if request.operation == "deeplink" else request.operation),
                    result_state=("OBSERVED" if result.accessible is not None
                                  else "INCONCLUSIVE"),
                    evidence_ids=[request.id],
                )
        except (ValueError, OSError) as exc:
            failures += 1
            session.record_coverage("ordinary_uid", "failed", component=component.name,
                                    reason=str(exc)[:300])
    evidence.record(session.dir, surface, args=args, serial=serial,
                    execution_context="ordinary_app_uid")
    _emit({"package": surface.package, "tested": len(results),
           "accessible": sum(r["accessible"] is True for r in results),
           "denied": sum(r["accessible"] is False for r in results),
           "inconclusive": sum(r["accessible"] is None for r in results),
           "failures": failures,
           "artifact": str(artifact)})
    return 0 if failures == 0 else 6


# ---- audit (full pipeline) ----

def cmd_audit(args) -> int:
    apks = _resolve_target(args.target)
    surface = manifest.analyze(apks)
    args.package = surface.package
    session = _session_for(surface, args)
    try:
        run = runs.prepare(session, surface, args, resume=args.resume)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        die(f"cannot resume audit: {exc}", 6)
    say("audit", f"run {run['run_id'][:12]} — {'resuming' if args.resume else 'starting'}")

    def completed(step: str) -> bool:
        current = session.load_state() if args.resume else None
        return bool(current and step in current.steps_done)

    def checkpoint(step: str) -> None:
        current = session.load_state() or SessionState(
            session_id=f"{surface.package}-{run['run_id'][:12]}",
            target_package=surface.package,
            apk_paths=[str(apk) for apk in apks],
        )
        session.mark_step(current, step)

    def phase(command) -> int:
        """Keep audit stdout to one final JSON or Markdown document."""
        with contextlib.redirect_stdout(io.StringIO()):
            return command(args)

    if args.resume and completed("audit"):
        # A completed run has already written its report. Replaying it avoids
        # appending identical coverage events or changing evidence timestamps.
        md_path = session.dir / "report.md"
        json_path = session.dir / "report.json"
        if md_path.is_file() and json_path.is_file():
            try:
                saved_markdown = md_path.read_text(encoding="utf-8")
                saved_doc = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass
            else:
                if args.format == "markdown":
                    sys.stdout.write(saved_markdown)
                else:
                    _emit(saved_doc)
                return 0
        # Recover a missing or damaged report from the completed artifacts.
        return cmd_report(args)

    state = session.load_state() if args.resume else None
    if not (state and "static" in state.steps_done and session.surface_path.is_file()):
        say("audit", "phase 1 — static manifest analysis")
        rc = phase(cmd_static)
        if rc != 0:
            return rc

    if not args.skip_code:
        state = session.load_state() if args.resume else None
        if not (state and "code" in state.steps_done and session.code_path.is_file()):
            say("audit", "phase 2 — decompile + code analysis")
            try:
                phase(cmd_code)
            except SystemExit:
                session.record_coverage("code", "failed", reason="code phase exited")
                warn("code phase failed — continuing without it")
    else:
        session.record_coverage("code", "skipped", reason="--skip-code")

    say("audit", "phase 3 — device")
    serial = args.serial or emulator.running_serial()
    if not serial:
        serial = emulator.boot(args.avd, headless=not args.window)
    if not serial:
        session.record_coverage("ipc", "failed", reason="no emulator or device available")
        for stage in ("exploit", "ordinary_uid", "ui", "chains", "network", "native"):
            session.record_coverage(stage, "skipped", reason="no device available")
        warn("no device — reporting the static analysis only")
        return cmd_report(args)
    try:
        runs.bind_device(session, serial)
    except ValueError as exc:
        die(f"cannot resume audit: {exc}", 6)
    args.serial = serial
    emulator.become_root(serial)

    state = session.load_state() if args.resume else None
    if not (state and "probes" in state.steps_done):
        say("audit", "phase 4 — IPC probes")
        try:
            phase(cmd_dynamic)
        except SystemExit as exc:
            session.record_coverage("ipc", "failed", reason=f"dynamic phase exited {exc.code}")
            warn(f"dynamic phase exited ({exc.code}) — reporting what we have")

    if args.deep:
        say("audit", "deep pass — targeted payloads and ordinary-app caller")
        if not completed("exploit"):
            try:
                if phase(cmd_exploit) == 0:
                    checkpoint("exploit")
            except (SystemExit, ValueError, OSError) as exc:
                session.record_coverage("exploit", "failed", reason=str(exc)[:300])
        if not completed("ordinary_uid"):
            try:
                if phase(cmd_verify_caller) == 0:
                    checkpoint("ordinary_uid")
            except (SystemExit, ValueError, OSError) as exc:
                session.record_coverage("ordinary_uid", "failed", reason=str(exc)[:300])
    else:
        session.record_coverage("exploit", "skipped", reason="use --deep")
        session.record_coverage("ordinary_uid", "skipped", reason="use --deep")

    if (args.explore or args.deep) and not completed("ui"):
        say("audit", "exploring app screens")
        bootstrap.launch_app(surface.package, serial)
        creds = (explorer.Credentials(args.username, args.password)
                 if args.username and args.password else explorer.Credentials.load(args.credentials))
        if creds.present:
            auth = explorer.authenticate(surface.package, creds, serial, session.screenshots)
            session.record_coverage("ui", "tested", check="authentication",
                                    result_state="OBSERVED" if auth.get("authenticated") else None)
        else:
            session.record_coverage("ui", "skipped", check="authentication",
                                    reason="no test credentials supplied")
        graph = explorer.explore(surface.package, serial,
                                 max_screens=args.max_screens, max_depth=args.max_depth,
                                 shots=session.screenshots)
        (session.dir / "screen_graph.json").write_text(json.dumps(graph, indent=2),
                                                        encoding="utf-8")
        session.record_coverage("ui", "tested", check="screen exploration")
        checkpoint("ui")
    elif not (args.explore or args.deep):
        session.record_coverage("ui", "skipped", reason="use --explore or --deep")

    if args.deep and not completed("chains"):
        args.no_verify = False
        try:
            if phase(cmd_chains) == 0:
                session.record_coverage("chains", "tested")
                checkpoint("chains")
        except (SystemExit, ValueError, OSError) as exc:
            session.record_coverage("chains", "failed", reason=str(exc)[:300])
    elif not args.deep:
        session.record_coverage("chains", "skipped", reason="use --deep")
    session.record_coverage("network", "skipped", reason="run `net setup/capture` explicitly")
    session.record_coverage("native", "skipped", reason="run `native` or `ghidra` explicitly")

    say("audit", "final phase — triage + report")
    triage_rc = phase(cmd_triage)
    if triage_rc != 0:
        return triage_rc
    report_rc = cmd_report(args)
    if report_rc == 0:
        checkpoint("audit")
    return report_rc


# ---- frida ----

def cmd_frida(args) -> int:
    from .frida import server as frida_server

    serial = _pick_serial(args)
    tc = TransportConfig.from_cli(args)
    if args.frida_action == "setup":
        available, msg = frida_server.ensure_server(serial, transport=tc.frida)
        _emit({"available": available, "message": msg,
               "transport": tc.frida.mode,
               "scripts": sorted(frida_server.list_scripts())})
        return 0 if available else 7

    if args.frida_action == "run":
        available, msg = frida_server.ensure_server(serial, transport=tc.frida)
        if not available:
            warn(f"frida unavailable: {msg}")
            _emit({"available": False, "message": msg})
            return 7
        scripts = frida_server.list_scripts()
        script = scripts.get(args.script) or Path(args.script)
        succeeded, output = frida_server.run_script(
            args.package, script, serial, spawn=not args.attach, duration=args.duration,
            transport=tc.frida,
        )
        session = Session.open(args.package, Path(args.sessions))
        artifact = frida_server.persist_output(
            output, session.dir / "frida", script.stem)
        _emit({
            "ok": succeeded,
            "script": str(script),
            "output": frida_server.output_excerpt(output, 8000),
            "artifact": str(artifact) if artifact else None,
        })
        return 0 if succeeded else 7

    return 1



# ---- agent ----

def cmd_agent(args) -> int:
    from . import agent as agent_mod
    return agent_mod.run(args)


def _add_agent_args(sp) -> None:
    """Arguments shared by `droid-recon agent` and the standalone `droid-agent`."""
    sp.add_argument("task", nargs="?", default=None,
                    help="a task to run once, non-interactively; omit for an interactive REPL")
    sp.add_argument("--model", default=None,
                    help="DeepSeek model (default: $DEEPSEEK_MODEL or deepseek-chat)")
    sp.add_argument("--base-url", dest="base_url", default=None,
                    help="API base URL (default: $DEEPSEEK_BASE_URL or https://api.deepseek.com)")
    sp.add_argument("--api-key", dest="api_key", default=None,
                    help="DeepSeek API key (default: $DEEPSEEK_API_KEY)")
    sp.add_argument("--approval", choices=["auto", "suggest", "full-auto"], default="auto",
                    help="auto: ask before device-mutating tools (default); "
                         "suggest: never run them; full-auto: run everything unattended")
    sp.add_argument("--full-auto", action="store_true", help="shortcut for --approval full-auto")
    sp.add_argument("--temperature", type=float, default=0.2)
    sp.add_argument("--max-steps", dest="max_steps", type=int, default=30,
                    help="max tool calls per turn before forcing a stop")
    sp.add_argument("--check", action="store_true",
                    help="verify key/base-url/model with a tiny completion, then exit")
    sp.add_argument("--save", action="store_true",
                    help="save the transcript after a one-shot task")
    sp.add_argument("--no-color", dest="no_color", action="store_true")


def build_agent_parser(prog: str = "droid-agent") -> argparse.ArgumentParser:
    """Standalone parser for the `droid-agent` entry point."""
    p = argparse.ArgumentParser(
        prog=prog,
        description="Codex-style DeepSeek agent wired natively into droid-recon.")
    p.add_argument("--sessions", default=str(DEFAULT_ROOT),
                   help="session root shared with droid-recon")
    _add_agent_args(p)
    return p


# ---- mcp ----

def cmd_mcp(args) -> int:
    from . import mcp_server
    return mcp_server.serve(Path(args.sessions), allow_mutating=(
        True if args.allow_mutating_tools else None))


# ---- net ----

def cmd_net(args) -> int:
    serial = _pick_serial(args)
    if args.net_action == "setup":
        ca = network.ensure_ca()
        if not ca:
            die("could not obtain the mitmproxy CA (is mitmproxy installed?)", 8)
        good, msg = certs.install_system_ca(ca, serial)
        _emit({"ok": good, "message": msg, "ca": str(ca),
               "trust_store": certs.trust_status(serial)})
        return 0 if good else 8

    if args.net_action == "status":
        _emit({"trust_store": certs.trust_status(serial),
               "device_proxy": network.device_proxy(serial),
               "mitmdump": shell.which("mitmdump")})
        return 0

    if args.net_action == "reset":
        certs.remove_system_ca(serial)
        network.clear_device_proxy(serial)
        ok("trust-store overlay removed, proxy cleared")
        return 0

    if args.net_action == "capture":
        import time
        session = Session.open(args.package, Path(args.sessions))
        out = session.dir / "network"
        cap = network.start_capture(out, port=args.port)
        if cap is None:
            die("mitmdump failed to start", 8)
        network.set_device_proxy(args.port, serial)
        bootstrap.notify_proxy_change(serial)
        if not args.no_launch:
            bootstrap.launch_app(args.package, serial)
        say("net", f"capturing for {args.duration}s — exercise the app now")
        time.sleep(args.duration)
        cap.stop()
        network.clear_device_proxy(serial)
        recs = network.read_flows(cap.flows_path)
        analysis = network.analyse(recs, args.package)
        network.export_har(recs, out / "traffic.har")
        (out / "analysis.json").write_text(json.dumps(analysis, indent=2), encoding="utf-8")
        ok(analysis["interpretation"])
        _emit({**analysis, "har": str(out / "traffic.har")})
        return 0
    return 1


# ---- exploit ----

def cmd_exploit(args) -> int:
    apks = _resolve_target(args.target)
    surface = manifest.analyze(apks)
    session = _session_for(surface, args)
    existing = session.read_surface()
    if existing and apk_identity.same_surface(existing, surface):
        surface = existing
    else:
        session.write_surface(surface)
    serial = _pick_serial(args)
    tc = TransportConfig.from_cli(args)
    agent = ensure_agent(tc.agent, serial)

    wanted = set(args.type or ["activity", "receiver", "service"])
    if "activity" in wanted:
        wanted.add("activity-alias")
    comps = [c for c in surface.components
             if c.type in wanted and c.reachable_from in ("third_party_app", "browser")]
    if not comps:
        warn("no third-party-reachable components — nothing an attacker could trigger")
        _emit({"attempts": 0, "landed": 0})
        return 0

    # Stream results to disk as they happen. A campaign can run for many minutes;
    # buffering until the end means an interrupt (or a wedged device) loses everything.
    path = session.dir / "exploits.jsonl"
    code_report = session.read_code_report() or {}
    code_extras = (code_report.get("intent_extras")
                   if apk_identity.report_matches_apks(code_report, surface) else None)

    def _persist(att) -> None:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(att.to_dict()) + "\n")
        session.add_observation(att.to_observation(
            f"O{session.count_observations() + 1:04d}", surface.package))

    attempts = exploit.run_campaign(
        surface.package, comps, serial=serial,
        screenshots_dir=session.screenshots,
        max_payloads_per_component=args.max_payloads,
        code_extras=code_extras,
        on_attempt=_persist,
        agent=agent,
    )
    hits = [a for a in attempts if a.verdict.hit]
    session.record_coverage(
        "exploit", "tested", check="payload campaign",
        result_state="OBSERVED" if hits else None,
        evidence_ids=[a.payload.name for a in hits][:20],
    )
    _emit({"package": surface.package, "attempts": len(attempts), "landed": len(hits),
           "confirmed": sum(1 for a in hits if a.verdict.confidence == "confirmed"),
           "hits": [a.to_dict() for a in hits][:10], "artifact": str(path)})
    return 0


# ---- ui ----

def cmd_ui(args) -> int:
    serial = _pick_serial(args)
    session = Session.open(args.package, Path(args.sessions))
    if args.ui_action == "auth":
        if args.username and args.password:
            creds = explorer.Credentials(args.username, args.password)
        else:
            creds = explorer.Credentials.load(args.credentials)
        bootstrap.launch_app(args.package, serial)
        import time
        time.sleep(3)
        _emit(explorer.authenticate(args.package, creds, serial, session.screenshots))
        return 0
    if args.ui_action == "explore":
        res = explorer.explore(args.package, serial, max_screens=args.max_screens,
                               max_depth=args.max_depth, shots=session.screenshots)
        (session.dir / "screen_graph.json").write_text(json.dumps(res, indent=2),
                                                        encoding="utf-8")
        _emit({**res, "artifact": str(session.dir / "screen_graph.json")})
        return 0
    if args.ui_action == "state":
        xml = screen.ui_tree_xml(serial)
        shot = screen.capture(session.screenshots, "ui_state", serial)
        _emit({"focus": screen.current_focus(serial),
               "elements": screen.ui_summary(xml or "", max_items=60),
               "screenshot": str(shot) if shot else None})
        return 0
    return 1


# ---- native ----

def cmd_corpus(args) -> int:
    """Acquire APKs from an operator-configured corpus.

    Kept separate from analysis on purpose: every source has its own terms, and
    the key is always supplied by the operator rather than embedded.
    """
    from .corpus import androzoo

    if args.corpus_action == "index":
        dest = Path(args.out)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and not args.force:
            _emit({"index": str(dest), "cached": True})
            return 0
        import urllib.request, urllib.error
        try:
            with urllib.request.urlopen(androzoo.INDEX_URL, timeout=args.timeout) as resp:
                with dest.open("wb") as fh:
                    while True:
                        chunk = resp.read(1 << 22)
                        if not chunk:
                            break
                        fh.write(chunk)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            _emit({"error": f"index download failed: {exc}"})
            return 1
        _emit({"index": str(dest), "bytes": dest.stat().st_size})
        return 0

    if args.corpus_action == "fetch":
        key = args.key or os.environ.get("ANDROZOO_API_KEY")
        if not key:
            _emit({"error": "no API key — pass --key or set ANDROZOO_API_KEY"})
            return 2
        packages = list(args.package or [])
        if args.packages_file:
            packages += [ln.strip() for ln in Path(args.packages_file).read_text().splitlines()
                         if ln.strip() and not ln.startswith("#")]
        if not packages:
            _emit({"error": "no packages — pass --package or --packages-file"})
            return 2
        index = Path(args.index)
        if not index.is_file():
            _emit({"error": f"index not found: {index} (run `corpus index` first)"})
            return 2
        _emit(androzoo.fetch_packages(index, packages, key, Path(args.out)))
        return 0
    return 2


def cmd_lottie(args) -> int:
    """Batch-triage a corpus for the exploitable Lottie stack.

    Deliberately archive-only: no jadx, no device.  The point is to spend
    seconds per APK deciding which targets deserve a full `code` run.
    """
    from .static import lottie as lottie_mod

    targets: dict[str, list[Path]] = {}
    if args.installed:
        serial = _pick_serial(args)
        from .device import install as install_mod
        pulled = Path(args.out)
        pulled.mkdir(parents=True, exist_ok=True)
        for pkg in install_mod.list_packages(serial, third_party_only=True):
            dest = pulled / pkg
            dest.mkdir(parents=True, exist_ok=True)
            local = install_mod.pull_installed_apk(pkg, dest, serial)
            if local:
                targets[pkg] = local
    for raw in args.target or []:
        path = Path(raw)
        if path.is_dir():
            apks = sorted(path.glob("*.apk"))
            if apks:
                targets[path.name] = apks
        elif path.is_file():
            targets[path.name] = [path]

    if not targets:
        _emit({"error": "no targets — pass APK paths/directories or --installed"})
        return 2

    result = lottie_mod.scan_many(targets)
    _emit(result)
    return 0


def cmd_native(args) -> int:
    serial = _pick_serial(args)
    session = Session.open(args.package, Path(args.sessions))
    if args.native_action == "libs":
        from .frida import native as native_mod
        _emit({"shipped": native_mod.list_native_libs(args.package, serial),
               "loaded": native_mod.loaded_modules(args.package, serial)})
        return 0
    if args.native_action == "trace":
        from .frida import native as native_mod
        tc = TransportConfig.from_cli(args)
        good, res = native_mod.trace(args.package, args.mode, serial=serial,
                                     modules=args.module, duration=args.duration,
                                     spawn=not args.attach, out_dir=session.dir / "native",
                                     transport=tc.frida)
        if good:
            (session.dir / f"native_{args.mode}.json").write_text(
                json.dumps(res, indent=2), encoding="utf-8")
        _emit({"ok": good, **res})
        return 0 if good else 9
    return 1


# ---- ghidra ----

def cmd_ghidra(args) -> int:
    if not ghidra.available():
        die("Ghidra analyzeHeadless not found — set GHIDRA_INSTALL_DIR", 10)
    if args.ghidra_action == "analyze":
        apks = _resolve_target(args.target)
        surface = manifest.analyze(apks)
        session = _session_for(surface, args)
        work = session.dir / "native"
        libs = ghidra.extract_native_libs(apks[0], work / "libs", args.abi)
        if not libs:
            _emit({"libraries": [], "note": f"no native libraries for ABI {args.abi}"})
            return 0
        results = []
        for so in libs[: args.max_libs]:
            blob = ghidra.analyse(so, work, force=args.force)
            if blob:
                results.append({"library": so.name, "functions": blob.get("functions_total"),
                                "findings": blob.get("findings", {})})
        (session.dir / "ghidra.json").write_text(json.dumps(results, indent=2),
                                                 encoding="utf-8")
        _emit({"libraries_found": [p.name for p in libs], "analysed": results,
               "artifact": str(session.dir / "ghidra.json")})
        return 0
    if args.ghidra_action == "decompile":
        session = Session.open(args.package or "_scratch", Path(args.sessions))
        c = ghidra.decompile_function(Path(args.so), args.function, session.dir / "native")
        _emit({"function": args.function, "ok": bool(c), "c": c or ""})
        return 0 if c else 10
    return 1


# ---- chains ----

def cmd_chains(args) -> int:
    session = Session.open(args.package, Path(args.sessions))
    surface = session.read_surface()
    if surface is None:
        die("no attack_surface.json — run `droid-recon static` first", 6)
    exploits = []
    ep = session.dir / "exploits.jsonl"
    if ep.exists():
        for line in ep.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    exploits.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    traffic = None
    tp = session.dir / "network" / "analysis.json"
    if tp.exists():
        traffic = json.loads(tp.read_text(encoding="utf-8"))
    native = None
    gp = session.dir / "ghidra.json"
    if gp.exists():
        blobs = json.loads(gp.read_text(encoding="utf-8"))
        if blobs:
            native = {"program": blobs[0].get("library"), "findings": blobs[0].get("findings")}
    built = chains_mod.build(surface, code_report=session.read_code_report(),
                             exploit_attempts=exploits, traffic=traffic, native=native)
    if not args.no_verify:
        serial = getattr(args, "serial", None) or emulator.running_serial()
        built = [chains_mod.verify(c, package=args.package, serial=serial) for c in built]
    (session.dir / "chains.json").write_text(
        json.dumps([c.to_dict() for c in built], indent=2), encoding="utf-8")
    ok(f"{len(built)} chain(s), {sum(1 for c in built if c.verified)} verified")
    _emit({"summary": chains_mod.summarise(built),
           "chains": [c.to_dict() for c in built][:12],
           "artifact": str(session.dir / "chains.json")})
    return 0


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

    sp = sub.add_parser("doctor", help="show available Android analysis tools and stages")
    sp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("diff", help="compare attack surfaces across APK releases")
    sp.add_argument("before", help="old APK or split-set directory")
    sp.add_argument("after", help="new APK or split-set directory")
    sp.add_argument("--output", default=None, help="save the JSON comparison")
    sp.set_defaults(func=cmd_diff)

    sp = sub.add_parser("verify-caller",
                        help="probe IPC from a separate, unprivileged Android app")
    add_target(sp)
    sp.add_argument("--serial", default=None)
    sp.add_argument("--companion-apk", default=None,
                    help="prebuilt companion APK; otherwise build from bundled source")
    sp.add_argument("--type", action="append",
                    choices=["activity", "service", "receiver", "provider"])
    sp.add_argument("--limit", type=int, default=0)
    sp.add_argument("--provider-method", action="append", default=None,
                    help="explicit ContentProvider.call method to test as ordinary UID (repeatable)")
    sp.set_defaults(func=cmd_verify_caller)

    # static
    sp = sub.add_parser("static", help="manifest -> attack surface (no device, <2s)")
    add_target(sp)
    sp.add_argument("--no-resources", action="store_true",
                    help="skip apktool resource decode (FileProvider paths)")
    sp.set_defaults(func=cmd_static)

    # code
    sp = sub.add_parser(
        "code", help="jadx sweep + provider paths + Lottie fingerprint (Q1-Q10)")
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
    up.add_argument("--http-proxy", default=None,
                    help="route ALL device traffic via a proxy at boot, e.g. 10.0.2.2:8080 "
                         "— required for WebView traffic, which ignores the runtime setting")
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
    sp.add_argument("--no-agent", action="store_true",
                    help="skip device agent, use adb shell for everything")
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
    sp.add_argument("--resume", action="store_true",
                    help="continue the active run only if APK hashes and options match")
    sp.add_argument("--deep", action="store_true",
                    help="also run exploit probes, ordinary-app reachability, UI exploration, and chains")
    sp.add_argument("--explore", action="store_true",
                    help="explore app screens after IPC probes")
    sp.add_argument("--credentials", default=None, help="test-account JSON for UI login")
    sp.add_argument("--username", default=None, help="test-account username")
    sp.add_argument("--password", default=None, help="test-account password")
    sp.add_argument("--max-screens", type=int, default=20)
    sp.add_argument("--max-depth", type=int, default=3)
    sp.add_argument("--max-payloads", type=int, default=10)
    sp.add_argument("--companion-apk", default=None,
                    help="prebuilt ordinary-caller companion APK")
    sp.add_argument("--provider-method", action="append", default=None,
                    help="explicit ContentProvider.call method for --deep ordinary-caller check")
    sp.add_argument("--reset-app-data", action="store_true",
                    help="clear target app state after installation, before probing")
    sp.set_defaults(func=cmd_audit)

    # frida
    sp = sub.add_parser("frida", help="optional Frida instrumentation (fails soft)")
    fsub = sp.add_subparsers(dest="frida_action", required=True)
    fsub.add_parser("setup", help="push and start a matching frida-server")
    fr = fsub.add_parser("run", help="run a script against a package")
    fr.add_argument("package")
    fr.add_argument("--script", default="ssl_unpin",
                    help="built-in name (ssl_unpin, crypto_logger, webview_hooks, "
                         "lottie_tracer) or a path")
    fr.add_argument("--attach", action="store_true", help="attach instead of spawn")
    fr.add_argument("--duration", type=int, default=25, help="collection window in seconds")
    sp.add_argument("--serial", default=None)
    sp.add_argument("--frida-transport", choices=["tcp", "usb", "auto"], default="auto",
                    help="frida device connection: tcp (via port forward), usb, or auto "
                         "(try TCP first, fall back to USB). Default: auto")
    sp.set_defaults(func=cmd_frida)


    # mcp
    sp = sub.add_parser("mcp", help="run as an MCP stdio server (Claude Code / Codex)")
    sp.add_argument("--allow-mutating-tools", action="store_true",
                    help="allow MCP clients to install, probe, or otherwise change a device")
    sp.set_defaults(func=cmd_mcp)

    # agent
    sp = sub.add_parser("agent",
                        help="interactive DeepSeek agent that drives droid-recon natively")
    _add_agent_args(sp)
    sp.set_defaults(func=cmd_agent)

    # net
    sp = sub.add_parser("net", help="TLS interception: CA injection and traffic capture")
    nsub = sp.add_subparsers(dest="net_action", required=True)
    nsub.add_parser("setup", help="install the mitmproxy CA into the system trust store")
    nsub.add_parser("status", help="trust store and proxy state")
    nsub.add_parser("reset", help="remove the trust-store overlay and clear the proxy")
    ncap = nsub.add_parser("capture", help="capture and analyse app traffic")
    ncap.add_argument("package")
    ncap.add_argument("--duration", type=int, default=30)
    ncap.add_argument("--port", type=int, default=network.DEFAULT_PORT)
    ncap.add_argument("--no-launch", action="store_true")
    sp.add_argument("--serial", default=None)
    sp.set_defaults(func=cmd_net)

    # exploit
    sp = sub.add_parser("exploit", help="send IPC payloads and verify each with the oracle")
    add_target(sp)
    sp.add_argument("--serial", default=None)
    sp.add_argument("--max-payloads", type=int, default=10)
    sp.add_argument("--type", action="append",
                    choices=["activity", "service", "receiver"])
    sp.add_argument("--no-agent", action="store_true")
    sp.set_defaults(func=cmd_exploit)

    # ui
    sp = sub.add_parser("ui", help="authenticate and explore the app through its real UI")
    usub = sp.add_subparsers(dest="ui_action", required=True)
    ua = usub.add_parser("auth", help="log in with credentials and verify")
    ua.add_argument("package")
    ua.add_argument("--credentials", default=None, help="JSON file with username/password")
    ua.add_argument("--username", default=None)
    ua.add_argument("--password", default=None)
    ue = usub.add_parser("explore", help="crawl app screens (run after auth)")
    ue.add_argument("package")
    ue.add_argument("--max-screens", type=int, default=20)
    ue.add_argument("--max-depth", type=int, default=3)
    us = usub.add_parser("state", help="current screen: focus, elements, screenshot")
    us.add_argument("package")
    sp.add_argument("--serial", default=None)
    sp.set_defaults(func=cmd_ui)

    # corpus
    sp = sub.add_parser("corpus", help="acquire APKs from an operator-configured corpus")
    csub = sp.add_subparsers(dest="corpus_action", required=True)
    ci = csub.add_parser("index", help="download the AndroZoo index (multi-GB, cached)")
    ci.add_argument("--out", default="./androzoo-latest.csv.gz")
    ci.add_argument("--force", action="store_true")
    ci.add_argument("--timeout", type=int, default=3600)
    cf = csub.add_parser("fetch", help="resolve package names and download, hash-verified")
    cf.add_argument("--index", default="./androzoo-latest.csv.gz")
    cf.add_argument("--key", default=None, help="AndroZoo API key (or $ANDROZOO_API_KEY)")
    cf.add_argument("--package", action="append", help="repeatable")
    cf.add_argument("--packages-file", default=None, help="one package name per line")
    cf.add_argument("--out", default="./apk-corpus")
    sp.set_defaults(func=cmd_corpus)

    # lottie
    sp = sub.add_parser("lottie", help="batch-triage APKs for the exploitable Lottie stack")
    lsub = sp.add_subparsers(dest="lottie_action", required=True)
    ls = lsub.add_parser("scan", help="fingerprint a corpus, ranked by exploitability")
    ls.add_argument("target", nargs="*", help="APK files or directories of APKs")
    ls.add_argument("--installed", action="store_true",
                    help="pull and scan every third-party package on the device")
    ls.add_argument("--out", default="./apk-corpus", help="where --installed pulls to")
    ls.add_argument("--serial", default=None)
    sp.set_defaults(func=cmd_lottie)

    # native
    sp = sub.add_parser("native", help="native/JNI tracing via Frida")
    nvsub = sp.add_subparsers(dest="native_action", required=True)
    nl = nvsub.add_parser("libs", help="shipped and loaded .so libraries")
    nl.add_argument("package")
    nt = nvsub.add_parser("trace", help="trace the native layer")
    nt.add_argument("package")
    nt.add_argument("--mode", choices=["jni", "libc", "exports"], default="jni")
    nt.add_argument("--duration", type=int, default=25)
    nt.add_argument("--module", action="append")
    nt.add_argument("--attach", action="store_true")
    sp.add_argument("--serial", default=None)
    sp.add_argument("--frida-transport", choices=["tcp", "usb", "auto"], default="auto",
                    help="frida device connection: tcp, usb, or auto. Default: auto")
    sp.set_defaults(func=cmd_native)

    # ghidra
    sp = sub.add_parser("ghidra", help="headless Ghidra analysis of native libraries")
    gsub = sp.add_subparsers(dest="ghidra_action", required=True)
    ga = gsub.add_parser("analyze", help="JNI entry points, dangerous imports, secrets")
    ga.add_argument("target")
    ga.add_argument("--abi", default="arm64-v8a")
    ga.add_argument("--max-libs", type=int, default=3)
    ga.add_argument("--force", action="store_true")
    gd = gsub.add_parser("decompile", help="decompile one function to C")
    gd.add_argument("so")
    gd.add_argument("function")
    gd.add_argument("--package", default=None)
    sp.set_defaults(func=cmd_ghidra)

    # chains
    sp = sub.add_parser("chains", help="correlate all layers into attack chains and verify")
    sp.add_argument("package")
    sp.add_argument("--no-verify", action="store_true")
    sp.set_defaults(func=cmd_chains)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Windows often starts Python with a cp1252 console; reports contain Unicode.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    log.set_quiet(args.quiet)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        warn("interrupted — state.json is up to date; re-run to resume")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
