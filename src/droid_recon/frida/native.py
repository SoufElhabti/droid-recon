"""Native-layer tracing: JNI boundary, .so exports, and libc syscall wrappers.

Static analysis stops at the JNI boundary — jadx shows `native byte[] decrypt(byte[])`
and nothing more. That's where keys, custom crypto, licence checks and root detection
live, so it is exactly where you need runtime visibility.

Three tracing levels, cheapest first:

  jni     RegisterNatives interception — recovers the Java<->native mapping, including
          methods registered dynamically that appear nowhere in the dex.
  exports Interceptor on each exported symbol of the target .so.
  libc    open/read/write/connect/system — what the native code touches.
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import shell
from ..log import say, warn

# ---- generated Frida scripts ----

_JNI_TRACE = r"""
// Recover the Java <-> native mapping at RegisterNatives time.
// Dynamically-registered natives never appear in the dex, so this is often the only
// way to learn they exist at all.
var out = [];
function typeName(p) { try { return Java.vm.tryGetEnv().getObjectClassName(p); } catch (e) { return "?"; } }

Interceptor.attach(Module.getExportByName(null, "__android_log_print"), {
    onEnter: function (a) {
        try { out.push({k: "log", tag: a[1].readCString(), msg: a[2].readCString()}); } catch (e) {}
    }
});

var RegisterNatives = null;
try {
    var libart = Process.findModuleByName("libart.so");
    if (libart) {
        libart.enumerateSymbols().forEach(function (s) {
            if (s.name.indexOf("RegisterNatives") !== -1 && s.name.indexOf("CheckJNI") === -1) {
                RegisterNatives = s.address;
            }
        });
    }
} catch (e) {}

if (RegisterNatives) {
    Interceptor.attach(RegisterNatives, {
        onEnter: function (args) {
            try {
                var env = args[0], klass = args[1], methods = args[2];
                var n = args[3].toInt32();
                var cname = Java.vm.tryGetEnv().getClassName(klass);
                for (var i = 0; i < n; i++) {
                    var base = methods.add(i * Process.pointerSize * 3);
                    var name = base.readPointer().readCString();
                    var sig = base.add(Process.pointerSize).readPointer().readCString();
                    var fn = base.add(Process.pointerSize * 2).readPointer();
                    var mod = Process.findModuleByAddress(fn);
                    out.push({
                        k: "register_natives", clazz: cname, method: name, sig: sig,
                        addr: fn.toString(),
                        module: mod ? mod.name : "?",
                        offset: mod ? fn.sub(mod.base).toString() : "?"
                    });
                    console.log("[jni] " + cname + "." + name + sig +
                                "  ->  " + (mod ? mod.name : "?") + "!" + (mod ? fn.sub(mod.base) : fn));
                }
            } catch (e) { console.log("[jni] error " + e); }
        }
    });
    console.log("[jni] RegisterNatives hooked");
} else {
    console.log("[jni] could not locate RegisterNatives in libart.so");
}

setTimeout(function () { console.log("[jni] JSON " + JSON.stringify(out)); }, __DURATION__ * 1000 - 800);
"""

_EXPORTS_TRACE = r"""
// Trace every exported symbol of the named modules.
var MODULES = __MODULES__;
var MAXLOG = 400;
var count = 0;

function hexdump_(p, n) {
    try { return hexdump(p, {length: n, header: false, ansi: false}).split("\n")[0]; }
    catch (e) { return "?"; }
}

MODULES.forEach(function (name) {
    var m = Process.findModuleByName(name);
    if (!m) { console.log("[native] module not loaded: " + name); return; }
    var exps = m.enumerateExports();
    console.log("[native] " + name + ": " + exps.length + " exports");
    exps.forEach(function (e) {
        if (e.type !== "function") return;
        try {
            Interceptor.attach(e.address, {
                onEnter: function (args) {
                    if (count++ > MAXLOG) return;
                    this.n = e.name;
                    console.log("[native] -> " + name + "!" + e.name +
                                " a0=" + args[0] + " a1=" + args[1]);
                },
                onLeave: function (r) {
                    if (this.n && count <= MAXLOG) {
                        console.log("[native] <- " + this.n + " = " + r);
                    }
                }
            });
        } catch (err) {}
    });
});
"""

_LIBC_TRACE = r"""
// What the native code actually touches: files, sockets, commands.
var FNS = ["open", "openat", "connect", "system", "popen", "fopen", "execve",
           "dlopen", "getenv", "unlink", "remove"];
var count = 0;
FNS.forEach(function (fn) {
    var addr = Module.findExportByName("libc.so", fn);
    if (!addr) return;
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                if (count++ > 500) return;
                var s = "?";
                try { s = args[fn === "openat" ? 1 : 0].readCString(); } catch (e) {}
                console.log("[libc] " + fn + "(" + s + ")");
            }
        });
    } catch (e) {}
});
console.log("[libc] hooks installed on " + FNS.length + " functions");
"""


def _render(template: str, duration: int, modules: list[str] | None = None) -> str:
    js = template.replace("__DURATION__", str(duration))
    if modules is not None:
        js = js.replace("__MODULES__", json.dumps(modules))
    return js


def list_native_libs(package: str, serial: str | None = None,
                     *, agent=None) -> list[str]:
    """.so files the app actually shipped (from its install dir)."""
    from ..device_agent.runtime import exec_script as _exec_script
    res = _exec_script(
        f"find /data/app -path '*{package}*' -name '*.so' 2>/dev/null | head -50",
        agent=agent, serial=serial, timeout=60,
    )
    return sorted({Path(p.strip()).name for p in res.stdout.splitlines() if p.strip()})


def loaded_modules(package: str, serial: str | None = None,
                   *, agent=None) -> list[str]:
    """.so files currently mapped into the running process — the ones worth hooking."""
    from ..device_agent.runtime import exec_on_device, exec_script as _exec_script
    pid = exec_on_device(["pidof", package], agent=agent, serial=serial,
                         timeout=20).stdout.strip().split()
    if not pid:
        return []
    res = _exec_script(
        f"cat /proc/{pid[0]}/maps 2>/dev/null | grep -o '/[^ ]*\\.so' | sort -u",
        agent=agent, serial=serial, timeout=45,
    )
    names = {Path(p.strip()).name for p in res.stdout.splitlines() if p.strip()}
    # Drop the platform's own libraries; the app's code is what matters.
    return sorted(n for n in names if not n.startswith(("libandroid", "libc.", "libm.",
                                                        "libdl.", "liblog", "libutils",
                                                        "libbinder", "libart", "libnative")))


def trace(package: str, mode: str = "jni", *, serial: str | None = None,
          modules: list[str] | None = None, duration: int = 25,
          spawn: bool = True, out_dir: Path | None = None,
          transport=None, agent=None) -> tuple[bool, dict]:
    """Run a native trace. Returns (ok, result-dict).

    `jni` is the right default: it is cheap, it works on a spawn (so it catches
    registration during startup, which `exports` misses), and its output tells you which
    modules are worth the expense of an `exports` trace.
    """
    from . import server as frida_server

    available, msg = frida_server.ensure_server(serial, transport=transport)
    if not available:
        return False, {"error": msg, "mode": mode}

    if mode == "jni":
        js = _render(_JNI_TRACE, duration)
    elif mode == "libc":
        js = _render(_LIBC_TRACE, duration)
    elif mode == "exports":
        mods = modules or loaded_modules(package, serial, agent=agent)
        if not mods:
            return False, {"error": "no app-specific .so modules loaded — "
                                    "run with the app started, or pass --module",
                           "mode": mode}
        js = _render(_EXPORTS_TRACE, duration, mods)
    else:
        return False, {"error": f"unknown trace mode: {mode}"}

    work = out_dir or Path("/tmp")
    work.mkdir(parents=True, exist_ok=True)
    script_path = work / f"native_{mode}.js"
    script_path.write_text(js, encoding="utf-8")

    say("native", f"{mode} trace on {package} ({duration}s)")
    good, output = frida_server.run_script(package, script_path, serial,
                                           spawn=spawn, duration=duration,
                                           transport=transport)
    if not good:
        return False, {"error": output[:600], "mode": mode}

    return True, _parse(mode, output)


def _parse(mode: str, output: str) -> dict:
    lines = output.splitlines()
    result: dict = {"mode": mode, "raw_lines": len(lines)}

    if mode == "jni":
        natives = []
        for line in lines:
            if line.startswith("[jni] ") and "->" in line:
                body = line[len("[jni] "):]
                java, _, native = body.partition("  ->  ")
                natives.append({"java": java.strip(), "native": native.strip()})
        result["registered_natives"] = natives
        result["count"] = len(natives)
        result["modules"] = sorted({n["native"].split("!")[0] for n in natives
                                    if "!" in n["native"]})
        result["note"] = ("Methods listed here are the JNI attack surface. Any registered "
                          "dynamically will NOT appear in jadx output — this is the only "
                          "place they show up.")

    elif mode == "exports":
        calls = [ln[len("[native] -> "):] for ln in lines if ln.startswith("[native] -> ")]
        result["calls"] = calls[:300]
        result["count"] = len(calls)
        result["modules_hooked"] = [ln for ln in lines if "exports" in ln]

    elif mode == "libc":
        calls = [ln[len("[libc] "):] for ln in lines if ln.startswith("[libc] ")]
        result["calls"] = calls[:300]
        result["count"] = len(calls)
        files = sorted({c.split("(", 1)[1].rstrip(")") for c in calls
                        if "(" in c and c.split("(")[0] in ("open", "openat", "fopen")})
        result["files_touched"] = files[:80]
        result["executed"] = [c for c in calls if c.startswith(("system(", "popen(", "execve("))]

    return result
