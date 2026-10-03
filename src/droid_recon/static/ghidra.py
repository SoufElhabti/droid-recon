"""Headless Ghidra analysis of native libraries.

`analyzeHeadless` is not on PATH on this machine — Homebrew installs it at
`<Cellar>/ghidra/<ver>/libexec/support/analyzeHeadless` and only links `ghidraRun`
(the GUI). Discovery below handles that, plus the common manual-install layouts.

What this extracts and why: JNI entry points (`Java_*` exports are the reachable
attack surface from the Java side), imported functions that indicate dangerous
behaviour (`system`, `exec`, `dlopen`, `strcpy`), and strings that look like embedded
secrets or endpoints. Decompilation of a specific function is available on demand —
running it over a whole library is slow and rarely what you want.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import zipfile
from pathlib import Path

from .. import shell
from ..log import ok, say, warn

ANALYZE_TIMEOUT = 1800

# Imports that change how you read a binary.
_DANGEROUS_IMPORTS = {
    "system": "command execution",
    "popen": "command execution",
    "execve": "command execution",
    "execl": "command execution",
    "dlopen": "dynamic code loading",
    "strcpy": "unbounded copy (overflow candidate)",
    "strcat": "unbounded concat (overflow candidate)",
    "sprintf": "unbounded format (overflow candidate)",
    "gets": "unbounded read",
    "memcpy": "bounded only if the length is validated",
    "ptrace": "anti-debug / debugger detection",
    "fork": "process spawning",
    "mprotect": "runtime code patching",
    "__android_log_print": "logging (check for secrets)",
}


def find_analyze_headless() -> str | None:
    """Locate analyzeHeadless across Homebrew and manual Ghidra layouts."""
    direct = shutil.which("analyzeHeadless")
    if direct:
        return direct

    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        cand = Path(env) / "support" / "analyzeHeadless"
        if cand.is_file():
            return str(cand)

    roots = [
        Path("/opt/homebrew/Cellar/ghidra"),
        Path("/usr/local/Cellar/ghidra"),
        Path("/opt/ghidra"),
        Path.home() / "ghidra",
        Path("/Applications"),
    ]
    for root in roots:
        if not root.is_dir():
            continue
        for cand in root.glob("**/support/analyzeHeadless"):
            if cand.is_file():
                return str(cand)

    # `ghidraRun` is usually the only linked binary — walk back from it.
    run = shutil.which("ghidraRun")
    if run:
        base = Path(run).resolve().parent.parent
        for cand in (base / "support" / "analyzeHeadless",
                     base / "libexec" / "support" / "analyzeHeadless"):
            if cand.is_file():
                return str(cand)
    return None


def available() -> bool:
    return find_analyze_headless() is not None


def extract_native_libs(apk: Path, dest: Path, abi_filter: str = "arm64-v8a") -> list[Path]:
    """Pull .so files out of the APK. Defaults to the emulator's ABI."""
    dest.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []
    try:
        with zipfile.ZipFile(apk) as zf:
            for name in zf.namelist():
                if not (name.startswith("lib/") and name.endswith(".so")):
                    continue
                if abi_filter and abi_filter not in name:
                    continue
                target = dest / Path(name).name
                with zf.open(name) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                out.append(target)
    except (zipfile.BadZipFile, OSError) as exc:
        warn(f"could not extract native libs: {exc}")
    return out


# Ghidra post-script.
#
# Written in JAVA, not Python, on purpose. Ghidra 12 routes `.py` post-scripts to
# PyGhidra (CPython) rather than the bundled Jython, and headless runs fail with
# "Ghidra was not started with PyGhidra. Python is not available" — verified on
# Ghidra 12.0.4. Java scripts are compiled by Ghidra at runtime and need no extra
# interpreter, so they work on every install.
#
# JSON is assembled by hand rather than via Gson: the classpath available to a headless
# script is not guaranteed, and a missing import here would fail exactly the same silent
# way the Python provider did.
_POST_SCRIPT_JAVA = r'''
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.util.*;

public class DroidReconExport extends GhidraScript {

    private String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7e) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        Program prog = currentProgram;
        FunctionManager fm = prog.getFunctionManager();
        Listing listing = prog.getListing();

        StringBuilder funcs = new StringBuilder("[");
        StringBuilder jni = new StringBuilder("[");
        int total = 0, nJni = 0, emitted = 0;

        for (Function f : fm.getFunctions(true)) {
            total++;
            String name = f.getName();
            String entry = "{\"name\":\"" + esc(name) + "\",\"addr\":\""
                    + f.getEntryPoint() + "\",\"size\":" + f.getBody().getNumAddresses()
                    + ",\"params\":" + f.getParameterCount()
                    + ",\"external\":" + f.isExternal()
                    + ",\"thunk\":" + f.isThunk() + "}";
            if (emitted < 2000) {
                if (emitted > 0) funcs.append(",");
                funcs.append(entry);
                emitted++;
            }
            if (name.startsWith("Java_")) {
                if (nJni > 0) jni.append(",");
                jni.append(entry);
                nJni++;
            }
        }
        funcs.append("]");
        jni.append("]");

        StringBuilder imports = new StringBuilder("[");
        Set<String> seen = new TreeSet<String>();
        SymbolTable st = prog.getSymbolTable();
        for (Symbol s : st.getExternalSymbols()) seen.add(s.getName());
        // Imported thunks show up as external functions too.
        for (Function f : fm.getExternalFunctions()) seen.add(f.getName());
        boolean first = true;
        for (String s : seen) {
            if (!first) imports.append(",");
            imports.append("\"").append(esc(s)).append("\"");
            first = false;
        }
        imports.append("]");

        StringBuilder strs = new StringBuilder("[");
        int nStr = 0;
        DataIterator di = listing.getDefinedData(true);
        while (di.hasNext() && nStr < 4000) {
            Data d = di.next();
            try {
                if (d.hasStringValue()) {
                    String v = d.getValue().toString();
                    if (v.length() >= 6) {
                        if (nStr > 0) strs.append(",");
                        strs.append("{\"addr\":\"").append(d.getAddress())
                            .append("\",\"value\":\"")
                            .append(esc(v.length() > 300 ? v.substring(0, 300) : v))
                            .append("\"}");
                        nStr++;
                    }
                }
            } catch (Exception e) { /* undefined data */ }
        }
        strs.append("]");

        println("DROID_RECON_JSON_BEGIN");
        println("{\"program\":\"" + esc(prog.getName())
                + "\",\"arch\":\"" + esc(prog.getLanguage().getProcessor().toString())
                + "\",\"functions_total\":" + total
                + ",\"jni_entry_points\":" + jni
                + ",\"imports\":" + imports
                + ",\"strings\":" + strs
                + ",\"functions\":" + funcs + "}");
        println("DROID_RECON_JSON_END");
    }
}
'''

# Kept for reference / non-headless use where Jython is available.
_POST_SCRIPT = r'''
# droid-recon: export functions, imports, JNI entry points and strings.
import json
from ghidra.program.model.symbol import SourceType

prog = currentProgram
fm = prog.getFunctionManager()
listing = prog.getListing()

funcs = []
jni = []
for f in fm.getFunctions(True):
    name = f.getName()
    entry = {
        "name": name,
        "addr": str(f.getEntryPoint()),
        "size": f.getBody().getNumAddresses(),
        "params": f.getParameterCount(),
        "external": f.isExternal(),
        "thunk": f.isThunk(),
    }
    funcs.append(entry)
    if name.startswith("Java_"):
        jni.append(entry)

imports = []
st = prog.getSymbolTable()
for sym in st.getExternalSymbols():
    imports.append(sym.getName())

strings = []
di = listing.getDefinedData(True)
while di.hasNext():
    d = di.next()
    try:
        if d.hasStringValue():
            v = str(d.getValue())
            if len(v) >= 6:
                strings.append({"addr": str(d.getAddress()), "value": v[:300]})
    except:
        pass
    if len(strings) > 4000:
        break

result = {
    "program": prog.getName(),
    "arch": str(prog.getLanguage().getProcessor()),
    "functions_total": len(funcs),
    "jni_entry_points": jni,
    "imports": sorted(set(imports)),
    "strings": strings,
    "functions": funcs[:2000],
}
print("DROID_RECON_JSON_BEGIN")
print(json.dumps(result))
print("DROID_RECON_JSON_END")
'''


def analyse(so_path: Path, work_dir: Path, *, timeout: int = ANALYZE_TIMEOUT,
            force: bool = False) -> dict | None:
    """Run headless Ghidra over one .so. Cached by file name in `work_dir`."""
    exe = find_analyze_headless()
    if not exe:
        warn("Ghidra analyzeHeadless not found — set GHIDRA_INSTALL_DIR or install Ghidra")
        return None

    work_dir.mkdir(parents=True, exist_ok=True)
    cache = work_dir / f"{so_path.stem}.ghidra.json"
    if cache.exists() and not force:
        say("ghidra", f"cache hit for {so_path.name}")
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    script_dir = work_dir / "scripts"
    script_dir.mkdir(exist_ok=True)
    script = script_dir / "DroidReconExport.java"
    script.write_text(_POST_SCRIPT_JAVA, encoding="utf-8")

    project_dir = work_dir / "proj"
    project_dir.mkdir(exist_ok=True)

    say("ghidra", f"analysing {so_path.name} (headless, up to {timeout}s)")
    proc = shell.run([
        exe, str(project_dir), "droid_recon",
        "-import", str(so_path),
        "-overwrite",
        "-scriptPath", str(script_dir),
        "-postScript", "DroidReconExport.java",
        "-deleteProject",
    ], timeout=timeout)

    blob = _extract_json(proc.stdout)
    if blob is None:
        warn(f"Ghidra produced no result for {so_path.name} "
             f"(rc={proc.rc}, timed_out={proc.timed_out})")
        tail = (proc.stdout + proc.stderr).strip()[-400:]
        if tail:
            warn(f"  tail: {tail}")
        return None

    blob["source_file"] = str(so_path)
    blob["findings"] = _interpret(blob)
    cache.write_text(json.dumps(blob, indent=2), encoding="utf-8")
    ok(f"{so_path.name}: {blob.get('functions_total', 0)} functions, "
       f"{len(blob.get('jni_entry_points', []))} JNI entry points")
    return blob


# Ghidra decorates every `println` from a script:
#   INFO  DroidReconExport.java> <the actual text> (GhidraScript)
# Extracting the payload therefore means stripping that wrapper line by line, not just
# slicing between the markers — a naive slice captures the log furniture and the JSON
# never parses.
_GHIDRA_LINE = re.compile(
    r"^(?:INFO|WARN|ERROR)\s+\S+?>\s?(?P<body>.*?)\s*\(GhidraScript\)\s*$"
)


def _script_output_lines(stdout: str) -> list[str]:
    out = []
    for line in stdout.splitlines():
        m = _GHIDRA_LINE.match(line.rstrip())
        out.append(m.group("body") if m else line.rstrip())
    return out


def _extract_json(stdout: str) -> dict | None:
    lines = _script_output_lines(stdout)
    try:
        start = lines.index("DROID_RECON_JSON_BEGIN")
        end = lines.index("DROID_RECON_JSON_END", start + 1)
    except ValueError:
        return None
    blob = "\n".join(lines[start + 1:end]).strip()
    if not blob:
        return None
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        return None


# Secrets worth flagging in a binary's string table.
_SECRET_RE = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "embedded private key"),
    (re.compile(r"https?://[A-Za-z0-9.\-]+"), "endpoint URL"),
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*\S{6,}"),
     "credential-shaped literal"),
]


def _interpret(blob: dict) -> dict:
    """Turn a raw Ghidra dump into the parts a human should look at."""
    imports = blob.get("imports", [])
    dangerous = [{"symbol": i, "why": _DANGEROUS_IMPORTS[i]}
                 for i in imports if i in _DANGEROUS_IMPORTS]

    secrets: list[dict] = []
    endpoints: list[dict] = []
    for s in blob.get("strings", []):
        val = s.get("value", "")
        for rx, label in _SECRET_RE:
            if rx.search(val):
                entry = {"addr": s.get("addr"), "value": val[:160], "label": label}
                (endpoints if label == "endpoint URL" else secrets).append(entry)
                break

    jni = blob.get("jni_entry_points", [])
    return {
        "jni_entry_points": [j["name"] for j in jni][:60],
        "jni_count": len(jni),
        "dangerous_imports": dangerous,
        "secrets": secrets[:40],
        "endpoints": sorted({e["value"] for e in endpoints})[:60],
        "anti_debug": [d for d in dangerous if d["symbol"] == "ptrace"],
        "note": ("JNI entry points are the functions reachable from Java — start there. "
                 "Decompile a specific one with `droid-recon ghidra decompile`."),
    }


def decompile_function(so_path: Path, function: str, work_dir: Path,
                       timeout: int = ANALYZE_TIMEOUT) -> str | None:
    """Decompile one function to C. Targeted, because whole-library decompile is slow."""
    exe = find_analyze_headless()
    if not exe:
        return None

    script_dir = work_dir / "scripts"
    script_dir.mkdir(parents=True, exist_ok=True)
    safe = function.replace('"', '\\"')
    (script_dir / "DroidReconDecompile.java").write_text(
        "import ghidra.app.script.GhidraScript;\n"
        "import ghidra.app.decompiler.*;\n"
        "import ghidra.program.model.listing.*;\n"
        "import ghidra.util.task.ConsoleTaskMonitor;\n"
        "public class DroidReconDecompile extends GhidraScript {\n"
        "  public void run() throws Exception {\n"
        "    String target = \"" + safe + "\";\n"
        "    DecompInterface di = new DecompInterface();\n"
        "    di.openProgram(currentProgram);\n"
        "    for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {\n"
        "      if (f.getName().equals(target) || f.getName().contains(target)) {\n"
        "        DecompileResults r = di.decompileFunction(f, 120, new ConsoleTaskMonitor());\n"
        "        if (r.decompileCompleted()) {\n"
        "          println(\"DROID_RECON_C_BEGIN\");\n"
        "          println(r.getDecompiledFunction().getC());\n"
        "          println(\"DROID_RECON_C_END\");\n"
        "        }\n"
        "        break;\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n", encoding="utf-8")
    project_dir = work_dir / "proj"
    project_dir.mkdir(parents=True, exist_ok=True)
    proc = shell.run([
        exe, str(project_dir), "droid_recon_dec",
        "-import", str(so_path), "-overwrite",
        "-scriptPath", str(script_dir),
        "-postScript", "DroidReconDecompile.java",
        "-deleteProject",
    ], timeout=timeout)
    lines = _script_output_lines(proc.stdout)
    try:
        start = lines.index("DROID_RECON_C_BEGIN")
        end = lines.index("DROID_RECON_C_END", start + 1)
    except ValueError:
        return None
    return "\n".join(lines[start + 1:end]).strip() or None
