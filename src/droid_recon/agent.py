"""droid-agent — a Codex-architecture coding/audit agent for DeepSeek, wired natively
into droid-recon.

Architecture (mirrors OpenAI's Codex CLI):

  * A single **agentic turn loop**: user text -> model -> tool_calls -> execute ->
    feed results back -> repeat until the model answers with prose instead of a tool
    call. `Agent.run_turn` is that loop.
  * **Tools are function-calls.** droid-recon already publishes 29 tool schemas and their
    in-process handlers (`mcp_server.TOOLS` / `mcp_server._HANDLERS`). We expose them to
    the model as OpenAI-style `tools` and execute them **in this process** — no MCP
    subprocess, no JSON-RPC round trip. That is what "natively interactive" means here.
  * **Approval policy**, like Codex's suggest / auto-edit / full-auto. Read-only tools run
    unattended; anything that touches the device, sends a payload, or installs an APK
    asks first (unless full-auto).
  * **Transport is injectable.** `Agent` takes a `chat_fn`; the default speaks the DeepSeek
    chat-completions API over stdlib urllib (zero third-party deps, matching the project).
    Tests inject a scripted `chat_fn` to exercise the whole loop with no network.

DeepSeek is OpenAI-compatible: POST {base_url}/chat/completions with a Bearer key, a
`messages` array, and a `tools` array; it replies with `choices[0].message.tool_calls`
(arguments as a JSON string) and `finish_reason == "tool_calls"` until it is done.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from . import mcp_server
from .permissions import READ_ONLY
from .session import DEFAULT_ROOT

# ---------------------------------------------------------------- configuration

DEFAULT_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEFAULT_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
API_KEY_ENV = ("DEEPSEEK_API_KEY", "DEEPSEEK_KEY")
MAX_TOOL_OUTPUT = 12000          # chars fed back per tool result; handlers are already bounded
DEFAULT_MAX_STEPS = 30           # tool-calls per turn before we force a stop

SYSTEM_PROMPT = """\
You are droid-agent, an autonomous Android offensive-security operator driving the
droid-recon engine through its tools. You audit APKs for IPC/attack-surface bugs on an
emulator and produce triaged findings.

The one rule that governs everything:
  THE MANIFEST ESTABLISHES REACHABILITY. PROBES ONLY ESTABLISH EFFECT.
`adb shell` runs as the shell UID and can launch unexported components, so a probe that
"works" tells you WHAT happens, never WHO can trigger it. Judge reachability only from
`reachable_from`: `browser` and `third_party_app` can be findings; `shell` and `none`
NEVER can. "Unexported activity launched via adb" is not a bug.

Standard workflow, in order (call session_status first to see where a package stands):
  1. static_analyze  — manifest -> attack surface (fast, no device). Read `verdict`;
     stop on SKIP / LOW-signature-only.
  2. code_analyze    — recover provider paths (providers need paths, not just authorities).
  3. probe_ipc       — prefer providers first; they return data, so they yield findings.
  4. exploit_campaign / provider_sqli / network_* / frida_* — as the surface warrants.
  5. build_chains -> triage -> get_report — triage applies three gates
     (reachability + real effect + a source->sink story). Read get_report last.

A finding needs all three gates. `Status: ok` is not an effect. Dedup one misconfigured
provider queried across many paths into one finding. Drop severity for AOSP
platform-signed design behavior; do not file a design decision as a bug.

Be concise. Explain what you are about to do before a device-mutating tool call, run the
minimum tools needed, and end a task with a short evidence-backed summary. If a tool
returns an `artifact` path, only open it when you actually need the detail.
"""


class DeepSeekError(RuntimeError):
    """Transport-level failure talking to the DeepSeek API."""


REDACTED = "[REDACTED]"
_SECRET_FIELD_NAMES = frozenset({
    "password", "passwd", "passphrase", "token", "accesstoken", "refreshtoken",
    "idtoken", "apikey", "authorization", "clientsecret", "secret",
    "privatekey", "credential", "credentials", "sessioncookie", "cookie",
})
_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|passphrase|token|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|client[_-]?secret|private[_-]?key|"
    r"secret|credential|authorization)\b[\"']?\s*(?:[:=]|\bis\b)\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,&;}\]]+)"
)
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_CLI_SECRET = re.compile(
    r"(?i)(--(?:password|passwd|token|api[-_]key|secret|authorization)\s+)(\S+)"
)
_KEY_PREFIX = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


def _sensitive_field(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    return normalized in _SECRET_FIELD_NAMES or normalized.endswith(
        ("password", "passwd", "accesstoken", "refreshtoken", "apikey", "secret")
    )


def redact_text(value: str) -> str:
    """Mask common credential forms in free text, including serialized JSON/logs."""
    value = _PRIVATE_KEY.sub(REDACTED, value)
    value = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", value)
    value = _CLI_SECRET.sub(lambda m: f"{m.group(1)}{REDACTED}", value)
    value = _ASSIGNMENT.sub(lambda m: f"{m.group(1)}\"{REDACTED}\"", value)
    return _KEY_PREFIX.sub(REDACTED, value)


def redact_sensitive(value: Any) -> Any:
    """Return a detached, redacted copy suitable for a model request or transcript."""
    if isinstance(value, dict):
        return {key: (REDACTED if _sensitive_field(str(key))
                      else redact_sensitive(item)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def preview_outbound(messages: list[dict], *, max_chars: int = 4000) -> str:
    """A bounded, redacted preview of what the next model request would contain."""
    rendered = json.dumps(redact_sensitive(messages), ensure_ascii=False, indent=2,
                          default=str)
    if len(rendered) <= max_chars:
        return rendered
    return rendered[:max_chars] + f"\n...[truncated {len(rendered) - max_chars} chars]"


def is_loopback_endpoint(base_url: str) -> bool:
    """True only for a URL whose host is explicitly a loopback name or address."""
    try:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        if parts.username or parts.password or parts.query or parts.fragment:
            return False
        host = parts.hostname.lower()
        return host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_endpoint(base_url: str, api_key: str | None) -> None:
    if is_loopback_endpoint(base_url):
        return
    parts = urllib.parse.urlsplit(base_url)
    if (parts.scheme != "https" or not parts.hostname or parts.username
            or parts.password or parts.query or parts.fragment):
        raise DeepSeekError("remote model endpoints require an HTTPS URL without credentials")
    if not api_key:
        raise DeepSeekError("an API key is required for a non-loopback model endpoint")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


# ---------------------------------------------------------------- tool bridge

def openai_tools() -> list[dict]:
    """droid-recon MCP tool schemas -> OpenAI/DeepSeek function-tool specs."""
    return [
        {"type": "function", "function": {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["inputSchema"],
        }}
        for t in mcp_server.TOOLS
    ]


def run_tool(name: str, args: dict) -> Any:
    """Execute a droid-recon tool in-process. Errors are returned, not raised, so the
    model can read and recover from them (same contract as the MCP server)."""
    fn = mcp_server._HANDLERS.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}
    try:
        return fn(args or {})
    except Exception as exc:  # noqa: BLE001 — report tool errors to the model
        return {"error": str(exc), "traceback": traceback.format_exc()[-1200:]}


def _bound(text: str) -> str:
    if len(text) <= MAX_TOOL_OUTPUT:
        return text
    return (text[:MAX_TOOL_OUTPUT]
            + f"\n...[truncated {len(text) - MAX_TOOL_OUTPUT} chars; "
              "read the artifact path for full detail]")


def _short(args: dict) -> str:
    s = json.dumps(redact_sensitive(args), default=str)
    return s if len(s) <= 80 else s[:77] + "..."


# ---------------------------------------------------------------- DeepSeek transport

def deepseek_chat(messages: list[dict], tools: list[dict] | None, *,
                  api_key: str | None, base_url: str = DEFAULT_BASE_URL,
                  model: str = DEFAULT_MODEL, temperature: float = 0.2,
                  timeout: int = 180, tool_choice: str = "auto") -> dict:
    """One POST to {base_url}/chat/completions. Returns the parsed JSON response."""
    _validate_endpoint(base_url, api_key)
    url = base_url.rstrip("/") + "/chat/completions"
    body: dict[str, Any] = {
        "model": model, "messages": redact_sensitive(messages),
        "temperature": temperature, "stream": False,
    }
    if tools:
        body["tools"] = tools
        body["tool_choice"] = tool_choice
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST", headers=headers,
    )
    try:
        # Do not follow redirects: a local endpoint must not forward prompts to a
        # remote host, and an authenticated request must not leak its bearer key.
        with urllib.request.build_opener(_NoRedirect()).open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = redact_text(exc.read().decode("utf-8", "replace")[:600])
        raise DeepSeekError(f"HTTP {exc.code} from model endpoint: {detail}") from None
    except urllib.error.URLError as exc:
        raise DeepSeekError(f"cannot reach model endpoint at {url}: {exc.reason}") from None
    except (TimeoutError, http.client.HTTPException, OSError) as exc:
        # dropped connection / read timeout / reset — a transport failure, not a crash
        raise DeepSeekError(f"connection to model endpoint failed: {exc}") from None
    except json.JSONDecodeError as exc:
        raise DeepSeekError(f"malformed JSON from model endpoint: {exc}") from None


def make_chat_fn(api_key: str | None, *, base_url: str = DEFAULT_BASE_URL,
                 temperature: float = 0.2, timeout: int = 180) -> Callable:
    """Adapt the DeepSeek transport to the Agent's chat_fn(messages, tools, *, model)."""
    def chat_fn(messages: list[dict], tools: list[dict] | None, *, model: str) -> dict:
        return deepseek_chat(messages, tools, api_key=api_key, base_url=base_url,
                             model=model, temperature=temperature, timeout=timeout)
    return chat_fn


def resolve_api_key(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    for name in API_KEY_ENV:
        val = os.environ.get(name)
        if val:
            return val
    return None


def _clean_assistant(msg: dict) -> dict:
    """Rebuild the assistant message for the history, dropping fields that must not be
    echoed back (e.g. deepseek-reasoner's `reasoning_content`)."""
    out: dict[str, Any] = {"role": "assistant", "content": msg.get("content") or ""}
    if msg.get("tool_calls"):
        out["tool_calls"] = msg["tool_calls"]
    return redact_sensitive(out)


# ---------------------------------------------------------------- the agent

class Agent:
    """The Codex-style turn loop over droid-recon's tools."""

    def __init__(self, chat_fn: Callable, *, model: str = DEFAULT_MODEL,
                 approval: str = "auto", emit: Callable | None = None,
                 ask: Callable[[str], bool] | None = None,
                 max_steps: int = DEFAULT_MAX_STEPS, system: str | None = None):
        self.chat_fn = chat_fn
        self.model = model
        self.approval = approval               # auto | suggest | full-auto
        self.emit = emit or (lambda ev, **k: None)
        self.ask = ask or (lambda prompt: False)
        self.max_steps = max_steps
        self.tools = openai_tools()
        self.messages: list[dict] = [{"role": "system", "content": system or SYSTEM_PROMPT}]

    # -- approval ---------------------------------------------------------------
    def _approved(self, name: str, args: dict) -> bool:
        if name in READ_ONLY:
            return True
        if self.approval in ("full-auto", "yolo"):
            return True
        if self.approval == "suggest":
            return False
        return self.ask(f"run {name}({_short(redact_sensitive(args))})?")

    # -- one tool call ----------------------------------------------------------
    def _exec_call(self, call: dict) -> None:
        fn = call.get("function") or {}
        name = fn.get("name", "")
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {}
        self.emit("tool_call", name=name, args=redact_sensitive(args),
                  read_only=name in READ_ONLY)
        approved = self._approved(name, args)
        if not approved:
            result: Any = {"error": "denied by operator; tool not executed"}
            self.emit("tool_denied", name=name)
        else:
            result = run_tool(name, args)
        safe_result = redact_sensitive(result)
        rendered = json.dumps(safe_result, default=str)
        bounded = _bound(rendered)
        if approved:
            self.emit("tool_result", name=name,
                      result=(safe_result if len(rendered) <= MAX_TOOL_OUTPUT
                              else {"preview": bounded}))
        self.messages.append({
            "role": "tool",
            "tool_call_id": call.get("id"),
            "content": bounded,
        })

    # -- one user turn ----------------------------------------------------------
    def run_turn(self, user_text: str) -> str | None:
        self.messages.append({"role": "user", "content": redact_text(user_text)})
        for _ in range(self.max_steps):
            resp = self.chat_fn(redact_sensitive(self.messages), self.tools,
                                model=self.model)
            choice = (resp.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            self.messages.append(_clean_assistant(msg))
            calls = msg.get("tool_calls") or []
            if not calls:
                text = redact_text(msg.get("content") or "")
                self.emit("assistant", text=text)
                return text
            if msg.get("content"):
                self.emit("assistant", text=redact_text(msg["content"]))
            for call in calls:
                self._exec_call(call)
        self.emit("warn", text=f"reached max {self.max_steps} tool-steps; stopping turn")
        return None


# ---------------------------------------------------------------- terminal UI

_C = {"dim": "\033[2m", "b": "\033[1m", "cyan": "\033[36m", "green": "\033[32m",
      "yellow": "\033[33m", "red": "\033[31m", "reset": "\033[0m"}


def _color(on: bool):
    return _C if on else {k: "" for k in _C}


def _printer(color: bool = True) -> Callable:
    c = _color(color)

    def emit(ev: str, **k):
        if ev == "assistant":
            t = (k.get("text") or "").strip()
            if t:
                print(f"\n{c['green']}droid-agent{c['reset']} {t}\n")
        elif ev == "tool_call":
            tag = "ro" if k.get("read_only") else "!!"
            col = c["dim"] if k.get("read_only") else c["yellow"]
            print(f"{col}  → {k['name']}({_short(k.get('args') or {})}) [{tag}]{c['reset']}")
        elif ev == "tool_result":
            r = k.get("result")
            head = r.get("error") if isinstance(r, dict) and r.get("error") else "ok"
            print(f"{c['dim']}    {k['name']}: {str(head)[:120]}{c['reset']}")
        elif ev == "tool_denied":
            print(f"{c['red']}    {k['name']}: denied{c['reset']}")
        elif ev == "warn":
            print(f"{c['yellow']}  [!] {k.get('text')}{c['reset']}")

    return emit


def _ask_fn(color: bool = True) -> Callable[[str], bool]:
    c = _color(color)

    def ask(prompt: str) -> bool:
        try:
            ans = input(f"{c['yellow']}  approve {prompt} [y/N] {c['reset']}").strip().lower()
        except EOFError:
            return False
        return ans in ("y", "yes")

    return ask


HELP = """\
Commands:
  /help              this message
  /tools             list the droid-recon tools available to the agent
  /approval MODE     set approval: auto | suggest | full-auto
  /reset             clear the conversation (keeps system prompt)
  /preview           show a redacted preview of the conversation sent to the model
  /save [path]       write the transcript to disk
  /exit, /quit       leave
Anything else is sent to the agent. Ctrl-C aborts the current turn.
"""


def _save_transcript(agent: Agent, path: Path | None = None) -> Path:
    root = Path(DEFAULT_ROOT) / "_agent"
    root.mkdir(parents=True, exist_ok=True)
    path = path or root / f"transcript-{int(time.time())}.json"
    path.write_text(json.dumps(redact_sensitive(agent.messages), indent=2, default=str),
                    encoding="utf-8")
    return path


def repl(agent: Agent, *, color: bool = True) -> int:
    c = _color(color)
    print(f"{c['b']}droid-agent{c['reset']} — DeepSeek + droid-recon "
          f"({len(agent.tools)} tools, model={agent.model}, approval={agent.approval})")
    print(f"{c['dim']}/help for commands, /exit to quit{c['reset']}")
    while True:
        try:
            line = input(f"{c['cyan']}you>{c['reset']} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        if line in ("/exit", "/quit"):
            return 0
        if line == "/help":
            print(HELP); continue
        if line == "/tools":
            for t in mcp_server.TOOLS:
                ro = "ro" if t["name"] in READ_ONLY else "!!"
                print(f"  [{ro}] {t['name']:<18} {t['description'][:70]}")
            continue
        if line.startswith("/approval"):
            parts = line.split()
            if len(parts) == 2 and parts[1] in ("auto", "suggest", "full-auto", "yolo"):
                agent.approval = parts[1]
                print(f"  approval = {agent.approval}")
            else:
                print("  usage: /approval auto|suggest|full-auto")
            continue
        if line == "/reset":
            agent.messages = agent.messages[:1]
            print("  conversation cleared"); continue
        if line == "/preview":
            print(preview_outbound(agent.messages)); continue
        if line.startswith("/save"):
            parts = line.split(maxsplit=1)
            p = _save_transcript(agent, Path(parts[1]) if len(parts) == 2 else None)
            print(f"  saved -> {p}"); continue
        if line.startswith("/"):
            print(f"  unknown command: {line} (/help)"); continue
        try:
            agent.run_turn(line)
        except DeepSeekError as exc:
            print(f"{c['red']}  [x] {exc}{c['reset']}")
        except KeyboardInterrupt:
            print(f"\n{c['yellow']}  [!] turn aborted{c['reset']}")


# ---------------------------------------------------------------- entry points

def check_connectivity(chat_fn: Callable, model: str) -> tuple[bool, str]:
    """Minimal no-tools completion to prove the key/base_url/model work."""
    try:
        resp = chat_fn([{"role": "user", "content": "reply with the single word: ok"}],
                       None, model=model)
        txt = ((resp.get("choices") or [{}])[0].get("message") or {}).get("content", "")
        return True, txt.strip()
    except DeepSeekError as exc:
        return False, str(exc)


def run(args) -> int:
    """CLI entry (`droid-recon agent` and the `droid-agent` script share this)."""
    color = sys.stdout.isatty() and not getattr(args, "no_color", False)
    c = _color(color)
    sessions = getattr(args, "sessions", None)
    if sessions:
        mcp_server._SESSIONS_ROOT = Path(sessions)
    configured_url = getattr(args, "base_url", None) or os.environ.get("DEEPSEEK_BASE_URL")
    base_url = configured_url or "https://api.deepseek.com"
    explicit_key = getattr(args, "api_key", None)
    # A local endpoint should not receive an unrelated DeepSeek key from the
    # environment. Operators may still pass a key explicitly if it needs one.
    api_key = (explicit_key if is_loopback_endpoint(base_url) else
               resolve_api_key(explicit_key))
    if not api_key:
        if not (configured_url and is_loopback_endpoint(base_url)):
            print(f"{c['red']}[x] no API key. Set DEEPSEEK_API_KEY or pass --api-key "
                  f"for a remote endpoint; configure a loopback --base-url for a "
                  f"keyless local model.{c['reset']}", file=sys.stderr)
            return 2
    try:
        _validate_endpoint(base_url, api_key)
    except DeepSeekError as exc:
        print(f"{c['red']}[x] {exc}{c['reset']}", file=sys.stderr)
        return 2

    model = getattr(args, "model", None) or DEFAULT_MODEL
    chat_fn = make_chat_fn(api_key, base_url=base_url,
                           temperature=getattr(args, "temperature", 0.2))

    if getattr(args, "check", False):
        okflag, detail = check_connectivity(chat_fn, model)
        print(("[+] " if okflag else "[x] ") + f"{base_url} model={model}: {detail}")
        return 0 if okflag else 1

    approval = getattr(args, "approval", "auto")
    if getattr(args, "full_auto", False):
        approval = "full-auto"
    agent = Agent(chat_fn, model=model, approval=approval,
                  emit=_printer(color), ask=_ask_fn(color),
                  max_steps=getattr(args, "max_steps", DEFAULT_MAX_STEPS))

    task = getattr(args, "task", None)
    if task:  # non-interactive exec mode (like `codex exec "..."`)
        try:
            agent.run_turn(task)
        except DeepSeekError as exc:
            print(f"{c['red']}[x] {exc}{c['reset']}", file=sys.stderr)
            return 1
        if getattr(args, "save", False):
            print(f"  transcript -> {_save_transcript(agent)}")
        return 0
    return repl(agent, color=color)


def main(argv: list[str] | None = None) -> int:
    """Standalone `droid-agent` entry point (thin wrapper over the shared parser)."""
    from .cli import build_agent_parser
    parser = build_agent_parser(prog="droid-agent")
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
