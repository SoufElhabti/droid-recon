"""The agent turn-loop, proven end-to-end with a scripted transport (no network, no key).

`chat_fn` is injectable, so these tests drive the whole Codex-style loop — tool schema
exposure, tool_call parsing, in-process handler execution, tool-result feedback, and the
follow-up model turn — against real droid-recon handlers. `session_status` is disk-only,
so it runs with no emulator.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from droid_recon import agent as A


def _tool_call(cid, name, args):
    return {"id": cid, "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}


def _asst(content=None, tool_calls=None):
    msg = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return {"choices": [{"message": msg,
                         "finish_reason": "tool_calls" if tool_calls else "stop"}]}


def test_tool_bridge_exposes_all_mcp_tools():
    tools = A.openai_tools()
    from droid_recon import mcp_server
    assert len(tools) == len(mcp_server.TOOLS) == 30
    for t in tools:
        assert t["type"] == "function"
        fn = t["function"]
        assert fn["name"] and fn["description"]
        assert fn["parameters"]["type"] == "object"


def test_full_turn_executes_a_real_tool_and_gets_a_final_answer():
    """Model asks for session_status -> agent runs the real handler -> model answers."""
    script = [
        _asst(tool_calls=[_tool_call("c1", "session_status",
                                     {"package": "com.does.not.exist"})]),
        _asst(content="No session exists yet; start with static_analyze."),
    ]
    seen = {"tools_sent": None}

    def chat_fn(messages, tools, *, model):
        seen["tools_sent"] = tools
        return script.pop(0)

    events = []
    agent = A.Agent(chat_fn, approval="auto", emit=lambda ev, **k: events.append((ev, k)))
    out = agent.run_turn("what's the status of com.does.not.exist?")

    assert out == "No session exists yet; start with static_analyze."
    # the model was actually offered the tool schemas
    assert seen["tools_sent"] and len(seen["tools_sent"]) == 30
    # a real tool result made it into the history and carried genuine handler output
    tool_msgs = [m for m in agent.messages if m["role"] == "tool"]
    assert len(tool_msgs) == 1
    payload = json.loads(tool_msgs[0]["content"])
    assert payload["package"] == "com.does.not.exist"
    assert payload["suggested_next"] == ["static_analyze"]
    # the loop emitted a real (not denied) tool result for a read-only tool
    assert any(ev == "tool_result" and k["name"] == "session_status" for ev, k in events)


def test_read_only_tool_never_needs_approval():
    agent = A.Agent(lambda *a, **k: None, approval="suggest",
                    ask=lambda p: (_ for _ in ()).throw(AssertionError("should not ask")))
    assert agent._approved("session_status", {}) is True
    assert agent._approved("get_report", {"package": "x"}) is True


def test_mutating_tool_denied_in_suggest_mode_and_not_executed():
    """A device-mutating tool must be refused under `suggest`, and the model told so —
    without ever touching a device."""
    script = [
        _asst(tool_calls=[_tool_call("c1", "device_up", {"avd": "webview_lab"})]),
        _asst(content="Understood, I won't boot the emulator."),
    ]
    agent = A.Agent(lambda m, t, *, model: script.pop(0), approval="suggest",
                    ask=lambda p: (_ for _ in ()).throw(AssertionError("should not ask")))
    out = agent.run_turn("boot the device")
    assert out == "Understood, I won't boot the emulator."
    tool_msgs = [m for m in agent.messages if m["role"] == "tool"]
    assert "denied" in tool_msgs[0]["content"]


def test_full_auto_approves_mutating_tools():
    agent = A.Agent(lambda *a, **k: None, approval="full-auto")
    assert agent._approved("device_up", {"avd": "x"}) is True
    assert agent._approved("exploit_campaign", {"target": "x"}) is True


def test_max_steps_stops_a_runaway_loop():
    """A model that only ever asks for tools must not loop forever."""
    def chat_fn(m, t, *, model):
        return _asst(tool_calls=[_tool_call("c", "session_status", {"package": "x"})])
    warned = []
    agent = A.Agent(chat_fn, approval="auto", max_steps=3,
                    emit=lambda ev, **k: warned.append(ev) if ev == "warn" else None)
    assert agent.run_turn("go") is None
    assert "warn" in warned


def test_reasoning_content_is_stripped_from_history():
    """deepseek-reasoner's reasoning_content must never be echoed back."""
    resp = {"choices": [{"message": {"role": "assistant", "content": "hi",
                                     "reasoning_content": "secret chain of thought"}}]}
    agent = A.Agent(lambda *a, **k: resp)
    agent.run_turn("hello")
    asst = [m for m in agent.messages if m["role"] == "assistant"][-1]
    assert "reasoning_content" not in asst
    assert asst["content"] == "hi"


def test_check_connectivity_uses_no_tools():
    def chat_fn(messages, tools, *, model):
        assert tools is None  # connectivity probe must not send the tool array
        return {"choices": [{"message": {"content": "ok"}}]}
    okflag, detail = A.check_connectivity(chat_fn, "deepseek-chat")
    assert okflag and detail == "ok"


def test_tool_output_is_bounded():
    big = "x" * (A.MAX_TOOL_OUTPUT + 5000)
    out = A._bound(big)
    assert len(out) < len(big)
    assert "truncated" in out


def test_redaction_masks_named_fields_and_free_text_without_mutating_input():
    original = {
        "password": "open-sesame",
        "nested": {"api_key": "sk-abcdefghijklmnop", "safe": "visible"},
        "log": 'Authorization: Bearer abc123xyz\n{"refresh_token":"private-value"}',
        "url": "https://example.test/?token=secret-query",
    }
    safe = A.redact_sensitive(original)
    encoded = json.dumps(safe)
    for secret in ("open-sesame", "sk-abcdefghijklmnop", "abc123xyz",
                   "private-value", "secret-query"):
        assert secret not in encoded
    assert safe["nested"]["safe"] == "visible"
    assert original["password"] == "open-sesame"
    assert A.REDACTED in A.preview_outbound([{"role": "tool", "content": original}])


def test_model_receives_redacted_history_and_transcript_is_safe(monkeypatch, tmp_path):
    secret = "some-very-private-password"
    calls = [
        _asst(tool_calls=[_tool_call("c1", "app_authenticate",
                                     {"package": "com.x", "password": secret})]),
        _asst(content=f"Login used password={secret}"),
    ]
    seen = []

    def chat_fn(messages, tools, *, model):
        seen.append(json.dumps(messages))
        return calls.pop(0)

    monkeypatch.setattr(A, "run_tool", lambda name, args: {
        "password": args["password"], "Authorization": f"Bearer {secret}",
        "long": "x" * (A.MAX_TOOL_OUTPUT + 2000),
    })
    events = []
    agent = A.Agent(chat_fn, approval="full-auto",
                    emit=lambda ev, **kw: events.append((ev, kw)))
    answer = agent.run_turn(f"Please use password={secret} to log in")
    assert secret not in answer
    assert all(secret not in sent for sent in seen)
    assert len(agent.messages[-1]["content"]) < A.MAX_TOOL_OUTPUT + 150
    assert "truncated" in agent.messages[-1]["content"] or any(
        "truncated" in m.get("content", "") for m in agent.messages if m["role"] == "tool")
    assert all(secret not in json.dumps(payload) for _, payload in events)
    output = A._save_transcript(agent, tmp_path / "transcript.json")
    assert secret not in output.read_text(encoding="utf-8")


def test_loopback_endpoint_validation_and_keyless_local_transport(monkeypatch):
    assert A.is_loopback_endpoint("http://127.0.0.1:11434/v1")
    assert A.is_loopback_endpoint("http://[::1]:8000/v1")
    assert A.is_loopback_endpoint("http://localhost:1234/v1")
    assert not A.is_loopback_endpoint("http://localhost.evil.test/v1")
    assert not A.is_loopback_endpoint("http://user:pass@localhost:1234/v1")

    captured = {}

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"choices":[{"message":{"content":"ok"}}]}'

    class Opener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return Reply()

    def fake_build_opener(handler):
        assert isinstance(handler, A._NoRedirect)
        return Opener()

    monkeypatch.setattr(A.urllib.request, "build_opener", fake_build_opener)
    A.deepseek_chat([{"role": "user", "content": "api_key=private-key"}], None,
                    api_key=None, base_url="http://127.0.0.1:11434/v1")
    request = captured["request"]
    assert request.get_header("Authorization") is None
    assert "private-key" not in request.data.decode("utf-8")
    assert A.REDACTED in request.data.decode("utf-8")


def test_remote_endpoint_without_key_or_https_is_rejected_before_transport(monkeypatch):
    monkeypatch.setattr(A.urllib.request, "build_opener",
                        lambda *args: (_ for _ in ()).throw(AssertionError("no transport")))
    for base_url, key in [
        ("https://api.example.test/v1", None),
        ("http://api.example.test/v1", "secret"),
        ("http://localhost.evil.test/v1", None),
    ]:
        try:
            A.deepseek_chat([], None, api_key=key, base_url=base_url)
        except A.DeepSeekError:
            pass
        else:
            raise AssertionError(f"unsafe endpoint accepted: {base_url}")


def test_explicit_local_run_ignores_remote_key_from_environment(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-environment-secret")
    captured = {}

    def fake_chat_fn(api_key, **kwargs):
        captured["api_key"] = api_key
        captured["base_url"] = kwargs["base_url"]
        return lambda *args, **kw: None

    monkeypatch.setattr(A, "make_chat_fn", fake_chat_fn)
    monkeypatch.setattr(A, "repl", lambda agent, **kwargs: 0)
    args = SimpleNamespace(base_url="http://127.0.0.1:11434/v1", api_key=None,
                           model="local-model", sessions=None, task=None, check=False,
                           no_color=True, approval="suggest", full_auto=False,
                           max_steps=2)
    assert A.run(args) == 0
    assert captured == {"api_key": None, "base_url": args.base_url}


def test_private_storage_read_requires_approval():
    assert "read_app_storage" not in A.READ_ONLY
    agent = A.Agent(lambda *args, **kw: None, approval="suggest")
    assert agent._approved("read_app_storage", {"package": "x"}) is False
