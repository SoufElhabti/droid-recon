"""Code-derived Intent inputs survive analysis and reach both campaign entry points."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from droid_recon import cli, mcp_server
from droid_recon.device import exploit, payloads
from droid_recon.models import AttackSurface, Component
from droid_recon.session import Session
from droid_recon.static import intents


@pytest.fixture
def source_tree(tmp_path):
    root = tmp_path / "sources"
    source = root / "com" / "example" / "target"
    source.mkdir(parents=True)
    (source / "OpenActivity.java").write_text(
        'package com.example.target;\n'
        'class OpenActivity {\n'
        '  static final String EXTRA_URL = "server_url";\n'
        '  void open(Intent i) {\n'
        '    String url = i.getStringExtra(OpenActivity.EXTRA_URL);\n'
        '    int page = i.getIntExtra("page_number", 0);\n'
        '    double ratio = i.getDoubleExtra("ratio", 0.0);\n'
        '    Intent next = i.getParcelableExtra("next_intent");\n'
        '    if (i.hasExtra("mode_flag")) {}\n'
        '  }\n'
        '}\n', encoding="utf-8")
    return root


@pytest.fixture
def surface():
    return AttackSurface(
        package="com.example.target", apk_sha256="same-apk-hash",
        components=[Component(name="com.example.target.OpenActivity", type="activity",
                              exported=True, reachable_from="third_party_app")],
    )


def test_extractor_records_keys_types_and_source_and_skips_unsupported_typed_probe(source_tree):
    inventory = intents.extract(source_tree)
    entries = {e["key"]: e for e in inventory["by_component"]["com.example.target.OpenActivity"]}
    assert entries["server_url"]["type"] == "string"
    assert entries["server_url"]["accessor"] == "getStringExtra"
    assert entries["server_url"]["source"] == "com/example/target/OpenActivity.java"
    assert entries["server_url"]["line"] == 5
    assert entries["page_number"]["type"] == "int"
    assert entries["ratio"]["type"] == "double"
    assert entries["next_intent"]["type"] == "parcelable"
    assert entries["mode_flag"]["type"] == "unknown"

    generated = payloads.for_component("activity", "com.example.target", list(entries.values()))
    typed = {p.extras[0].key: p for p in generated if p.name.startswith("typed_")}
    assert typed["page_number"].extras[0].to_args() == ["--ei", "page_number", "-1"]
    assert typed["server_url"].extras[0].to_args()[0] == "--es"
    assert "next_intent" not in typed  # `am` cannot construct a Parcelable.
    assert "ratio" not in typed  # `--ef` creates Float, not Double.
    assert "mode_flag" not in typed
    assert not any(p.name.startswith("webview_next_intent") for p in generated)


def test_extractor_records_only_literal_defaults_and_source(tmp_path):
    root = tmp_path / "sources"
    source = root / "com" / "example"
    source.mkdir(parents=True)
    (source / "Inputs.java").write_text(
        "class Inputs {\n"
        "  void read(Intent i) {\n"
        "    int page = i.getIntExtra(\"page\", 0);\n"
        "    boolean enabled = i.getBooleanExtra(\"enabled\", false);\n"
        "    int limit = i.getIntExtra(\"limit\", DEFAULT_LIMIT);\n"
        "    String title = i.getExtras().getString(\"title\", \"guest\");\n"
        "    String name = i.getStringExtra(\"name\");\n"
        "    Object parcel = i.getParcelableExtra(\"parcel\", Widget.class);\n"
        "  }\n"
        "}\n", encoding="utf-8")
    entries = {e["key"]: e for e in intents.extract(root)["global_keys"]}
    assert entries["page"]["default"] == {
        "literal": "0", "type": "int", "source": "com/example/Inputs.java", "line": 3}
    assert entries["enabled"]["default"]["literal"] == "false"
    assert entries["title"]["default"]["literal"] == '"guest"'
    assert entries["limit"]["default"] is None
    assert entries["limit"]["default_status"] == "unknown"
    assert "default" in entries["limit"]["unknown_fields"]
    assert entries["name"]["default_status"] == "not_applicable"
    assert "default" not in entries["name"]["unknown_fields"]
    assert entries["parcel"]["default_status"] == "not_applicable"
    assert entries["page"]["confidence"]["default"] == "high"


def test_extractor_validation_evidence_stays_in_method_and_does_not_claim_safety(tmp_path):
    root = tmp_path / "sources"
    source = root / "com" / "example"
    source.mkdir(parents=True)
    (source / "Checks.java").write_text(
        "class Checks {\n"
        "  void first(Intent i) {\n"
        "    String url = i.getStringExtra(\"url\");\n"
        "    if (url != null) { use(url); }\n"
        "    if (url.startsWith(\"https://\")) { use(url); }\n"
        "    String plain = i.getStringExtra(\"plain\");\n"
        "    // if (plain != null) { }\n"
        "    String replaced = i.getStringExtra(\"replaced\");\n"
        "    replaced = fallback();\n"
        "    if (replaced != null) { use(replaced); }\n"
        "  }\n"
        "  void second() {\n"
        "    if (plain != null) { use(plain); }\n"
        "  }\n"
        "}\n", encoding="utf-8")
    entries = {e["key"]: e for e in intents.extract(root)["global_keys"]}
    evidence = entries["url"]["validation_evidence"]
    assert [(e["check"], e["line"]) for e in evidence] == [
        ("null_check", 4), ("value_check", 5)]
    assert all(e["source"] == "com/example/Checks.java" and
               e["scope"] == "same_method" for e in evidence)
    assert entries["url"]["validation_status"] == "evidence_observed"
    assert entries["url"]["confidence"]["validation"] == "medium"
    assert entries["plain"]["validation_evidence"] == []
    assert entries["plain"]["validation_status"] == "not_observed"
    assert "validation" in entries["plain"]["unknown_fields"]
    assert entries["replaced"]["validation_evidence"] == []


def test_extractor_does_not_guess_ambiguous_constant_or_comment_key(tmp_path):
    root = tmp_path / "sources"
    root.mkdir()
    (root / "One.java").write_text('class One { static final String KEY = "first"; }\n',
                                   encoding="utf-8")
    (root / "Two.java").write_text('class Two { static final String KEY = "second"; }\n',
                                   encoding="utf-8")
    (root / "Reader.java").write_text(
        "class Reader {\n"
        "  void read(Intent i) {\n"
        "    i.getStringExtra(KEY);\n"
        "    // i.getStringExtra(\"comment_only\");\n"
        "  }\n"
        "}\n", encoding="utf-8")
    assert intents.extract(root)["global_keys"] == []


def test_cli_code_analysis_persists_inventory_for_all_apks(
        monkeypatch, tmp_path, source_tree, surface):
    apks = [tmp_path / "base.apk", tmp_path / "feature.apk"]
    seen = {}
    monkeypatch.setattr(cli, "_resolve_target", lambda target: apks)
    monkeypatch.setattr(cli.manifest, "analyze", lambda target: surface)

    def fake_decompile(given_apks, sha, **kwargs):
        seen["apks"] = given_apks
        seen["sha"] = sha
        return source_tree

    monkeypatch.setattr(cli.decompile, "decompile", fake_decompile)
    monkeypatch.setattr(cli, "_emit", lambda obj: seen.setdefault("output", obj))
    args = SimpleNamespace(target="fixture", sessions=str(tmp_path / "sessions"),
                           force=False, timeout=30, top=20)
    assert cli.cmd_code(args) == 0
    report = Session.open(surface.package, tmp_path / "sessions").read_code_report()
    assert seen["apks"] == apks
    assert seen["sha"] == surface.apk_sha256
    assert report["apk_sha256"] == surface.apk_sha256
    assert report["intent_extras"]["by_component"][surface.components[0].name][0]["key"] == "mode_flag"
    assert seen["output"]["intent_extras"]["unique_keys"] == 5


def test_mcp_code_analysis_persists_inventory_for_all_apks(
        monkeypatch, tmp_path, source_tree, surface):
    session = Session.open(surface.package, tmp_path / "sessions")
    apks = [tmp_path / "base.apk", tmp_path / "feature.apk"]
    seen = {}
    monkeypatch.setattr(mcp_server, "_surface_for", lambda target: (surface, apks))
    monkeypatch.setattr(mcp_server, "_session", lambda package: session)

    def fake_decompile(given_apks, sha, **kwargs):
        seen["apks"] = given_apks
        return source_tree

    monkeypatch.setattr(mcp_server.decompile, "decompile", fake_decompile)
    response = mcp_server._code_analyze({"target": "fixture"})
    assert seen["apks"] == apks
    assert response["intent_extras"]["unique_keys"] == 5
    assert session.read_code_report()["intent_extras"]["global_keys"]


def test_campaign_uses_component_keys_before_guesses_and_alias_target(source_tree, surface):
    inventory = intents.extract(source_tree)
    comp = surface.components[0]
    selected = exploit._campaign_payloads(comp, surface.package, inventory, limit=4)
    assert [p.extras[0].key for p in selected[:3]] == [
        "page_number", "server_url", "server_url",
    ]
    assert selected[0].extras[0].type == "int"
    assert any(p.name.startswith("webview_") and payloads.CANARY_HOST in p.extras[0].value
               for p in selected)
    alias = Component(name="com.example.target.Alias", type="activity-alias",
                      exported=True, reachable_from="third_party_app",
                      target_activity=comp.name)
    assert exploit._code_keys_for(surface.package, alias, inventory)[0]["scope"] == "component"
    assert exploit._campaign_payloads(alias, surface.package, inventory, 3)[0].extras[0].key == "page_number"


def test_run_campaign_passes_distinct_code_keys_to_each_component(monkeypatch, source_tree):
    second = source_tree / "com" / "example" / "target" / "OtherReceiver.java"
    second.write_text('class OtherReceiver { void f(Intent i) { i.getBooleanExtra("enabled", false); } }',
                      encoding="utf-8")
    inventory = intents.extract(source_tree)
    comps = [
        Component(name="com.example.target.OpenActivity", type="activity",
                  exported=True, reachable_from="third_party_app"),
        Component(name="com.example.target.OtherReceiver", type="receiver",
                  exported=True, reachable_from="third_party_app"),
    ]
    seen = []

    def fake_run_payload(package, comp, payload, **kwargs):
        seen.append((comp.name, payload.extras[0].key, payload.extras[0].type))
        return SimpleNamespace(verdict=SimpleNamespace(hit=False, confidence="none"))

    monkeypatch.setattr(exploit, "run_payload", fake_run_payload)
    exploit.run_campaign("com.example.target", comps, code_extras=inventory,
                         max_payloads_per_component=1)
    assert seen == [
        ("com.example.target.OpenActivity", "page_number", "int"),
        ("com.example.target.OtherReceiver", "enabled", "bool"),
    ]


@pytest.mark.parametrize("entry_point", ["cli", "mcp"])
@pytest.mark.parametrize("stored_hash,expected", [
    ("same-apk-hash", True), ("older-apk-hash", False),
])
def test_exploit_entry_points_use_only_matching_code_report(
        monkeypatch, tmp_path, surface, entry_point, stored_hash, expected):
    session = Session.open(surface.package, tmp_path / "sessions")
    inventory = {"by_component": {surface.components[0].name: [{"key": "server_url", "type": "string"}]},
                 "global_keys": []}
    session.write_code_report({"apk_sha256": stored_hash, "intent_extras": inventory})
    if stored_hash != surface.apk_sha256:
        session.write_surface(AttackSurface(package=surface.package, apk_sha256=stored_hash,
                                            components=surface.components))
    captured = {}

    def fake_campaign(*args, **kwargs):
        captured["code_extras"] = kwargs.get("code_extras")
        return []

    if entry_point == "cli":
        monkeypatch.setattr(cli, "_resolve_target", lambda target: [tmp_path / "app.apk"])
        monkeypatch.setattr(cli.manifest, "analyze", lambda target: surface)
        monkeypatch.setattr(cli, "_pick_serial", lambda args: "offline-test-serial")
        monkeypatch.setattr(cli, "ensure_agent", lambda config, serial: None)
        monkeypatch.setattr(cli.exploit, "run_campaign", fake_campaign)
        monkeypatch.setattr(cli, "_emit", lambda obj: None)
        args = SimpleNamespace(target="fixture", sessions=str(tmp_path / "sessions"),
                               type=None, max_payloads=10)
        assert cli.cmd_exploit(args) == 0
    else:
        monkeypatch.setattr(mcp_server, "_surface_for", lambda target: (surface, []))
        monkeypatch.setattr(mcp_server, "_session", lambda package: session)
        monkeypatch.setattr(mcp_server.emulator, "running_serial", lambda: "offline-test-serial")
        monkeypatch.setattr(mcp_server, "_agent", lambda: None)
        monkeypatch.setattr(mcp_server.exploit, "run_campaign", fake_campaign)
        mcp_server._exploit_campaign({"target": "fixture"})
    assert (captured["code_extras"] == inventory) is expected
    assert session.read_surface() is None or session.read_surface().apk_sha256 == surface.apk_sha256
