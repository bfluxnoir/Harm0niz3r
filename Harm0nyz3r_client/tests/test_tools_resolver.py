"""Tests for the F-bucket central tool resolver (Harm0nyz3r_client/tools.py)."""

import json
import os
import shutil

import pytest

import tools as tools_module
from tools import resolve_tool, tools_status, _load_one


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    """Point the resolver at temp tools.json / tools.local.json files."""
    primary = tmp_path / "tools.json"
    local = tmp_path / "tools.local.json"
    monkeypatch.setattr(tools_module, "_PRIMARY", str(primary))
    monkeypatch.setattr(tools_module, "_LOCAL", str(local))
    return primary, local


# ---------------------------------------------------------------------------
# _load_one
# ---------------------------------------------------------------------------

def test_load_one_missing_file_returns_empty(isolated_config):
    primary, _ = isolated_config
    assert _load_one(str(primary)) == {}


def test_load_one_malformed_json_returns_empty(isolated_config):
    primary, _ = isolated_config
    primary.write_text("{this is: not json", encoding="utf-8")
    assert _load_one(str(primary)) == {}


def test_load_one_drops_dollar_prefixed_keys(isolated_config):
    primary, _ = isolated_config
    primary.write_text(
        json.dumps({"$schema": "doc", "$doc": "ignore me", "jadx": "/a"}),
        encoding="utf-8",
    )
    cfg = _load_one(str(primary))
    assert cfg == {"jadx": "/a"}


def test_load_one_rejects_non_object_root(isolated_config):
    primary, _ = isolated_config
    primary.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    assert _load_one(str(primary)) == {}


# ---------------------------------------------------------------------------
# resolve_tool precedence
# ---------------------------------------------------------------------------

def test_no_config_no_path_returns_none(isolated_config, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: None)
    assert resolve_tool("jadx") is None


def test_falls_back_to_path_lookup_when_unconfigured(isolated_config, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/" + n)
    assert resolve_tool("jadx") == "/usr/bin/jadx"


def test_shipped_path_wins_over_path_lookup(isolated_config, monkeypatch, tmp_path):
    primary, _ = isolated_config
    real_jadx = tmp_path / "real_jadx"
    real_jadx.write_text("#!/bin/sh", encoding="utf-8")
    primary.write_text(json.dumps({"jadx": str(real_jadx)}), encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/" + n)
    assert resolve_tool("jadx") == str(real_jadx)


def test_local_path_wins_over_shipped_and_path(isolated_config, monkeypatch, tmp_path):
    primary, local = isolated_config
    shipped = tmp_path / "shipped_jadx"
    shipped.write_text("#!/bin/sh", encoding="utf-8")
    pinned = tmp_path / "pinned_jadx"
    pinned.write_text("#!/bin/sh", encoding="utf-8")
    primary.write_text(json.dumps({"jadx": str(shipped)}), encoding="utf-8")
    local.write_text(json.dumps({"jadx": str(pinned)}), encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/" + n)
    assert resolve_tool("jadx") == str(pinned)


def test_broken_config_path_does_not_short_circuit_to_none(isolated_config, monkeypatch):
    primary, _ = isolated_config
    primary.write_text(
        json.dumps({"jadx": "/this/path/does/not/exist"}), encoding="utf-8"
    )
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/jadx")
    # The configured path is unusable; resolver should keep walking and
    # fall through to PATH instead of returning None.
    assert resolve_tool("jadx") == "/usr/bin/jadx"


def test_null_configured_value_falls_through_to_path(isolated_config, monkeypatch):
    primary, _ = isolated_config
    primary.write_text(json.dumps({"jadx": None}), encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/jadx")
    assert resolve_tool("jadx") == "/usr/bin/jadx"


def test_fallback_path_lookup_can_be_disabled(isolated_config, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/" + n)
    assert resolve_tool("jadx", fallback_path_lookup=False) is None


# ---------------------------------------------------------------------------
# tools_status diagnostic helper
# ---------------------------------------------------------------------------

def test_tools_status_marks_local_source(isolated_config, monkeypatch, tmp_path):
    primary, local = isolated_config
    pinned = tmp_path / "pinned_jadx"
    pinned.write_text("#!/bin/sh", encoding="utf-8")
    local.write_text(json.dumps({"jadx": str(pinned)}), encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/" + n)
    rows = tools_status()
    jadx = next(r for r in rows if r["name"] == "jadx")
    assert jadx["source"] == "local"
    assert jadx["resolved"] == str(pinned)


def test_tools_status_marks_path_source_when_neither_config_has_it(
    isolated_config, monkeypatch,
):
    primary, _ = isolated_config
    primary.write_text(json.dumps({"jadx": None}), encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/jadx")
    rows = tools_status()
    jadx = next(r for r in rows if r["name"] == "jadx")
    assert jadx["source"] == "PATH"
    assert jadx["resolved"] == "/usr/bin/jadx"


def test_tools_status_source_none_when_nothing_resolves(isolated_config, monkeypatch):
    primary, _ = isolated_config
    primary.write_text(json.dumps({"jadx": None, "apktool": None}), encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda n: None)
    rows = tools_status()
    for r in rows:
        assert r["source"] is None
        assert r["resolved"] is None


# ---------------------------------------------------------------------------
# Shipped tools.json sanity (the file in the repo)
# ---------------------------------------------------------------------------

def test_shipped_tools_json_lists_expected_keys():
    # No monkeypatching: this hits the real shipped file in the repo.
    cfg = _load_one(tools_module._PRIMARY)
    for required in ("jadx", "apktool", "openssl", "adb"):
        assert required in cfg, required


def test_shipped_tools_json_keeps_every_value_null():
    cfg = _load_one(tools_module._PRIMARY)
    for k, v in cfg.items():
        assert v is None, (
            f"tools.json must ship with {k} set to null so it doesn't "
            f"shadow the user's tools.local.json"
        )
