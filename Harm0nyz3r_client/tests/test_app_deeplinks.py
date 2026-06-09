"""Tests for commands/android/app_deeplinks.py."""

import json

from commands.android.app_deeplinks import (
    _collect_handlers, _build_example_uri,
    _render_console, _render_json,
)


def _activity(name, skills):
    return {
        "name": name,
        "type": "Activity",
        "visible": True,
        "permissionsRequired": [],
        "skills": skills,
    }


def test_browsable_https_handler_produces_full_example_uri():
    parsed = {
        "packageName": "com.example.app",
        "exposedComponents": [
            _activity(
                "com.example.app.Login",
                [
                    {
                        "action": "android.intent.action.VIEW",
                        "entity": "android.intent.category.DEFAULT",
                        "categories": [
                            "android.intent.category.DEFAULT",
                            "android.intent.category.BROWSABLE",
                        ],
                        "scheme": "https",
                        "host": "login.example.com",
                        "path": "/panel",
                        "pathType": "LITERAL",
                    },
                ],
            ),
        ],
    }
    handlers = _collect_handlers(parsed)
    assert len(handlers) == 1
    h = handlers[0]
    assert h["browsable"] is True
    assert "https://login.example.com/panel" in h["examples"]


def test_non_view_filter_excluded():
    parsed = {
        "packageName": "com.x",
        "exposedComponents": [
            _activity(
                "com.x.Main",
                [
                    {"action": "android.intent.action.MAIN"},
                    {"action": "android.intent.action.SEARCH"},
                ],
            ),
        ],
    }
    assert _collect_handlers(parsed) == []


def test_non_exported_component_excluded():
    parsed = {
        "packageName": "com.x",
        "exposedComponents": [
            {
                "name": "com.x.Hidden",
                "type": "Activity",
                "visible": False,
                "permissionsRequired": [],
                "skills": [{"action": "android.intent.action.VIEW", "scheme": "x"}],
            },
        ],
    }
    assert _collect_handlers(parsed) == []


def test_scheme_only_handler_renders_as_scheme_colon():
    """tel:, mailto:, sms: etc.  No host/path -> just 'scheme:'."""
    skill = {"action": "android.intent.action.VIEW", "scheme": "tel"}
    assert _build_example_uri(skill) == "tel:"


def test_prefix_path_uri_carries_placeholder():
    skill = {
        "action": "android.intent.action.VIEW",
        "scheme": "myapp",
        "host": "admin",
        "path": "/v1",
        "pathType": "PREFIX",
    }
    uri = _build_example_uri(skill)
    assert uri == "myapp://admin/v1/<rest>"


def test_glob_path_uri_carries_matches_placeholder():
    skill = {
        "action": "android.intent.action.VIEW",
        "scheme": "myapp",
        "host": "api",
        "port": 8080,
        "path": "/users/.*",
        "pathType": "GLOB",
    }
    uri = _build_example_uri(skill)
    assert uri.startswith("myapp://api:8080")
    assert "<matches:" in uri


def test_console_render_empty_says_so():
    out = _render_console("com.empty", [])
    assert "No deeplink handlers found" in out


def test_json_render_counts():
    parsed = {
        "packageName": "com.x",
        "exposedComponents": [
            _activity(
                "com.x.Browsable",
                [{
                    "action": "android.intent.action.VIEW",
                    "categories": [
                        "android.intent.category.DEFAULT",
                        "android.intent.category.BROWSABLE",
                    ],
                    "scheme": "https",
                    "host": "x.com",
                    "path": "/",
                    "pathType": "LITERAL",
                }],
            ),
            _activity(
                "com.x.Internal",
                [{
                    "action": "android.intent.action.VIEW",
                    "scheme": "myapp",
                    "host": "internal",
                }],
            ),
        ],
    }
    handlers = _collect_handlers(parsed)
    payload = _render_json("com.x", handlers)
    data = json.loads(payload)
    assert data["package"] == "com.x"
    assert data["counts"]["total"] == 2
    assert data["counts"]["browsable"] == 1
