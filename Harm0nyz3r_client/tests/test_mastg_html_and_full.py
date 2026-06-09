"""Tests for the C22 HTML payload + the C21 mastg_full orchestrator."""

import os

from commands.android.mastg_report import _html_payload, _h, ReportFinding


def _f(id_, severity, title, detail, evidence=None, recommendation=None, source="test"):
    return ReportFinding(source, id_, severity, title, detail, evidence, recommendation)


# ---------------------------------------------------------------------------
# _h escape
# ---------------------------------------------------------------------------

def test_h_escapes_html_metacharacters():
    assert _h("<script>") == "&lt;script&gt;"
    assert _h("a & b") == "a &amp; b"
    assert _h('a "b" c') == "a &quot;b&quot; c"


def test_h_handles_none_and_non_string():
    assert _h(None) == ""
    assert _h(42) == "42"


# ---------------------------------------------------------------------------
# HTML payload structure
# ---------------------------------------------------------------------------

def test_html_payload_has_doctype_and_title():
    findings = [
        _f("DEBUG", "HIGH", "App is debuggable",
           "android:debuggable=true in manifest.",
           evidence="<application android:debuggable=\"true\">"),
    ]
    parsed = {"versionName": "1.0", "versionCode": "1", "targetSdk": "34",
              "minSdk": "23", "debugMode": True, "systemApp": False}
    html = _html_payload("com.example.target", parsed, findings)
    assert html.startswith("<!DOCTYPE html>")
    assert "<title>" in html
    assert "com.example.target" in html


def test_html_payload_renders_severity_badges_and_counts():
    findings = [
        _f("A", "HIGH",   "h1", "."),
        _f("B", "HIGH",   "h2", "."),
        _f("C", "MEDIUM", "m1", "."),
        _f("D", "LOW",    "l1", "."),
        _f("E", "INFO",   "i1", "."),
    ]
    parsed = {"versionName": "1.0", "versionCode": "1", "targetSdk": "34",
              "minSdk": "23", "debugMode": False, "systemApp": False}
    html = _html_payload("p", parsed, findings)
    # severity counts in the cards
    assert ">2<" in html  # HIGH count card
    assert "card high" in html
    assert "card medium" in html
    assert "card low" in html
    assert "card info" in html
    # every severity badge class
    assert "sev-HIGH" in html
    assert "sev-MEDIUM" in html
    assert "sev-LOW" in html
    assert "sev-INFO" in html


def test_html_payload_groups_findings_by_masvs_category():
    findings = [
        _f("DEBUGGABLE_FLAG",      "HIGH", "debug", "."),  # MASVS-RESILIENCE
        _f("CLEARTEXT_TRAFFIC",    "HIGH", "clr",   "."),  # MASVS-NETWORK
        _f("DEEPLINK_HANDLERS",    "INFO", "dl",    "."),  # MASVS-PLATFORM
    ]
    parsed = {"versionName": "1.0", "versionCode": "1", "targetSdk": "34",
              "minSdk": "23", "debugMode": True, "systemApp": False}
    html = _html_payload("p", parsed, findings)
    assert "MASVS-RESILIENCE" in html
    assert "MASVS-NETWORK" in html
    assert "MASVS-PLATFORM" in html
    # Each finding ends up inside a <details>
    assert html.count("<details>") >= 3


def test_html_payload_escapes_evidence_with_html_metas():
    findings = [
        _f("XSS", "HIGH", "Title with <script>",
           "Detail with <em>",
           evidence='<a href="javascript:alert(1)">x</a>'),
    ]
    parsed = {"versionName": "1.0", "versionCode": "1", "targetSdk": "34",
              "minSdk": "23", "debugMode": False, "systemApp": False}
    html = _html_payload("p", parsed, findings)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert 'javascript:alert(1)' in html.replace("&amp;", "&")  # value survives
    assert 'href="javascript:' not in html                       # but only escaped


def test_html_payload_empty_findings_render_friendly_block():
    parsed = {"versionName": "1.0", "versionCode": "1", "targetSdk": "34",
              "minSdk": "23", "debugMode": False, "systemApp": False}
    html = _html_payload("p", parsed, [])
    assert 'class="empty"' in html
    assert "No findings" in html


# ---------------------------------------------------------------------------
# mastg_full orchestrator -- argument parsing only
# ---------------------------------------------------------------------------

def test_mastg_full_help_mentions_every_phase():
    from commands.android.mastg_full import AndroidMastgFullCommand
    help_text = AndroidMastgFullCommand().help()
    for chunk in (
        "app_pull", "app_decompile", "mastg_report", "index.html",
        "--out", "--decompiled", "--skip-pull", "--skip-decompile",
    ):
        assert chunk in help_text, chunk


def test_mastg_full_no_device_errors_out():
    from commands.android.mastg_full import AndroidMastgFullCommand
    class _FC:
        device_id = None
        msgs = []
        def _print_message(self, l, m): self.msgs.append((l, m))
    cmd = AndroidMastgFullCommand()
    fc = _FC()
    cmd.execute(fc, ["com.x"], "cli")
    assert any(l == "ERROR" and "No Android device" in m for l, m in fc.msgs)


def test_mastg_full_rejects_invalid_package_name():
    from commands.android.mastg_full import AndroidMastgFullCommand
    class _FC:
        device_id = "SERIAL"
        msgs = []
        def _print_message(self, l, m): self.msgs.append((l, m))
    cmd = AndroidMastgFullCommand()
    fc = _FC()
    cmd.execute(fc, ["bad name!"], "cli")
    assert any(l == "ERROR" and "Invalid package name" in m for l, m in fc.msgs)


def test_mastg_full_resolves_default_out_dir(tmp_path, monkeypatch):
    # We can verify the default-out-dir wiring without ever pulling an APK
    # by intercepting the moment app_pull is about to be invoked.
    from commands.android import mastg_full as mf
    monkeypatch.chdir(tmp_path)

    captured = {}
    def fake_invoke(cls, console, args):
        captured["args"] = args
        # Make every later phase a no-op
        raise RuntimeError("stop here")

    monkeypatch.setattr(mf, "_invoke", fake_invoke)

    class _FC:
        device_id = "SERIAL"
        msgs = []
        def _print_message(self, l, m): self.msgs.append((l, m))
        def _run_shell(self, *a, **k): return ("", "", 1)

    cmd = mf.AndroidMastgFullCommand()
    fc = _FC()
    cmd.execute(fc, ["com.x"], "cli")
    # captured["args"] is the args list passed to app_pull -- it should
    # carry --out pointing inside results/com.x/apk
    assert captured.get("args"), "expected app_pull to be reached"
    assert "--out" in captured["args"]
    out_idx = captured["args"].index("--out")
    assert "results" in captured["args"][out_idx + 1]
    assert "com.x" in captured["args"][out_idx + 1]


# ---------------------------------------------------------------------------
# _resolve_decompile_root
# ---------------------------------------------------------------------------

def test_resolve_decompile_root_picks_newest(tmp_path):
    from commands.android.mastg_full import _resolve_decompile_root
    import time as _t
    parent = tmp_path / "decompiled"
    parent.mkdir()
    older = parent / "older"
    newer = parent / "newer"
    older.mkdir()
    _t.sleep(0.01)
    newer.mkdir()
    # Force mtime distinction even on filesystems with low resolution
    os.utime(older, (0, 0))
    res = _resolve_decompile_root(str(parent), "com.x")
    assert res == str(newer)


def test_resolve_decompile_root_returns_none_when_empty(tmp_path):
    from commands.android.mastg_full import _resolve_decompile_root
    parent = tmp_path / "decompiled"
    parent.mkdir()
    assert _resolve_decompile_root(str(parent), "com.x") is None


def test_resolve_decompile_root_returns_none_for_missing_dir(tmp_path):
    from commands.android.mastg_full import _resolve_decompile_root
    assert _resolve_decompile_root(str(tmp_path / "nope"), "com.x") is None
