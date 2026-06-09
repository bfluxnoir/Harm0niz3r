"""Tests for the bundled Frida preset library (C19)."""

import os

from commands.android.frida_run import _list_preset_names, _resolve_preset, _PRESETS_DIR


_EXPECTED_PRESETS = {
    "ssl_pinning_bypass",
    "root_bypass",
    "biometric_bypass",
    "intent_spy",
}


def test_preset_dir_exists():
    assert os.path.isdir(_PRESETS_DIR)


def test_all_expected_presets_are_listed():
    names = set(_list_preset_names())
    missing = _EXPECTED_PRESETS - names
    assert not missing, f"missing presets: {missing}"


def test_resolve_known_preset_returns_a_file():
    for name in _EXPECTED_PRESETS:
        path = _resolve_preset(name)
        assert path is not None
        assert os.path.isfile(path)
        with open(path, "r", encoding="utf-8") as f:
            head = f.read(64)
        # Each preset script must start with a JS comment header so the
        # Frida runtime accepts it and the user can read it for safety.
        assert head.startswith("/*"), name


def test_unknown_preset_returns_none():
    assert _resolve_preset("definitely_not_a_real_preset") is None
    assert _resolve_preset("") is None
    assert _resolve_preset(None) is None


def test_help_text_mentions_preset_flag():
    from commands.android.frida_run import AndroidFridaRunCommand
    cmd = AndroidFridaRunCommand()
    help_text = cmd.help()
    assert "--preset" in help_text
    assert "--list-presets" in help_text
    # Every preset name should surface in help so the user can discover them.
    for name in _EXPECTED_PRESETS:
        assert name in help_text


def test_execute_list_presets_does_not_require_frida():
    from commands.android.frida_run import AndroidFridaRunCommand
    import io, contextlib

    cmd = AndroidFridaRunCommand()

    class _FakeConsole:
        def __init__(self): self.msgs = []
        def _print_message(self, level, m): self.msgs.append((level, m))

    fc = _FakeConsole()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd.execute(fc, ["--list-presets"], "cli")
    out = buf.getvalue()
    # Every preset should appear in either the captured stdout or an INFO msg.
    haystack = out + "\n".join(m for _, m in fc.msgs)
    for name in _EXPECTED_PRESETS:
        assert name in haystack, (name, out, fc.msgs)


def test_execute_rejects_unknown_preset_cleanly():
    from commands.android.frida_run import AndroidFridaRunCommand
    cmd = AndroidFridaRunCommand()

    class _FakeConsole:
        def __init__(self): self.msgs = []
        def _print_message(self, level, m): self.msgs.append((level, m))

    fc = _FakeConsole()
    cmd.execute(fc, ["com.example.target", "--preset", "nope"], "cli")
    errs = [m for l, m in fc.msgs if l == "ERROR"]
    assert any("Unknown preset" in m or "pip install" in m for m in errs), errs
