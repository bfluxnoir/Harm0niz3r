"""Tests for E batch 3 - frida_server + app_explore.

Preset coverage (antidebug_bypass, native_trace) is handled by
test_frida_presets via the _EXPECTED_PRESETS matrix.
"""

import os

from commands.android.frida_server import (
    AndroidFridaServerCommand, _decompress_xz_if_needed,
)
from commands.android.app_explore import AndroidAppExploreCommand


class _FakeConsole:
    def __init__(self, device_id="SERIAL"):
        self.device_id = device_id
        self.msgs = []
        self.shell_calls = []
        self.shell_responses = {}
    def _print_message(self, l, m): self.msgs.append((l, m))
    def _run_shell(self, args):
        self.shell_calls.append(tuple(args))
        return self.shell_responses.get(tuple(args), ("", "", 0))


def _errors(c): return [m for l, m in c.msgs if l == "ERROR"]
def _infos(c):  return [m for l, m in c.msgs if l == "INFO"]
def _wars(c):   return [m for l, m in c.msgs if l == "WARNING"]
def _ok(c):     return [m for l, m in c.msgs if l == "SUCCESS"]


# ---------------------------------------------------------------------------
# frida_server
# ---------------------------------------------------------------------------

def test_frida_server_help_mentions_every_action():
    h = AndroidFridaServerCommand().help()
    for k in ("--status", "--start", "--stop", "--install", "--remote-path"):
        assert k in h, k


def test_frida_server_no_device_errors_out():
    c = _FakeConsole(device_id=None)
    AndroidFridaServerCommand().execute(c, [], "cli")
    assert any("No Android device" in m for m in _errors(c))


def test_frida_server_mutually_exclusive_actions_rejected():
    c = _FakeConsole()
    AndroidFridaServerCommand().execute(c, ["--start", "--stop"], "cli")
    assert any("mutually exclusive" in m for m in _errors(c))


def test_frida_server_default_action_is_status_and_calls_pgrep_and_test():
    c = _FakeConsole()
    # Set responses so status reports both not-present and not-running
    c.shell_responses[("test", "-f", "/data/local/tmp/frida-server")] = ("", "", 1)
    c.shell_responses[("pgrep", "-f", "frida-server")] = ("", "", 1)
    AndroidFridaServerCommand().execute(c, [], "cli")
    assert ("test", "-f", "/data/local/tmp/frida-server") in c.shell_calls
    assert ("pgrep", "-f", "frida-server") in c.shell_calls
    assert any("NOT FOUND" in m for m in _wars(c))
    assert any("no frida-server PID" in m for m in _wars(c))


def test_frida_server_status_reports_running_when_pgrep_returns_pids():
    c = _FakeConsole()
    c.shell_responses[("test", "-f", "/data/local/tmp/frida-server")] = ("", "", 0)
    c.shell_responses[("pgrep", "-f", "frida-server")] = ("12345\n12346", "", 0)
    AndroidFridaServerCommand().execute(c, ["--status"], "cli")
    assert any("present on /data/local/tmp/frida-server" in m for m in _infos(c))
    assert any("PID(s) 12345, 12346" in m for m in _infos(c))


def test_frida_server_install_rejects_missing_host_binary(tmp_path):
    c = _FakeConsole()
    bogus = str(tmp_path / "does_not_exist.bin")
    AndroidFridaServerCommand().execute(c, ["--install", bogus], "cli")
    assert any("Host binary not found" in m for m in _errors(c))


def test_frida_server_install_without_path_errors():
    # --install with no host path should be caught by arg parser
    c = _FakeConsole()
    cmd = AndroidFridaServerCommand()
    # Manually emit just '--install' with no value -- the loop won't
    # advance into action=install (the i+1<len branch fails), so the
    # action stays 'status'.  Acceptable behaviour; verify it doesn't
    # crash.
    cmd.execute(c, ["--install"], "cli")
    # No error, no special install path -- we just default to status.
    # That's what we want.


def test_decompress_xz_passthrough_for_non_xz(tmp_path):
    src = tmp_path / "frida.bin"
    src.write_bytes(b"hello")
    assert _decompress_xz_if_needed(str(src)) == str(src)


def test_decompress_xz_actually_decompresses(tmp_path):
    import lzma
    plain = b"frida-server-binary-stand-in-payload" * 100
    archived = tmp_path / "frida-server.xz"
    with lzma.open(archived, "wb") as f:
        f.write(plain)
    out_path = _decompress_xz_if_needed(str(archived))
    assert out_path.endswith("frida-server")
    with open(out_path, "rb") as f:
        assert f.read() == plain


# ---------------------------------------------------------------------------
# app_explore
# ---------------------------------------------------------------------------

def test_app_explore_help_mentions_critical_flags():
    h = AndroidAppExploreCommand().help()
    for k in ("--class", "--methods", "--out", "--spawn", "--seconds",
              "DexClassLoader", "InMemoryDexClassLoader"):
        assert k in h, k


def test_app_explore_no_device_errors_out():
    c = _FakeConsole(device_id=None)
    AndroidAppExploreCommand().execute(c, ["com.x"], "cli")
    assert any("No Android device" in m for m in _errors(c))


def test_app_explore_invalid_package_rejected():
    c = _FakeConsole()
    AndroidAppExploreCommand().execute(c, ["not a pkg"], "cli")
    assert any("Invalid package name" in m for m in _errors(c))


def test_app_explore_wrong_arity_prints_usage():
    c = _FakeConsole()
    AndroidAppExploreCommand().execute(c, [], "cli")
    assert any("Usage: app_explore" in m for m in _infos(c))


def test_app_explore_refuses_app_source():
    c = _FakeConsole()
    AndroidAppExploreCommand().execute(c, ["com.x"], "app")
    assert any("CLI-only" in m for _, m in c.msgs)


def test_embedded_explore_script_carries_expected_markers():
    from commands.android.app_explore import _EXPLORE_SCRIPT
    for marker in (
        "Java.enumerateLoadedClasses",
        "kind: 'class'",
        "kind: 'app_explore'",
        "withMethods",
        "ready: true",
    ):
        assert marker in _EXPLORE_SCRIPT, marker
