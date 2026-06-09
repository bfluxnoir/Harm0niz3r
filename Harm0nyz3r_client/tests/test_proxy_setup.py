"""Tests for commands/android/proxy_setup.py."""

import os
import tempfile
from typing import List

from commands.android.proxy_setup import AndroidProxySetupCommand, _PROXY_RE


class _FakeConsole:
    """Minimal console stand-in that captures messages and shell calls."""

    def __init__(self, shell_responses=None):
        self.msgs: List = []
        self.shell_calls: List = []
        self.device_id = "TEST123"
        # shell_responses: dict mapping (tuple of args) -> (stdout, stderr, retcode)
        # or a callable(args) -> triple.
        self.shell_responses = shell_responses or {}

    def _print_message(self, level, msg):
        self.msgs.append((level, msg))

    def _run_shell(self, args):
        self.shell_calls.append(tuple(args))
        if callable(self.shell_responses):
            return self.shell_responses(tuple(args))
        return self.shell_responses.get(tuple(args), ("", "", 0))

    def _run_bridge(self, args):
        return ("", "", 0)


def _errs(c: _FakeConsole):
    return [m for l, m in c.msgs if l == "ERROR"]


def _wars(c: _FakeConsole):
    return [m for l, m in c.msgs if l == "WARNING"]


def _ok(c: _FakeConsole):
    return [m for l, m in c.msgs if l == "SUCCESS"]


# ---------------------------------------------------------------------------
# Validation / arg-parsing
# ---------------------------------------------------------------------------

def test_proxy_regex_accepts_typical_forms():
    assert _PROXY_RE.match("192.168.1.10:8080")
    assert _PROXY_RE.match("burp.local:8080")
    assert _PROXY_RE.match("10.0.0.1:443")


def test_proxy_regex_rejects_garbage():
    assert not _PROXY_RE.match("not a proxy")
    assert not _PROXY_RE.match("192.168.1.10")        # no port
    assert not _PROXY_RE.match("192.168.1.10:abc")    # non-numeric port
    assert not _PROXY_RE.match("http://a:8080")       # scheme not accepted


def test_no_device_short_circuits():
    cmd = AndroidProxySetupCommand()
    c = _FakeConsole()
    c.device_id = None
    cmd.execute(c, ["--status"], "cli")
    assert any("No Android device" in m for m in _errs(c))


def test_default_action_is_status():
    cmd = AndroidProxySetupCommand()
    c = _FakeConsole({
        ("settings", "get", "global", "http_proxy"): ("null", "", 0),
    })
    cmd.execute(c, [], "cli")
    # Should have hit 'settings get'
    assert ("settings", "get", "global", "http_proxy") in c.shell_calls
    assert any("not set" in m for _, m in c.msgs)


def test_set_proxy_then_verifies_with_status():
    cmd = AndroidProxySetupCommand()
    c = _FakeConsole({
        ("settings", "put", "global", "http_proxy", "10.0.0.1:8080"): ("", "", 0),
        ("settings", "get", "global", "http_proxy"): ("10.0.0.1:8080", "", 0),
    })
    cmd.execute(c, ["--proxy", "10.0.0.1:8080"], "cli")
    # The set + a confirming get must both have been called
    assert ("settings", "put", "global", "http_proxy", "10.0.0.1:8080") in c.shell_calls
    assert ("settings", "get", "global", "http_proxy") in c.shell_calls
    assert any("http_proxy set to 10.0.0.1:8080" in m for m in _ok(c))


def test_set_proxy_validates_format():
    cmd = AndroidProxySetupCommand()
    c = _FakeConsole()
    cmd.execute(c, ["--proxy", "garbage"], "cli")
    assert any("Invalid proxy format" in m for m in _errs(c))
    # Nothing should have been pushed to the device
    assert ("settings", "put", "global", "http_proxy", "garbage") not in c.shell_calls


def test_clear_proxy_resets_to_zero_port():
    cmd = AndroidProxySetupCommand()
    c = _FakeConsole({
        ("settings", "put", "global", "http_proxy", ":0"): ("", "", 0),
        ("settings", "get", "global", "http_proxy"): ("null", "", 0),
    })
    cmd.execute(c, ["--clear"], "cli")
    assert ("settings", "put", "global", "http_proxy", ":0") in c.shell_calls
    assert any("cleared" in m.lower() for m in _ok(c))


def test_both_clear_and_proxy_at_once_warns_and_picks_proxy():
    cmd = AndroidProxySetupCommand()
    c = _FakeConsole({
        ("settings", "put", "global", "http_proxy", "1.2.3.4:9999"): ("", "", 0),
        ("settings", "get", "global", "http_proxy"): ("1.2.3.4:9999", "", 0),
    })
    cmd.execute(c, ["--clear", "--proxy", "1.2.3.4:9999"], "cli")
    assert any("--proxy wins" in m for m in _wars(c))
    assert ("settings", "put", "global", "http_proxy", "1.2.3.4:9999") in c.shell_calls
    # --clear should NOT have fired
    assert ("settings", "put", "global", "http_proxy", ":0") not in c.shell_calls


def test_unknown_flag_warns_but_continues():
    cmd = AndroidProxySetupCommand()
    c = _FakeConsole({
        ("settings", "get", "global", "http_proxy"): ("null", "", 0),
    })
    cmd.execute(c, ["--funky"], "cli")
    assert any("Ignoring unknown argument(s): --funky" in m for m in _wars(c))


# ---------------------------------------------------------------------------
# CA install
# ---------------------------------------------------------------------------

def test_ca_without_system_prints_helpful_info():
    cmd = AndroidProxySetupCommand()
    ca = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    ca.write(b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")
    ca.close()
    c = _FakeConsole({
        ("settings", "get", "global", "http_proxy"): ("null", "", 0),
    })
    try:
        cmd.execute(c, ["--ca", ca.name], "cli")
        # No --system: should print an INFO with the user-store hint, no errors
        assert not _errs(c)
        infos = [m for l, m in c.msgs if l == "INFO"]
        assert any("system store path" in m for m in infos)
    finally:
        os.unlink(ca.name)


def test_ca_install_refuses_when_root_unavailable():
    cmd = AndroidProxySetupCommand()
    ca = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    ca.write(b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")
    ca.close()
    c = _FakeConsole({
        ("settings", "get", "global", "http_proxy"): ("null", "", 0),
        # su 0 id -> no uid=0 in stdout, retcode 1
        ("su", "0", "id"): ("not root", "", 1),
    })
    try:
        cmd.execute(c, ["--ca", ca.name, "--system"], "cli")
        assert any("requires root" in m for m in _errs(c))
        assert any("MagiskTrustUserCerts" in m for m in _errs(c))
    finally:
        os.unlink(ca.name)


def test_ca_install_with_hash_name_short_circuit_validates_hex():
    cmd = AndroidProxySetupCommand()
    ca = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    ca.write(b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")
    ca.close()
    c = _FakeConsole({
        ("settings", "get", "global", "http_proxy"): ("null", "", 0),
        ("su", "0", "id"): ("uid=0(root) gid=0(root)", "", 0),
    })
    try:
        # Bogus 7-char hash -> should be refused even before remount.
        cmd.execute(c, ["--ca", ca.name, "--system", "--hash-name", "1234567"], "cli")
        assert any("8 hex chars" in m for m in _errs(c))
        # No remount should have been attempted.
        assert ("su", "0", "mount", "-o", "rw,remount", "/system") not in c.shell_calls
    finally:
        os.unlink(ca.name)


def test_missing_ca_file_errors_out():
    cmd = AndroidProxySetupCommand()
    c = _FakeConsole({
        ("settings", "get", "global", "http_proxy"): ("null", "", 0),
    })
    cmd.execute(c, ["--ca", "/no/such/cert.pem", "--system"], "cli")
    assert any("CA file not found" in m for m in _errs(c))
