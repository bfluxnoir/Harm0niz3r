"""Tests for app_dex_dump + app_memory_dump (E batch 2).

The actual Frida session is out of scope for unit tests -- those tests
focus on argument parsing, defaults, registration and JS-script
prelude assembly.
"""

import os

from commands.android.app_dex_dump import AndroidAppDexDumpCommand
from commands.android.app_memory_dump import AndroidAppMemoryDumpCommand


class _FakeConsole:
    def __init__(self, device_id="SERIAL"):
        self.device_id = device_id
        self.msgs = []
    def _print_message(self, l, m): self.msgs.append((l, m))


def _errors(c): return [m for l, m in c.msgs if l == "ERROR"]
def _infos(c): return [m for l, m in c.msgs if l == "INFO"]


# ---------------------------------------------------------------------------
# Registration + help text
# ---------------------------------------------------------------------------

def test_dex_dump_help_mentions_critical_flags():
    h = AndroidAppDexDumpCommand().help()
    for k in ("--out", "--spawn", "--seconds", "DEX", "Bangcle", "Tencent", "Legu"):
        assert k in h, k


def test_memory_dump_help_mentions_critical_flags():
    h = AndroidAppMemoryDumpCommand().help()
    for k in ("--strings", "--raw", "--filter", "--min-strlen", "--min-range",
              "--max-range", "in-RAM-only", "Bearer"):
        assert k in h, k


# ---------------------------------------------------------------------------
# Argument validation -- both commands reject bad shapes before touching
# the Frida import.
# ---------------------------------------------------------------------------

def test_dex_dump_invalid_package_is_rejected():
    cmd = AndroidAppDexDumpCommand()
    c = _FakeConsole()
    cmd.execute(c, ["not a valid pkg"], "cli")
    assert any("Invalid package name" in e for e in _errors(c))


def test_dex_dump_wrong_arity_prints_usage():
    cmd = AndroidAppDexDumpCommand()
    c = _FakeConsole()
    cmd.execute(c, [], "cli")
    assert any("Usage: app_dex_dump" in m for m in _infos(c))


def test_memory_dump_invalid_package_is_rejected():
    cmd = AndroidAppMemoryDumpCommand()
    c = _FakeConsole()
    cmd.execute(c, ["not!a-pkg"], "cli")
    assert any("Invalid package name" in e for e in _errors(c))


def test_memory_dump_wrong_arity_prints_usage():
    cmd = AndroidAppMemoryDumpCommand()
    c = _FakeConsole()
    cmd.execute(c, [], "cli")
    assert any("Usage: app_memory_dump" in m for m in _infos(c))


def test_memory_dump_bad_filter_regex_is_rejected_before_frida():
    cmd = AndroidAppMemoryDumpCommand()
    c = _FakeConsole()
    cmd.execute(c, ["com.x", "--filter", "(unbalanced"], "cli")
    assert any("Bad --filter regex" in e for e in _errors(c))


# ---------------------------------------------------------------------------
# Source / app source CLI gate
# ---------------------------------------------------------------------------

def test_dex_dump_refuses_app_source():
    c = _FakeConsole()
    AndroidAppDexDumpCommand().execute(c, ["com.x"], "app")
    assert any("CLI-only" in m for _, m in c.msgs)


def test_memory_dump_refuses_app_source():
    c = _FakeConsole()
    AndroidAppMemoryDumpCommand().execute(c, ["com.x"], "app")
    assert any("CLI-only" in m for _, m in c.msgs)


# ---------------------------------------------------------------------------
# Embedded scripts -- they must be syntactically reasonable JS strings.
# ---------------------------------------------------------------------------

def test_embedded_dex_script_carries_expected_markers():
    from commands.android.app_dex_dump import _DEX_DUMP_SCRIPT
    for marker in (
        "looksLikeDex",
        "Process.enumerateRanges",
        "kind: 'dex'",
        "kind: 'dex_dump'",
        "ready: true",
    ):
        assert marker in _DEX_DUMP_SCRIPT, marker


def test_embedded_memory_script_carries_expected_markers():
    from commands.android.app_memory_dump import _MEM_DUMP_SCRIPT
    for marker in (
        "extractPrintable",
        "Process.enumerateRanges",
        "kind: 'mem_strings'",
        "kind: 'mem_raw'",
        "kind: 'memory_dump'",
        "ready:          true",
    ):
        assert marker in _MEM_DUMP_SCRIPT, marker
