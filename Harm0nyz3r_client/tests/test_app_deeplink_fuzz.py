"""Tests for commands/android/app_deeplink_fuzz.py."""

from commands.android.app_deeplink_fuzz import (
    _build_corpus, _classify, _fire,
)


# ---------------------------------------------------------------------------
# Corpus builder
# ---------------------------------------------------------------------------

def _h(scheme="https", host="api.example.com", path="/v1/x", examples=None):
    return {
        "scheme":   scheme,
        "host":     host,
        "path":     path,
        "examples": examples or [],
        "component": "com.example/.LinkActivity",
    }


def _uris(corpus):
    return [uri for _, uri in corpus]


def test_corpus_has_canonical_entry_first_when_example_present():
    handler = _h(examples=["https://api.example.com/v1/x?id=42"])
    uris = _uris(_build_corpus(handler))
    assert uris[0] == "https://api.example.com/v1/x?id=42"


def test_corpus_falls_back_to_rebuilt_base_when_no_example():
    handler = _h()
    uris = _uris(_build_corpus(handler))
    assert any(u == "https://api.example.com/v1/x" for u in uris)


def test_corpus_contains_expected_mutation_shapes():
    handler = _h()
    uris = _uris(_build_corpus(handler))
    # Long-path, traversal, SQLi, JS scheme, content:// pivot
    assert any("A" * 64 in u for u in uris)
    assert any("../../../" in u for u in uris)
    assert any("OR '1'='1" in u for u in uris)
    assert any(u.startswith("javascript:") for u in uris)
    assert any(u.startswith("content://") for u in uris)
    assert any(u.startswith("file://") for u in uris)


def test_corpus_is_deduplicated():
    # When the handler has no host, the base falls back to 'example.com';
    # the duplicate-handling should keep one base, not two.
    handler = _h(host=None)
    uris = _uris(_build_corpus(handler))
    assert len(uris) == len(set(uris))


def test_corpus_is_empty_for_handler_without_scheme():
    assert _build_corpus(_h(scheme="")) == []


def test_corpus_size_is_bounded():
    # Real handlers should never blow up the corpus -- regression guard
    handler = _h()
    assert len(_build_corpus(handler)) <= 15


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def test_classify_security_exception_is_anomaly():
    verdict, markers = _classify(
        stdout="Starting...",
        stderr="java.lang.SecurityException: Permission Denial: foo",
        retcode=0,
    )
    assert verdict == "ANOMALY"
    # Both 'SecurityException' AND 'Permission Denial' should be flagged
    assert "SecurityException" in markers
    assert "Permission Denial" in markers


def test_classify_crash_is_anomaly():
    out = (
        "Starting: Intent { act=android.intent.action.VIEW dat=... }\n"
        "AndroidRuntime: FATAL EXCEPTION: main\n"
        "NullPointerException: target was null"
    )
    verdict, markers = _classify(out, "", 0)
    assert verdict == "ANOMALY"


def test_classify_rejected_when_no_handler_matches():
    out = "Starting: Intent { ... }\nError: Activity not started, unable to resolve Intent"
    verdict, markers = _classify(out, "", 0)
    assert verdict == "REJECTED"


def test_classify_clean_run_is_ok():
    out = (
        "Starting: Intent { act=android.intent.action.VIEW dat=https://x }\n"
        "Status: ok\nActivity: com.example/.LinkActivity\nThisTime: 42"
    )
    verdict, markers = _classify(out, "", 0)
    assert verdict == "OK"
    assert markers == []


def test_classify_nonzero_exit_no_markers_is_error():
    verdict, markers = _classify("", "", 7)
    assert verdict == "ERROR"
    assert markers == []


# ---------------------------------------------------------------------------
# _fire end-to-end with fake console
# ---------------------------------------------------------------------------

class _FakeConsole:
    def __init__(self, shell_responses):
        # shell_responses: callable(args) -> (stdout, stderr, retcode)
        self.shell_responses = shell_responses
        self.calls = []
    def _print_message(self, l, m): pass
    def _run_shell(self, args):
        self.calls.append(tuple(args))
        return self.shell_responses(tuple(args))


def test_fire_dispatches_am_start_with_correct_args():
    captured_args = []
    def fake(args):
        captured_args.append(args)
        return ("Status: ok", "", 0)
    c = _FakeConsole(fake)
    r = _fire(c, "com.example.target", "https://x/y")
    assert r["uri"] == "https://x/y"
    assert r["verdict"] == "OK"
    # Verify the actual command shape
    expected = (
        "am", "start", "-W",
        "-a", "android.intent.action.VIEW",
        "-d", "https://x/y",
        "com.example.target",
    )
    assert expected in captured_args


def test_fire_with_security_exception_flags_anomaly():
    def fake(_):
        return ("", "SecurityException: not exported", 0)
    c = _FakeConsole(fake)
    r = _fire(c, "com.example.target", "https://x")
    assert r["verdict"] == "ANOMALY"
    assert "SecurityException" in r["markers"]
