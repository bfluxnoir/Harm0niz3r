"""Tests for the C14 upgrades to commands/android/app_ability_fuzz.py."""

import random

from commands.android.app_ability_fuzz import (
    _classify,
    _resolve_mode,
    _fuzz_int, _fuzz_long, _fuzz_float, _fuzz_uri, _fuzz_path, _fuzz_string,
    _next_value,
    _INT_EDGE_CASES, _LONG_EDGE_CASES, _STRING_EDGE_CASES, _AM_EXTRA_FLAG,
    _AUTO_CHOICES,
)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def test_classify_security_exception_is_anomaly():
    verdict, markers = _classify("", "java.lang.SecurityException: ...", 0)
    assert verdict == "ANOMALY"
    assert "SecurityException" in markers


def test_classify_crash_is_anomaly_with_multiple_markers():
    verdict, markers = _classify(
        "", "AndroidRuntime: FATAL EXCEPTION: main\nNullPointerException: x", 1,
    )
    assert verdict == "ANOMALY"
    assert {"AndroidRuntime", "FATAL EXCEPTION", "NullPointerException"}.issubset(markers)


def test_classify_nonzero_with_no_marker_is_error():
    assert _classify("", "", 17) == ("ERROR", [])


def test_classify_clean_run_is_ok():
    assert _classify("Status: ok", "", 0) == ("OK", [])


# ---------------------------------------------------------------------------
# Mode parsing
# ---------------------------------------------------------------------------

def test_resolve_mode_recognises_v1_markers():
    assert _resolve_mode("?s") == "string"
    assert _resolve_mode("?i") == "int"
    assert _resolve_mode("?b") == "bool"
    assert _resolve_mode("?") == "auto"


def test_resolve_mode_recognises_new_markers():
    assert _resolve_mode("?l") == "long"
    assert _resolve_mode("?f") == "float"
    assert _resolve_mode("?u") == "uri"
    assert _resolve_mode("?p") == "path"


def test_resolve_mode_falls_back_to_fixed_for_literal_value():
    assert _resolve_mode("alice@example.com") == "fixed"
    assert _resolve_mode("42") == "fixed"


# ---------------------------------------------------------------------------
# Fuzz generators -- statistically cover the edge pools over many samples
# ---------------------------------------------------------------------------

def test_fuzz_int_samples_cover_some_edge_cases():
    random.seed(0xC14)
    pool = {_fuzz_int() for _ in range(500)}
    edge = set(_INT_EDGE_CASES) & pool
    assert len(edge) >= 5, (
        "Expected the edge pool to be sampled at least 5 distinct times "
        f"out of 500 draws; saw {len(edge)} ({sorted(edge)})"
    )


def test_fuzz_long_samples_cover_long_boundaries():
    random.seed(0xC14)
    pool = {_fuzz_long() for _ in range(500)}
    long_only = {x for x in _LONG_EDGE_CASES if x not in _INT_EDGE_CASES}
    assert long_only & pool, (
        "Expected at least one int64-only boundary to be drawn"
    )


def test_fuzz_string_samples_include_edge_payloads():
    random.seed(0xC14)
    pool = {_fuzz_string() for _ in range(500)}
    # 'A' * 65536 is a memorable canary; ensure something from the edge
    # set actually shows up.
    assert pool & set(_STRING_EDGE_CASES)


def test_fuzz_float_includes_nan_or_inf_across_samples():
    random.seed(0xC14)
    samples = [_fuzz_float() for _ in range(500)]
    assert any(s in ("NaN", "Infinity", "-Infinity") for s in samples)


def test_fuzz_uri_samples_include_javascript_or_file_scheme():
    random.seed(0xC14)
    samples = [_fuzz_uri() for _ in range(500)]
    assert any(s.startswith("javascript:") or s.startswith("file:") for s in samples)


def test_fuzz_path_includes_traversal_pattern():
    random.seed(0xC14)
    samples = [_fuzz_path() for _ in range(200)]
    assert any(".." in s for s in samples)


# ---------------------------------------------------------------------------
# _next_value dispatch
# ---------------------------------------------------------------------------

def test_next_value_uses_fixed_when_mode_is_fixed():
    spec = {"mode": "fixed", "fixed_value": "alice@example.com"}
    v, t = _next_value(spec)
    assert v == "alice@example.com"
    # Inferred type for a non-numeric / non-boolean literal
    assert t == "string"


def test_next_value_long_returns_long_type():
    random.seed(0xC14)
    spec = {"mode": "long", "fixed_value": None, "last_value": None}
    v, t = _next_value(spec)
    assert t == "long"
    # Must round-trip through Java long range
    assert -(2 ** 63) <= int(v) <= (2 ** 63) - 1


def test_next_value_uri_returns_uri_type():
    random.seed(0xC14)
    spec = {"mode": "uri", "fixed_value": None, "last_value": None}
    v, t = _next_value(spec)
    assert t == "uri"
    assert ":" in v


def test_next_value_auto_picks_from_known_modes():
    random.seed(0xC14)
    spec = {"mode": "auto", "fixed_value": None, "last_value": None}
    seen_types = {_next_value(spec)[1] for _ in range(200)}
    # At least three distinct am-type tags should have surfaced
    assert len(seen_types & {"string", "int", "long", "float", "uri", "bool"}) >= 3


# ---------------------------------------------------------------------------
# Sanity on the am-extras flag mapping
# ---------------------------------------------------------------------------

def test_am_extra_flag_map_has_all_supported_types():
    assert _AM_EXTRA_FLAG["string"] == "--es"
    assert _AM_EXTRA_FLAG["int"]    == "--ei"
    assert _AM_EXTRA_FLAG["long"]   == "--el"
    assert _AM_EXTRA_FLAG["float"]  == "--ef"
    assert _AM_EXTRA_FLAG["bool"]   == "--ez"
    assert _AM_EXTRA_FLAG["uri"]    == "--eu"


def test_auto_choices_is_a_subset_of_supported_modes():
    # Every auto-pickable mode must dispatch in _next_value
    for mode in _AUTO_CHOICES:
        spec = {"mode": mode, "fixed_value": None, "last_value": None}
        v, t = _next_value(spec)
        assert isinstance(v, str)
        assert t in _AM_EXTRA_FLAG or t == "string"
