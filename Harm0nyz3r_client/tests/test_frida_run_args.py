"""Tests for the E-batch-1 --arg / _args prelude added to frida_run."""

import json

import pytest

from commands.android.frida_run import _build_args_prelude


def test_no_args_returns_empty_string():
    assert _build_args_prelude([]) == ""


def test_single_arg_produces_const_args_declaration():
    out = _build_args_prelude([("classPattern", "okhttp3.*")])
    assert out.startswith("const _args = {")
    assert out.endswith("};\n\n")
    assert "classPattern" in out
    assert "okhttp3.*" in out


def test_value_is_json_encoded_so_quotes_and_backslashes_survive():
    out = _build_args_prelude([("pattern", 'foo"bar\\baz')])
    # The output must be valid JS: extracting the JSON portion and
    # decoding it round-trips back to the original value.
    inside = out[out.index("{") + 1: out.rindex("}")]
    kv = inside.strip()
    assert kv.startswith("pattern:")
    raw = kv.split(":", 1)[1].strip().rstrip(",")
    assert json.loads(raw) == 'foo"bar\\baz'


def test_multiple_args_are_comma_separated():
    out = _build_args_prelude([
        ("classPattern", "okhttp3.*"),
        ("methodPattern", "execute"),
        ("includeReturn", "false"),
    ])
    assert out.count(":") == 3
    # Trailing comma is invalid JS -- ensure we don't emit one
    assert ",\n};" not in out
    assert "};\n\n" in out


def test_invalid_keys_raise_value_error():
    bad_keys = ["1classPattern", "class-pattern", "class pattern", "", "class.pattern"]
    for bad in bad_keys:
        with pytest.raises(ValueError, match="JS identifier"):
            _build_args_prelude([(bad, "v")])


def test_valid_identifier_keys_accepted():
    good_keys = ["a", "A", "_arg", "arg1", "ARG_ONE", "classPattern42"]
    for good in good_keys:
        out = _build_args_prelude([(good, "v")])
        assert good + ":" in out.replace(" ", "")
