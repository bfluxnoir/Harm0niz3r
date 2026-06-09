"""Smoke tests for parsers/harmonyos_parser.parse_app_dump_string.

Kept intentionally light so a HarmonyOS-side change can't be broken by
purely Android-focused refactors.
"""

from parsers.harmonyos_parser import parse_app_dump_string


def test_parses_minimal_harmonyos_dump_to_dict():
    # The HarmonyOS parser expects 'bundle name <newline> JSON content',
    # which is what 'hdc bm dump -n <bundle>' produces.  We don't try to
    # match the exact field set across HarmonyOS versions -- just confirm
    # the function returns a dict for a syntactically valid input and
    # doesn't blow up.
    sample = "com.example.bundle:\n" + '{"reqPermissions": []}'
    parsed = parse_app_dump_string(sample)
    assert isinstance(parsed, dict)


def test_rejects_empty_input():
    import pytest
    with pytest.raises(ValueError):
        parse_app_dump_string("")
