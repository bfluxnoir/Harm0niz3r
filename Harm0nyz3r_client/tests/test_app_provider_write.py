"""Tests for the C13 write surface added to commands/android/app_provider.py."""

from commands.android.app_provider import (
    _validate_bind_spec, _build_content_args, _classify_write,
    AndroidAppProviderCommand,
)


# ---------------------------------------------------------------------------
# _validate_bind_spec
# ---------------------------------------------------------------------------

def test_valid_bind_spec_returns_triple():
    assert _validate_bind_spec("name:s:Alice") == ("name", "s", "Alice")
    assert _validate_bind_spec("age:i:42") == ("age", "i", "42")
    assert _validate_bind_spec("active:b:true") == ("active", "b", "true")


def test_bind_spec_keeps_colons_inside_value_intact():
    assert _validate_bind_spec("url:s:https://x.example/api:8080") == (
        "url", "s", "https://x.example/api:8080",
    )


def test_bind_spec_rejects_unknown_type():
    try:
        _validate_bind_spec("col:zzz:value")
    except ValueError as e:
        assert "type must be" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_bind_spec_rejects_missing_columns_or_pieces():
    for bad in ("only_one", "no:value", ":i:42", "col:s:"):
        try:
            r = _validate_bind_spec(bad)
            # Empty value is allowed; empty column or missing type is not.
            if bad == "col:s:":
                assert r == ("col", "s", "")
                continue
            raise AssertionError(f"expected ValueError for {bad!r}, got {r}")
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# _build_content_args
# ---------------------------------------------------------------------------

def test_build_args_for_insert_carries_every_bind_in_order():
    binds = [("a", "s", "x"), ("b", "i", "7")]
    cmd = _build_content_args("insert", "content://x/y", binds, None)
    assert cmd == [
        "content", "insert", "--uri", "content://x/y",
        "--bind", "a:s:x",
        "--bind", "b:i:7",
    ]


def test_build_args_for_update_appends_where_clause():
    cmd = _build_content_args(
        "update", "content://x/y", [("a", "s", "z")], '_id=1',
    )
    assert cmd[-2] == "--where"
    assert cmd[-1] == "_id=1"


def test_build_args_for_delete_with_no_binds_no_where_is_just_uri():
    cmd = _build_content_args("delete", "content://x/y", [], None)
    assert cmd == ["content", "delete", "--uri", "content://x/y"]


# ---------------------------------------------------------------------------
# _classify_write
# ---------------------------------------------------------------------------

def test_classify_security_exception_is_denied():
    verdict, markers = _classify_write(
        "", "java.lang.SecurityException: Permission Denial: writing requires foo", 1,
    )
    assert verdict == "DENIED"
    assert "Permission Denial" in markers
    assert "SecurityException" in markers


def test_classify_clean_run_is_ok():
    assert _classify_write("Row count: 1", "", 0) == ("OK", [])


def test_classify_nonzero_exit_with_no_markers_is_error():
    assert _classify_write("", "", 7) == ("ERROR", [])


# ---------------------------------------------------------------------------
# _parse_args (the dispatcher's argument-handling layer)
# ---------------------------------------------------------------------------

def _parse(args):
    return AndroidAppProviderCommand()._parse_args(args)


def test_parse_query_only_form_returns_no_op():
    pkg, uri, op, binds, where, sta, log, err = _parse(
        ["com.example.app", "content://x/y"],
    )
    assert err is None
    assert pkg == "com.example.app"
    assert uri == "content://x/y"
    assert op is None
    assert binds == []
    assert where is None


def test_parse_insert_populates_binds_and_marks_op():
    pkg, uri, op, binds, where, *_ = _parse([
        "com.example.app", "content://x/y",
        "--insert", "--bind", "a:s:hi", "--bind", "b:i:9",
    ])
    assert op == "insert"
    assert binds == [("a", "s", "hi"), ("b", "i", "9")]


def test_parse_update_keeps_where_clause():
    pkg, uri, op, binds, where, *_ = _parse([
        "com.example.app", "content://x/y",
        "--update", "--bind", "a:s:bye", "--where", "_id=1",
    ])
    assert op == "update"
    assert binds == [("a", "s", "bye")]
    assert where == "_id=1"


def test_parse_delete_without_binds_is_accepted():
    pkg, uri, op, binds, where, *_ = _parse([
        "com.example.app", "content://x/y",
        "--delete", "--where", "_id=1",
    ])
    assert op == "delete"
    assert binds == []
    assert where == "_id=1"


def test_parse_rejects_two_write_actions():
    *_, err = _parse([
        "com.example.app", "content://x/y", "--insert", "--update",
    ])
    assert err and "mutually exclusive" in err


def test_parse_rejects_insert_without_binds():
    *_, err = _parse(["com.example.app", "content://x/y", "--insert"])
    assert err and "needs at least one --bind" in err


def test_parse_rejects_delete_with_binds():
    *_, err = _parse([
        "com.example.app", "content://x/y", "--delete",
        "--bind", "a:s:1",
    ])
    assert err and "does not take --bind" in err


def test_parse_rejects_write_op_without_uri():
    *_, err = _parse(["com.example.app", "--insert", "--bind", "a:s:x"])
    assert err and "requires a URI" in err


def test_parse_rejects_unknown_bind_type_via_validation():
    *_, err = _parse([
        "com.example.app", "content://x/y", "--insert",
        "--bind", "a:zz:v",
    ])
    assert err and "type must be" in err
