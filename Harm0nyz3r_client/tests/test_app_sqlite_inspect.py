"""Tests for commands/android/app_sqlite_inspect.py."""

import json
import os
import sqlite3
import tempfile

from commands.android.app_sqlite_inspect import (
    _walk_dbs, _render_console, _render_json,
)


def _make_db(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
    cur.executemany(
        "INSERT INTO users (name, secret) VALUES (?, ?)",
        [("admin", "hunter2"), ("alice", "supersecret"), ("bob", "p@ssw0rd")],
    )
    cur.execute("CREATE TABLE empty_t (a TEXT)")
    conn.commit()
    conn.close()


def test_walk_finds_db_and_reports_tables_and_row_counts():
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "databases", "users.db")
    _make_db(db_path)
    dbs = _walk_dbs(tmp)
    assert len(dbs) == 1
    db = dbs[0]
    assert db.ok is True
    names = sorted(t.name for t in db.tables)
    assert names == ["empty_t", "users"]
    users = next(t for t in db.tables if t.name == "users")
    assert users.row_count == 3
    col_names = sorted(c["name"] for c in users.columns)
    assert col_names == ["id", "name", "secret"]


def test_sample_rows_returned_when_requested():
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "users.db")
    _make_db(db_path)
    dbs = _walk_dbs(tmp, sample=2)
    users = next(t for t in dbs[0].tables if t.name == "users")
    assert users.sample_rows is not None
    assert len(users.sample_rows) == 2
    # First row should be 'admin' / 'hunter2'
    assert users.sample_rows[0]["name"] == "admin"
    assert users.sample_rows[0]["secret"] == "hunter2"


def test_non_sqlite_file_is_reported_unreadable():
    tmp = tempfile.mkdtemp()
    bogus = os.path.join(tmp, "fake.db")
    with open(bogus, "w", encoding="utf-8") as f:
        f.write("this is definitely not a SQLite file")
    dbs = _walk_dbs(tmp)
    assert len(dbs) == 1
    assert dbs[0].ok is False
    assert dbs[0].error  # error message attached


def test_empty_directory_reports_zero_dbs():
    empty = tempfile.mkdtemp()
    assert _walk_dbs(empty) == []


def test_json_render_shape():
    tmp = tempfile.mkdtemp()
    _make_db(os.path.join(tmp, "x.db"))
    dbs = _walk_dbs(tmp, sample=1)
    payload = json.loads(_render_json(tmp, dbs))
    assert payload["counts"]["total"] == 1
    assert payload["counts"]["readable"] == 1
    table = payload["databases"][0]["tables"][0]
    assert "name" in table and "columns" in table and "row_count" in table


def test_console_render_mentions_unreadable_marker():
    tmp = tempfile.mkdtemp()
    bogus = os.path.join(tmp, "broken.db")
    with open(bogus, "w", encoding="utf-8") as f:
        f.write("not sqlite")
    dbs = _walk_dbs(tmp)
    out = _render_console(tmp, dbs)
    assert "[unreadable]" in out
    assert "broken.db" in out
