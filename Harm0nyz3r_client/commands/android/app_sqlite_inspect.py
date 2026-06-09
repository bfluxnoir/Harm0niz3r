# -*- coding: utf-8 -*-
# commands/android/app_sqlite_inspect.py
"""
app_sqlite_inspect - walk a directory (typically the output of
app_sandbox_dump), find every SQLite database, and surface its tables /
columns / row counts.  Optional --sample N dumps the first N rows from
each table for a quick eyeball pass.

V1 deliberately uses Python's stdlib sqlite3 module, so no native
deps.  Encrypted databases (SQLCipher, EncDB) won't open here and will
be reported separately so a pentester knows they're worth a closer look.
"""

import json
import os
import sqlite3
from typing import List, Optional

from commands.base import Command, CommandSource


_DB_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".db-journal-skip", ".db3")


class TableInfo:
    __slots__ = ("name", "columns", "row_count", "sample_rows")

    def __init__(self, name, columns, row_count, sample_rows=None):
        self.name = name
        self.columns = columns
        self.row_count = row_count
        self.sample_rows = sample_rows

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "columns":     self.columns,
            "row_count":   self.row_count,
            "sample_rows": self.sample_rows,
        }


class DbInfo:
    __slots__ = ("path", "ok", "tables", "error")

    def __init__(self, path, ok, tables=None, error=None):
        self.path = path
        self.ok = ok
        self.tables = tables or []
        self.error = error

    def to_dict(self) -> dict:
        return {
            "path":   self.path,
            "ok":     self.ok,
            "error":  self.error,
            "tables": [t.to_dict() for t in self.tables],
        }


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------

def _is_db_filename(name: str) -> bool:
    lower = name.lower()
    if any(lower.endswith(suf) for suf in _DB_SUFFIXES):
        return True
    # WAL / SHM siblings are not opened directly
    if lower.endswith("-wal") or lower.endswith("-shm") or lower.endswith("-journal"):
        return False
    return False


def _inspect_db(path: str, sample: int = 0) -> DbInfo:
    try:
        # Open read-only with the URI form so we never accidentally write
        # to the dumped file.
        uri = f"file:{os.path.abspath(path)}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2)
    except sqlite3.Error as e:
        return DbInfo(path, False, error=str(e))

    try:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
            table_names = [r[0] for r in cur.fetchall()]
        except sqlite3.DatabaseError as e:
            return DbInfo(path, False, error=f"Not a SQLite database: {e}")

        tables: List[TableInfo] = []
        for name in table_names:
            # PRAGMA table_info
            try:
                cur.execute(f'PRAGMA table_info("{name}")')
                columns = [{"name": r[1], "type": r[2]} for r in cur.fetchall()]
            except sqlite3.Error as e:
                columns = [{"error": str(e)}]
            # Row count
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{name}"')
                row_count = cur.fetchone()[0]
            except sqlite3.Error:
                row_count = -1
            # Sample rows
            sample_rows = None
            if sample and sample > 0:
                try:
                    cur.execute(f'SELECT * FROM "{name}" LIMIT {int(sample)}')
                    col_names = [c[0] for c in cur.description] if cur.description else []
                    sample_rows = [
                        {col_names[i]: _safe_value(r[i]) for i in range(len(col_names))}
                        for r in cur.fetchall()
                    ]
                except sqlite3.Error:
                    sample_rows = []
            tables.append(TableInfo(name, columns, row_count, sample_rows))
        return DbInfo(path, True, tables=tables)
    finally:
        conn.close()


def _safe_value(v):
    """Make a row value JSON-safe and readable in the console."""
    if isinstance(v, bytes):
        try:
            txt = v.decode("utf-8")
            if len(txt) > 80:
                return txt[:77] + "..."
            return txt
        except UnicodeDecodeError:
            return f"<bytes len={len(v)}>"
    if isinstance(v, str) and len(v) > 80:
        return v[:77] + "..."
    return v


def _walk_dbs(root: str, sample: int = 0) -> List[DbInfo]:
    out: List[DbInfo] = []
    if os.path.isfile(root):
        out.append(_inspect_db(root, sample=sample))
        return out
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            if _is_db_filename(name):
                full = os.path.join(dirpath, name)
                out.append(_inspect_db(full, sample=sample))
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_BOLD = "\033[1m"
_DIM = "\033[2m"
_RST = "\033[0m"
_GREEN = "\033[1;92m"
_YELLOW = "\033[1;93m"
_RED = "\033[1;91m"


def _render_console(root: str, dbs: List[DbInfo]) -> str:
    sep = "=" * 60
    lines = [
        sep,
        f"{_BOLD}SQLITE INSPECT  {root}{_RST}",
        sep,
        f"  Databases : {len(dbs)} found",
        "-" * 60,
    ]
    if not dbs:
        lines.append("  No SQLite databases discovered.")
        lines.append(sep)
        return "\n".join(lines)
    for db in dbs:
        lines.append("")
        if not db.ok:
            lines.append(f"  {_RED}[unreadable]{_RST} {db.path}")
            lines.append(f"          {_DIM}{db.error}{_RST}")
            continue
        lines.append(f"  {_GREEN}[ok]{_RST} {_BOLD}{db.path}{_RST}")
        lines.append(f"          Tables: {len(db.tables)}")
        for t in db.tables:
            cols = ", ".join(c.get("name", "?") for c in t.columns)
            lines.append(
                f"            * {_BOLD}{t.name}{_RST}  "
                f"({t.row_count} rows; cols: {cols if cols else '(none)'})"
            )
            if t.sample_rows:
                lines.append("              sample:")
                for r in t.sample_rows:
                    lines.append(f"                {r}")
    lines.append("")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(root: str, dbs: List[DbInfo]) -> str:
    return json.dumps({
        "root":      root,
        "databases": [d.to_dict() for d in dbs],
        "counts":    {
            "total":      len(dbs),
            "readable":   sum(1 for d in dbs if d.ok),
            "unreadable": sum(1 for d in dbs if not d.ok),
        },
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidAppSqliteInspectCommand(Command):
    @property
    def name(self) -> str:
        return "app_sqlite_inspect"

    def help(self) -> str:
        return (
            "app_sqlite_inspect <path> [--sample N] [--json]\n"
            "  Walk <path> (file or directory) and inspect every SQLite\n"
            "  database found.  For each: list tables, columns and row\n"
            "  counts.  Use --sample N to also dump the first N rows from\n"
            "  each table.\n"
            "  --json  Emit JSON instead of the console view.\n\n"
            "Examples:\n"
            "  app_sqlite_inspect ./sandbox/com.example.target/databases/\n"
            "  app_sqlite_inspect ./sandbox/com.example.target/ --sample 3\n"
            "  app_sqlite_inspect ./db/users.db --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        as_json = False
        sample = 0
        positional: List[str] = []
        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--json":
                as_json = True; i += 1
            elif tok == "--sample" and i + 1 < len(args):
                try:
                    sample = int(args[i + 1])
                except ValueError:
                    console._print_message("WARNING", f"Invalid --sample value '{args[i + 1]}'; using 0.")
                    sample = 0
                i += 2
            else:
                positional.append(tok); i += 1

        if len(positional) != 1:
            console._print_message("INFO", "Usage: app_sqlite_inspect <path> [--sample N] [--json]")
            return
        root = positional[0]
        if not os.path.exists(root):
            console._print_message("ERROR", f"Path not found: {root}")
            return
        console._print_message("INFO", f"Scanning {root} for SQLite databases ...")
        dbs = _walk_dbs(root, sample=sample)
        if as_json:
            print(_render_json(root, dbs))
        else:
            print(_render_console(root, dbs))


def register(registry_func):
    registry_func(AndroidAppSqliteInspectCommand())
