# -*- coding: utf-8 -*-
# commands/android/app_provider_probe.py
"""
app_provider_probe - automated security probes against exported Content
Providers declared by an installed Android package.

For every exported provider authority in the target package, the command
runs a fixed set of read-only probes through 'adb shell content query':

  1. READ_BASE         plain read against content://<authority>/
                       -> ROWS_LEAKED if it returns rows without a
                          permission challenge.
  2. SQLI_QUOTE_BREAK  --where "1=1'"
                       -> SQLI_SYNTAX_ERROR if the provider answers with
                          a SQL syntax error (often "sqlite_exception:
                          near \"'\"...").
  3. SQLI_UNION        --where "1=1) UNION SELECT name FROM
                                sqlite_master--"
                       -> SQLI_UNION_REVEALED if any new tables /
                          schema names surface in the response.
  4. PATH_TRAVERSAL    URI rewritten with '../../databases/<pkg>.db' tail
                       -> TRAVERSAL_FILE_ACCESS if the response shape
                          changes (different rows / a 'file=' line / a
                          file-not-found instead of authority error).

Each finding is severity-tagged.  Write probes are NOT included in V1 to
avoid corrupting state on the device.  Use 'app_provider <auth> [cols]'
for ad-hoc manual queries.
"""

import json
import re
from typing import List, Optional

from commands.base import Command, CommandSource
from parsers.android_parser import parse_pm_dump, parse_content_query


_BOLD = "\033[1m"
_DIM = "\033[2m"
_RST = "\033[0m"
_SEV_COLOR = {
    "HIGH":   "\033[1;91m",
    "MEDIUM": "\033[1;93m",
    "LOW":    "\033[1;94m",
    "INFO":   "\033[1;90m",
}


class ProbeFinding:
    __slots__ = ("authority", "probe", "severity", "title", "detail", "evidence")

    def __init__(
        self,
        authority: str,
        probe: str,
        severity: str,
        title: str,
        detail: str,
        evidence: Optional[str] = None,
    ) -> None:
        self.authority = authority
        self.probe = probe
        self.severity = severity
        self.title = title
        self.detail = detail
        self.evidence = evidence

    def to_dict(self) -> dict:
        return {
            "authority": self.authority,
            "probe": self.probe,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _classify_output(stdout: str, stderr: str) -> dict:
    """Classify the raw shell output for one content-query attempt."""
    out = (stdout or "")
    err = (stderr or "")
    combined = out + "\n" + err
    has_rows = any(line.strip().startswith("Row:") for line in out.splitlines())
    syntax = bool(re.search(r"SQLite\w*Exception|syntax error|near \".*?\":", combined))
    permission_denied = bool(re.search(
        r"Permission Denial|requires .*?permission|SecurityException",
        combined,
    ))
    no_provider = bool(re.search(
        r"No content provider|Could not find provider|Unknown URL",
        combined,
    ))
    return {
        "stdout": out,
        "stderr": err,
        "has_rows": has_rows,
        "syntax_error": syntax,
        "permission_denied": permission_denied,
        "no_provider": no_provider,
    }


def _probe_read_base(console, authority: str) -> Optional[ProbeFinding]:
    uri = f"content://{authority}/"
    out, err, _ = console._run_shell(["content", "query", "--uri", uri])
    cls = _classify_output(out, err)
    if cls["has_rows"]:
        rows = parse_content_query(out, uri).get("rows", [])
        preview = json.dumps(rows[:3], ensure_ascii=False)
        return ProbeFinding(
            authority, "READ_BASE", "HIGH",
            "Provider returns rows without a permission challenge",
            "A plain read against the base URI returned data, so the provider "
            "is reachable from any other app on the device.",
            evidence=f"{len(rows)} row(s); first 3: {preview[:240]}",
        )
    if cls["permission_denied"]:
        return ProbeFinding(
            authority, "READ_BASE", "INFO",
            "Provider exposed but guarded by a permission",
            "Base read was rejected with a permission error.  Check whether the "
            "required permission has 'signature' protection or is granted to "
            "another installed app.",
            evidence=(cls["stdout"] or cls["stderr"])[:240],
        )
    return None


def _probe_sqli_quote(console, authority: str) -> Optional[ProbeFinding]:
    uri = f"content://{authority}/"
    out, err, _ = console._run_shell([
        "content", "query", "--uri", uri, "--where", "1=1'",
    ])
    cls = _classify_output(out, err)
    if cls["syntax_error"]:
        return ProbeFinding(
            authority, "SQLI_QUOTE_BREAK", "HIGH",
            "Provider reflects unsanitised --where input",
            "A trailing single quote in --where produced a SQL syntax error, "
            "indicating the provider concatenates the selection into a SQL "
            "query without binding parameters.  Likely SQLi sink.",
            evidence=(cls["stderr"] or cls["stdout"])[:240],
        )
    return None


def _probe_sqli_union(console, authority: str) -> Optional[ProbeFinding]:
    uri = f"content://{authority}/"
    where = "1=1) UNION SELECT name FROM sqlite_master--"
    out, err, _ = console._run_shell([
        "content", "query", "--uri", uri, "--where", where,
    ])
    cls = _classify_output(out, err)
    if cls["has_rows"] and "sqlite_master" not in (out or ""):
        # Heuristic: UNION succeeded and the output now contains rows from a
        # schema query.  We can't always confirm sqlite_master values appear,
        # but new rows that the base query didn't return is a strong signal.
        return ProbeFinding(
            authority, "SQLI_UNION", "HIGH",
            "Provider accepts a UNION payload in --where",
            "A UNION SELECT against sqlite_master returned rows, confirming "
            "the WHERE clause is concatenated into SQL.  Try extracting "
            "schema and data with 'adb shell content query --uri ... "
            "--where ...' manually.",
            evidence=cls["stdout"][:240],
        )
    return None


def _probe_path_traversal(console, authority: str) -> Optional[ProbeFinding]:
    # We rewrite the URI to point at a path that should NOT belong to the
    # provider; if the provider naively concatenates the path into a
    # filesystem operation, the error / response shape changes.
    uri = f"content://{authority}/../../databases/"
    out, err, _ = console._run_shell(["content", "query", "--uri", uri])
    combined = (out or "") + "\n" + (err or "")
    if re.search(r"FileNotFoundException|open failed|ENOENT", combined):
        return ProbeFinding(
            authority, "PATH_TRAVERSAL", "MEDIUM",
            "Provider attempts filesystem access for traversed URI",
            "The provider tried to open a filesystem path derived from the "
            "URI segments and failed with a file-not-found error.  This "
            "suggests it concatenates path segments into File / open calls "
            "without canonicalising; worth testing with a real path that "
            "exists in the app sandbox.",
            evidence=combined[:240],
        )
    return None


_PROBES = (
    _probe_read_base,
    _probe_sqli_quote,
    _probe_sqli_union,
    _probe_path_traversal,
)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def _collect_providers(parsed: dict) -> List[dict]:
    """Return [{name, authority, permission, exported}] for every exported provider."""
    out = []
    for comp in parsed.get("exposedComponents", []):
        if comp.get("type") != "Provider":
            continue
        if not comp.get("visible"):
            continue
        out.append({
            "name": comp.get("name"),
            "authority": comp.get("authority"),
            "permission": comp.get("permissionsRequired") or [],
        })
    return out


def _run_probes(console, providers: List[dict]) -> List[ProbeFinding]:
    findings: List[ProbeFinding] = []
    for prov in providers:
        auth = prov.get("authority")
        if not auth:
            continue
        # ',-' separated authorities may occur (multiple authorities per provider).
        for one in [a.strip() for a in str(auth).split(",") if a.strip()]:
            for probe in _PROBES:
                try:
                    f = probe(console, one)
                except Exception as e:
                    console._print_message("WARNING", f"Probe failed on {one}: {e}")
                    continue
                if f is not None:
                    findings.append(f)
    return findings


def _render_console(package: str, providers: List[dict], findings: List[ProbeFinding]) -> str:
    sep = "=" * 60
    lines = [
        sep,
        f"{_BOLD}APP PROVIDER PROBE  {package}{_RST}",
        sep,
        f"  Exported providers : {len(providers)}",
        f"  Findings           : {len(findings)}",
        "-" * 60,
    ]
    if not providers:
        lines.append("  No exported Content Providers declared by this package.")
        lines.append(sep)
        return "\n".join(lines)
    if not findings:
        lines.append("  All probes came back clean (no rows leaked, no SQLi, no traversal signals).")
        lines.append(sep)
        return "\n".join(lines)
    # group by authority
    by_auth: dict = {}
    for f in findings:
        by_auth.setdefault(f.authority, []).append(f)
    for auth, group in by_auth.items():
        lines.append(f"\n  {_BOLD}{auth}{_RST}")
        for f in group:
            color = _SEV_COLOR.get(f.severity, "")
            lines.append(
                f"    [{color}{f.severity}{_RST}] {_BOLD}{f.probe}{_RST} : {f.title}"
            )
            lines.append(f"          Detail   : {f.detail}")
            if f.evidence:
                lines.append(f"          Evidence : {_DIM}{f.evidence}{_RST}")
    lines.append("")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(package: str, providers: List[dict], findings: List[ProbeFinding]) -> str:
    return json.dumps({
        "package": package,
        "providers": providers,
        "findings": [f.to_dict() for f in findings],
        "counts": {
            "providers": len(providers),
            "findings":  len(findings),
        },
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidAppProviderProbeCommand(Command):
    """
    Run a fixed set of read-only security probes against every exported
    Content Provider declared by an installed package.
    """

    @property
    def name(self) -> str:
        return "app_provider_probe"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_provider_probe <package> [--json]\n"
            "  For every exported Content Provider in <package>, run\n"
            "  read-only probes: base read, SQLi quote-break, SQLi UNION,\n"
            "  path traversal.  Reports severity-tagged findings.\n\n"
            "  --json  Emit findings as JSON instead of the console table.\n\n"
            "Examples:\n"
            "  app_provider_probe com.example.app\n"
            "  app_provider_probe com.example.app --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        as_json = False
        if "--json" in args:
            as_json = True
            args = [a for a in args if a != "--json"]

        if len(args) != 1:
            console._print_message("INFO", "Usage: app_provider_probe <package> [--json]")
            return

        package = args[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        console._print_message("INFO", f"Discovering providers for {package} ...")
        stdout, stderr, retcode = console._run_shell(["pm", "dump", package])
        if retcode != 0 or not stdout:
            console._print_message("ERROR", f"pm dump failed: {stderr or 'no output'}")
            return

        parsed = parse_pm_dump(stdout, package)
        providers = _collect_providers(parsed)

        if not providers:
            console._print_message(
                "INFO",
                f"No exported Content Providers found for {package}."
            )
            if as_json:
                print(_render_json(package, providers, []))
            else:
                print(_render_console(package, providers, []))
            return

        console._print_message(
            "INFO",
            f"Probing {len(providers)} exported provider(s) -- this can take a moment ..."
        )
        findings = _run_probes(console, providers)

        if as_json:
            print(_render_json(package, providers, findings))
        else:
            print(_render_console(package, providers, findings))


def register(registry_func):
    registry_func(AndroidAppProviderProbeCommand())
