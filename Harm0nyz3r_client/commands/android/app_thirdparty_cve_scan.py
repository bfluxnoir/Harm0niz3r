# -*- coding: utf-8 -*-
# commands/android/app_thirdparty_cve_scan.py
"""
app_thirdparty_cve_scan - inventory third-party Android libraries used by
a decompiled app and surface the historical CVEs known for each.

V1 design
---------
This is intentionally an INVENTORY + KNOWN-CVE ANNOTATION tool, NOT a
precise version-aware scanner.  Library presence is detected by class
fingerprint (e.g. okhttp3.OkHttpClient, com.fasterxml.jackson.databind
.ObjectMapper), and any historical CVE recorded for that library in
the bundled JSON DB is attached to the finding so the operator knows
which version-pin to verify by hand.

V1 deliberately does NOT
- parse build.gradle to discover the actual pinned version
- infer the version from class layout / string constants
- treat 'class is present' as 'app is exploitable'
Those three would each generate false-positive HIGHs without
deepening confidence -- the operator's manual version check is
better than a wrong red flag in the report.

For each detected library the command emits one finding per known
CVE, plus one INFO finding for libraries that ship without any
recorded CVE (so the inventory itself is visible).  The severity of
each per-CVE finding is taken from the CVE entry in the DB.
"""

import json
import os
import re
from typing import List

from commands.base import Command, CommandSource


_DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "data",
    "android_thirdparty_cves.json",
)


# ---------------------------------------------------------------------------
# Finding shape
# ---------------------------------------------------------------------------

class CveFinding:
    __slots__ = (
        "library", "cve_id", "severity", "fixed_in", "summary", "files",
    )

    def __init__(
        self,
        library,
        cve_id,
        severity,
        fixed_in,
        summary,
        files,
    ):
        self.library = library
        self.cve_id = cve_id
        self.severity = severity
        self.fixed_in = fixed_in
        self.summary = summary
        self.files = list(files)

    def to_dict(self) -> dict:
        return {
            "library":  self.library,
            "cve_id":   self.cve_id,
            "severity": self.severity,
            "fixed_in": self.fixed_in,
            "summary":  self.summary,
            "files":    self.files,
        }


# ---------------------------------------------------------------------------
# DB / scan
# ---------------------------------------------------------------------------

_TEXT_EXTS = {".java", ".kt", ".smali"}


def _load_db() -> dict:
    with open(_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _search_terms(detect: str):
    """Yield both 'java.style' and 'smali/style' patterns."""
    slash = detect.replace(".", "/")
    if slash == detect:
        return (detect,)
    return (detect, slash)


def _detect_libraries(root: str, db: dict) -> dict:
    """
    Returns a dict keyed by library name -> {'lib': <DB entry>,
    'files': sorted list of file paths where the fingerprint matched}.
    """
    libs = db.get("libraries", [])
    terms = [(lib, _search_terms(lib["detect"])) for lib in libs]
    found: dict = {}

    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in _TEXT_EXTS:
                continue
            full = os.path.join(dirpath, name)
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except OSError:
                continue
            rel = os.path.relpath(full, root)
            for lib, tlist in terms:
                if any(t in text for t in tlist):
                    entry = found.setdefault(
                        lib["name"],
                        {"lib": lib, "files": set()},
                    )
                    entry["files"].add(rel)

    # Normalise -> sorted lists for stable output
    for entry in found.values():
        entry["files"] = sorted(entry["files"])
    return found


def _build_findings(found: dict) -> List[CveFinding]:
    out: List[CveFinding] = []
    for lib_name in sorted(found.keys()):
        entry = found[lib_name]
        lib = entry["lib"]
        files = entry["files"]
        cves = lib.get("cves") or []
        if not cves:
            out.append(CveFinding(
                library=lib_name,
                cve_id="",
                severity="INFO",
                fixed_in="",
                summary="3rd-party library present; no known CVEs in the V1 DB.",
                files=files,
            ))
            continue
        for cve in cves:
            out.append(CveFinding(
                library=lib_name,
                cve_id=cve.get("id", ""),
                severity=cve.get("severity", "INFO"),
                fixed_in=cve.get("fixed_in", ""),
                summary=cve.get("summary", ""),
                files=files,
            ))
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_BOLD = "\033[1m"; _DIM = "\033[2m"; _RST = "\033[0m"
_SEV_COLOR = {
    "HIGH":   "\033[1;91m",
    "MEDIUM": "\033[1;93m",
    "LOW":    "\033[1;94m",
    "INFO":   "\033[1;90m",
}
_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def _render_console(root: str, findings: List[CveFinding], db: dict) -> str:
    sep = "=" * 60
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines = [
        sep,
        f"{_BOLD}3rd-PARTY LIBRARY CVE SCAN  {root}{_RST}",
        sep,
        f"  Bundled DB version : {db.get('version', '?')}  "
        f"({len(db.get('libraries', []))} libraries known)",
        f"  Findings           : {len(findings)} total  "
        f"({counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, "
        f"{counts['LOW']} LOW, {counts['INFO']} INFO)",
        "-" * 60,
    ]
    if not findings:
        lines.append("  No bundled library fingerprints matched.")
        lines.append(sep)
        return "\n".join(lines)
    # Group by library so the same lib's CVEs cluster together
    by_lib: dict = {}
    for f in findings:
        by_lib.setdefault(f.library, []).append(f)
    for lib in sorted(by_lib.keys()):
        bucket = sorted(by_lib[lib], key=lambda x: _SEV_ORDER.get(x.severity, 9))
        lines.append("")
        lines.append(f"  {_BOLD}{lib}{_RST}")
        if bucket:
            files = bucket[0].files
            shown = files[:4]
            lines.append(
                f"    files: {', '.join(shown)}"
                + (f"  (+{len(files) - 4} more)" if len(files) > 4 else "")
            )
        for f in bucket:
            color = _SEV_COLOR.get(f.severity, "")
            if f.cve_id:
                lines.append(
                    f"    [{color}{f.severity}{_RST}] {f.cve_id}  fixed in {f.fixed_in}"
                )
                lines.append(f"        {_DIM}{f.summary}{_RST}")
            else:
                lines.append(f"    [{color}{f.severity}{_RST}] {f.summary}")
    lines.append("")
    lines.append("-" * 60)
    lines.append(
        "  Reminder: this is a class-fingerprint inventory, NOT a precise"
    )
    lines.append(
        "  version-aware scan.  Confirm the actual library version in"
    )
    lines.append("  build.gradle / app/build.gradle before treating any HIGH /")
    lines.append("  MEDIUM finding as an actionable vulnerability.")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(root: str, findings: List[CveFinding], db: dict) -> str:
    return json.dumps({
        "root":     root,
        "db_version": db.get("version", None),
        "findings": [f.to_dict() for f in findings],
        "counts":   {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
        },
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidAppThirdpartyCveScanCommand(Command):
    @property
    def name(self) -> str:
        return "app_thirdparty_cve_scan"

    def help(self) -> str:
        return (
            "app_thirdparty_cve_scan <directory> [--json]\n"
            "  Walk a decompiled Android source tree, detect well-known\n"
            "  third-party libraries by class fingerprint (OkHttp, Apache\n"
            "  Commons Collections, Bouncy Castle, Jackson Databind, jsoup,\n"
            "  SQLCipher, Volley, ...), and surface the historical CVEs\n"
            "  recorded for each library in the bundled JSON DB.\n"
            "  --json  Emit findings as JSON instead of the console table.\n\n"
            "Examples:\n"
            "  app_thirdparty_cve_scan ./decompiled/com.example.target/\n"
            "  app_thirdparty_cve_scan ./decompiled/com.example.target/ --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        as_json = False
        if "--json" in args:
            as_json = True
            args = [a for a in args if a != "--json"]
        if len(args) != 1:
            console._print_message(
                "INFO",
                "Usage: app_thirdparty_cve_scan <directory> [--json]"
            )
            return
        root = args[0]
        if not os.path.isdir(root):
            console._print_message("ERROR", f"Not a directory: {root}")
            return
        try:
            db = _load_db()
        except (OSError, json.JSONDecodeError) as e:
            console._print_message("ERROR", f"Could not load bundled CVE DB: {e}")
            return
        console._print_message(
            "INFO",
            f"Scanning {root} against {len(db.get('libraries', []))} known libraries ..."
        )
        found = _detect_libraries(root, db)
        findings = _build_findings(found)
        if as_json:
            print(_render_json(root, findings, db))
        else:
            print(_render_console(root, findings, db))


def register(registry_func):
    registry_func(AndroidAppThirdpartyCveScanCommand())
