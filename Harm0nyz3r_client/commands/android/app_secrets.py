# -*- coding: utf-8 -*-
# commands/android/app_secrets.py
"""
app_secrets - regex scan over a decompiled APK tree for hardcoded secrets,
credentials, API keys, JWTs, and other low-hanging static-analysis findings.

Targets the output produced by app_decompile, but accepts any directory
containing source-shaped files (.java, .kt, .smali, .xml, .json, .properties,
.txt).  Binary blobs are skipped by extension.

Each finding records:
  - file        relative path of the file the pattern matched in
  - line        1-indexed line number of the first match
  - rule        rule id from _RULES
  - severity    HIGH / MEDIUM / LOW / INFO
  - match       the matched substring (truncated)
"""

import json
import os
import re
from typing import List, Optional

from commands.base import Command, CommandSource


_TEXT_EXTENSIONS = {
    ".java", ".kt", ".smali", ".xml", ".json",
    ".properties", ".txt", ".cfg", ".conf",
    ".yml", ".yaml", ".env", ".md", ".html",
}

# Each rule: (id, severity, compiled regex)
_RULES = [
    ("AWS_ACCESS_KEY_ID",     "HIGH",   re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("GOOGLE_API_KEY",        "HIGH",   re.compile(r"\b(AIza[0-9A-Za-z_\-]{32,40})\b")),
    ("STRIPE_LIVE_KEY",       "HIGH",   re.compile(r"\b(sk_live_[0-9a-zA-Z]{16,})\b")),
    ("STRIPE_PUBLIC_KEY",     "MEDIUM", re.compile(r"\b(pk_live_[0-9a-zA-Z]{16,})\b")),
    ("SLACK_TOKEN",           "HIGH",   re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b")),
    ("GITHUB_PAT",            "HIGH",   re.compile(r"\b(ghp_[0-9A-Za-z]{36})\b")),
    ("JWT",                   "MEDIUM", re.compile(r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{8,})\b")),
    ("PRIVATE_KEY_BLOCK",     "HIGH",   re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("FIREBASE_DB_URL",       "MEDIUM", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("INTERNAL_URL_HTTP",     "LOW",    re.compile(r"\bhttp://(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.[0-9.]+")),
    ("EMAIL",                 "INFO",   re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    # Generic key/value secret pattern -- intentionally INFO because it false-
    # positives on resource strings, but useful as a manual-review pointer.
    ("GENERIC_SECRET_ASSIGN", "INFO",
     re.compile(
         r"(?i)(?:api[_-]?key|secret|password|passwd|token|auth)"
         r"\s*[:=]\s*[\"']([A-Za-z0-9_\-./+=]{16,})[\"']"
     )),
]

_BOLD = "\033[1m"
_DIM = "\033[2m"
_RST = "\033[0m"
_SEV_COLOR = {
    "HIGH":   "\033[1;91m",
    "MEDIUM": "\033[1;93m",
    "LOW":    "\033[1;94m",
    "INFO":   "\033[1;90m",
}


class SecretFinding:
    __slots__ = ("file", "line", "rule", "severity", "match")

    def __init__(self, file: str, line: int, rule: str, severity: str, match: str) -> None:
        self.file = file
        self.line = line
        self.rule = rule
        self.severity = severity
        self.match = match

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "match": self.match,
        }


def _scan_text(path: str, rel: str) -> List[SecretFinding]:
    findings: List[SecretFinding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for ln, line in enumerate(f, start=1):
                if len(line) > 4096:
                    # extremely long single line (minified bundle) -- still scan
                    # but truncate the recorded match
                    pass
                for rule_id, sev, rx in _RULES:
                    m = rx.search(line)
                    if not m:
                        continue
                    matched = m.group(0)
                    if len(matched) > 120:
                        matched = matched[:117] + "..."
                    findings.append(SecretFinding(rel, ln, rule_id, sev, matched))
    except OSError:
        pass
    return findings


def _walk_and_scan(root: str) -> List[SecretFinding]:
    findings: List[SecretFinding] = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in _TEXT_EXTENSIONS:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            findings.extend(_scan_text(full, rel))
    return findings


_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def _render_console(root: str, findings: List[SecretFinding]) -> str:
    sep = "=" * 60
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines = [
        sep,
        f"{_BOLD}APP SECRETS SCAN  {root}{_RST}",
        sep,
        f"  Findings : {len(findings)} total  "
        f"({counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, "
        f"{counts['LOW']} LOW, {counts['INFO']} INFO)",
        "-" * 60,
    ]
    if not findings:
        lines.append("  Nothing flagged by the V1 rule set.")
        lines.append(sep)
        return "\n".join(lines)
    for f in sorted(findings, key=lambda x: (_SEV_ORDER.get(x.severity, 9), x.file, x.line)):
        color = _SEV_COLOR.get(f.severity, "")
        lines.append("")
        lines.append(f"  [{color}{f.severity}{_RST}] {_BOLD}{f.rule}{_RST}  {f.file}:{f.line}")
        lines.append(f"        {_DIM}{f.match}{_RST}")
    lines.append("")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(root: str, findings: List[SecretFinding]) -> str:
    return json.dumps({
        "root": root,
        "findings": [f.to_dict() for f in findings],
        "counts": {
            "total":  len(findings),
            "HIGH":   sum(1 for f in findings if f.severity == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
            "LOW":    sum(1 for f in findings if f.severity == "LOW"),
            "INFO":   sum(1 for f in findings if f.severity == "INFO"),
        },
    }, indent=2)


class AndroidAppSecretsCommand(Command):
    @property
    def name(self) -> str:
        return "app_secrets"

    def help(self) -> str:
        return (
            "app_secrets <directory> [--json]\n"
            "  Regex scan a directory tree (typically the output of\n"
            "  app_decompile) for hardcoded secrets, API keys, JWTs and\n"
            "  private-key blocks.  Reports severity-tagged findings.\n\n"
            "  --json  Emit findings as JSON instead of the console view.\n\n"
            "Examples:\n"
            "  app_secrets ./decompiled/com.example.target/\n"
            "  app_secrets ./decompiled/com.example.target/ --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        as_json = False
        if "--json" in args:
            as_json = True
            args = [a for a in args if a != "--json"]
        if len(args) != 1:
            console._print_message("INFO", "Usage: app_secrets <directory> [--json]")
            return
        root = args[0]
        if not os.path.isdir(root):
            console._print_message("ERROR", f"Not a directory: {root}")
            return
        console._print_message("INFO", f"Scanning {root} ...")
        findings = _walk_and_scan(root)
        if as_json:
            print(_render_json(root, findings))
        else:
            print(_render_console(root, findings))


def register(registry_func):
    registry_func(AndroidAppSecretsCommand())
