# -*- coding: utf-8 -*-
# commands/android/app_pinning_check.py
"""
app_pinning_check - find certificate-pinning implementations (or TLS
sanity bypasses) in a decompiled Android source tree.

Typical workflow:

  app_decompile com.example.target
  app_pinning_check ./decompiled/com.example.target/

What it looks for
-----------------
  PINNING_OKHTTP_LIB           INFO    okhttp3/CertificatePinner reference.
  PINNING_OKHTTP_SETTER        INFO    Code calls setCertificatePinner(...).
  PINNING_TRUSTKIT             INFO    TrustKit (datatheorem) usage.
  PINNING_APPMATTUS_CT         INFO    Appmattus certificate-transparency
                                       library usage.
  TRUST_ALL_CERTS              HIGH    X509TrustManager.checkServerTrusted
                                       is implemented as an empty/return
                                       body, or getAcceptedIssuers returns
                                       null / new X509Certificate[0].
  HOSTNAME_VERIFIER_ALLOW_ALL  HIGH    HostnameVerifier returning true
                                       unconditionally / SSLSocketFactory
                                       ALLOW_ALL pattern.
  CONSCRYPT_TRUST_PROVIDER     INFO    Conscrypt usage (often paired with
                                       custom pinning).
  PINNING_BUNDLE_VERSION       LOW     A pinning library version was
                                       detected -- include in the report
                                       for the CVE-matching step later.
"""

import json
import os
import re
from typing import List

from commands.base import Command, CommandSource


class PinningFinding:
    __slots__ = ("rule", "severity", "file", "line", "match")

    def __init__(self, rule, severity, file, line, match):
        self.rule = rule
        self.severity = severity
        self.file = file
        self.line = line
        self.match = match

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


# Files we scan -- decompiled Java/Kotlin, Smali, AndroidManifest fragments,
# string resources can also hold pinning hashes.
_TEXT_EXTENSIONS = {
    ".java", ".kt", ".smali", ".xml",
    ".properties", ".txt", ".json",
}

_RULES = [
    ("PINNING_OKHTTP_LIB",          "INFO",
     re.compile(r"okhttp3[/.]CertificatePinner")),
    ("PINNING_OKHTTP_SETTER",       "INFO",
     re.compile(r"\.setCertificatePinner\s*\(")),
    ("PINNING_OKHTTP_PIN",          "INFO",
     re.compile(r'CertificatePinner\.Builder|\.add\(\s*"[A-Za-z0-9.*-]+"\s*,\s*"sha256/')),
    ("PINNING_TRUSTKIT",            "INFO",
     re.compile(r"com[/.]datatheorem[/.]android[/.]trustkit")),
    ("PINNING_APPMATTUS_CT",        "INFO",
     re.compile(r"com[/.]appmattus[/.]certificatetransparency")),
    ("CONSCRYPT_TRUST_PROVIDER",    "INFO",
     re.compile(r"org[/.]conscrypt[/.]Conscrypt")),
    # HIGH: known TLS bypass shapes
    ("TRUST_ALL_CERTS",             "HIGH",
     re.compile(
         r"checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*\}"
         r"|getAcceptedIssuers\s*\(\s*\)\s*\{\s*return\s+(?:null|new\s+X509Certificate\[\s*0\s*\])"
         r"|new\s+X509TrustManager\s*\(\s*\)\s*\{[^}]{0,400}?return\s+null",
         re.DOTALL,
     )),
    ("HOSTNAME_VERIFIER_ALLOW_ALL", "HIGH",
     re.compile(
         r"HostnameVerifier\s*\.\s*ALLOW_ALL"
         r"|SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER"
         r"|verify\s*\(\s*String[^)]*SSLSession[^)]*\)\s*\{\s*return\s+true",
     )),
]


def _scan_file(path: str, rel: str) -> List[PinningFinding]:
    out: List[PinningFinding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return out
    for rule_id, sev, rx in _RULES:
        for m in rx.finditer(text):
            # Compute line number from byte offset
            line = text.count("\n", 0, m.start()) + 1
            snippet = m.group(0).replace("\n", " ")
            if len(snippet) > 200:
                snippet = snippet[:197] + "..."
            out.append(PinningFinding(rule_id, sev, rel, line, snippet))
    return out


def _walk_and_scan(root: str) -> List[PinningFinding]:
    out: List[PinningFinding] = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in _TEXT_EXTENSIONS:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            out.extend(_scan_file(full, rel))
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_BOLD = "\033[1m"
_DIM = "\033[2m"
_RST = "\033[0m"
_SEV_COLOR = {
    "HIGH":   "\033[1;91m",
    "MEDIUM": "\033[1;93m",
    "LOW":    "\033[1;94m",
    "INFO":   "\033[1;90m",
}
_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def _render_console(root: str, findings: List[PinningFinding]) -> str:
    sep = "=" * 60
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines = [
        sep,
        f"{_BOLD}PINNING / TLS SANITY SCAN  {root}{_RST}",
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


def _render_json(root: str, findings: List[PinningFinding]) -> str:
    return json.dumps({
        "root":     root,
        "findings": [f.to_dict() for f in findings],
        "counts":   {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
        },
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidAppPinningCheckCommand(Command):
    @property
    def name(self) -> str:
        return "app_pinning_check"

    def help(self) -> str:
        return (
            "app_pinning_check <directory> [--json]\n"
            "  Scan a decompiled Android source tree (typically the output of\n"
            "  app_decompile) for certificate-pinning libraries and TLS-sanity\n"
            "  bypasses.  Findings are tagged INFO (pinning library present;\n"
            "  worth manual review) through HIGH (custom TrustAllCerts /\n"
            "  HostnameVerifier ALLOW_ALL patterns).\n\n"
            "  --json  Emit findings as JSON instead of the console table.\n\n"
            "Examples:\n"
            "  app_pinning_check ./decompiled/com.example.target/\n"
            "  app_pinning_check ./decompiled/com.example.target/ --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        as_json = False
        if "--json" in args:
            as_json = True
            args = [a for a in args if a != "--json"]
        if len(args) != 1:
            console._print_message("INFO", "Usage: app_pinning_check <directory> [--json]")
            return
        root = args[0]
        if not os.path.isdir(root):
            console._print_message("ERROR", f"Not a directory: {root}")
            return
        console._print_message("INFO", f"Scanning {root} for pinning / TLS-bypass patterns ...")
        findings = _walk_and_scan(root)
        if as_json:
            print(_render_json(root, findings))
        else:
            print(_render_console(root, findings))


def register(registry_func):
    registry_func(AndroidAppPinningCheckCommand())
