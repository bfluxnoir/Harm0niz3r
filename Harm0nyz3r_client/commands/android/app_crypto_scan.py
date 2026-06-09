# -*- coding: utf-8 -*-
# commands/android/app_crypto_scan.py
"""
app_crypto_scan - regex scan over a decompiled Android source tree for
weak-crypto patterns commonly flagged by OWASP MASTG MSTG-CRYPTO-*.

Rules
-----
  CRYPTO_DES_CIPHER             HIGH    Cipher.getInstance("DES/...")
  CRYPTO_RC4_CIPHER             HIGH    Cipher.getInstance("RC4/...")
  CRYPTO_3DES_CIPHER            MEDIUM  Cipher.getInstance("DESede/...")
  CRYPTO_BLOWFISH_CIPHER        MEDIUM  Cipher.getInstance("Blowfish/...")
  CRYPTO_AES_ECB_MODE           HIGH    Cipher.getInstance("AES/ECB/...")
  CRYPTO_AES_DEFAULT_MODE       MEDIUM  Cipher.getInstance("AES") -> ECB on
                                        most JDK/OpenSSL combos
  CRYPTO_MD5_HASH               MEDIUM  MessageDigest.getInstance("MD5") /
                                        DigestUtils.md5(...) / explicit "md5"
  CRYPTO_SHA1_HASH              MEDIUM  MessageDigest.getInstance("SHA-1") /
                                        SHA1 / "sha1"
  CRYPTO_INSECURE_RANDOM        MEDIUM  new java.util.Random() (use
                                        SecureRandom for tokens / keys)
  CRYPTO_ZERO_IV                HIGH    new IvParameterSpec(new byte[N])
                                        (all-zero IV)
  CRYPTO_HARDCODED_KEY          HIGH    new SecretKeySpec("<literal>")
  CRYPTO_WEAK_KEYGEN            HIGH    KeyGenerator.getInstance for a weak
                                        algorithm (DES / RC4)
  CRYPTO_LEGACY_BC_PROVIDER     LOW     SecurityProvider "BC" registered
                                        (Bouncy Castle legacy provider)
"""

import json
import os
import re
from typing import List

from commands.base import Command, CommandSource


class CryptoFinding:
    __slots__ = ("rule", "severity", "file", "line", "match")

    def __init__(self, rule, severity, file, line, match):
        self.rule = rule
        self.severity = severity
        self.file = file
        self.line = line
        self.match = match

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


_TEXT_EXTENSIONS = {".java", ".kt", ".smali"}

_RULES = [
    ("CRYPTO_DES_CIPHER",         "HIGH",
     re.compile(r'Cipher\.getInstance\s*\(\s*"DES(?:/[^"]+)?"')),
    ("CRYPTO_RC4_CIPHER",         "HIGH",
     re.compile(r'Cipher\.getInstance\s*\(\s*"RC4(?:/[^"]+)?"')),
    ("CRYPTO_3DES_CIPHER",        "MEDIUM",
     re.compile(r'Cipher\.getInstance\s*\(\s*"DESede(?:/[^"]+)?"')),
    ("CRYPTO_BLOWFISH_CIPHER",    "MEDIUM",
     re.compile(r'Cipher\.getInstance\s*\(\s*"Blowfish(?:/[^"]+)?"')),
    ("CRYPTO_AES_ECB_MODE",       "HIGH",
     re.compile(r'Cipher\.getInstance\s*\(\s*"AES/ECB')),
    ("CRYPTO_AES_DEFAULT_MODE",   "MEDIUM",
     re.compile(r'Cipher\.getInstance\s*\(\s*"AES"\s*[,)]')),
    ("CRYPTO_MD5_HASH",           "MEDIUM",
     re.compile(r'MessageDigest\.getInstance\s*\(\s*"MD5"|DigestUtils\.md5|"md5"', re.IGNORECASE)),
    ("CRYPTO_SHA1_HASH",          "MEDIUM",
     re.compile(r'MessageDigest\.getInstance\s*\(\s*"SHA-?1"|DigestUtils\.sha1|"sha-?1"', re.IGNORECASE)),
    ("CRYPTO_INSECURE_RANDOM",    "MEDIUM",
     re.compile(r"\bnew\s+(?:java\.util\.)?Random\s*\(")),
    ("CRYPTO_ZERO_IV",            "HIGH",
     re.compile(r"new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\d+\s*\]\s*\)")),
    ("CRYPTO_HARDCODED_KEY",      "HIGH",
     re.compile(
         r'new\s+SecretKeySpec\s*\(\s*"[A-Za-z0-9+/=]{8,}"\.getBytes'
         r'|new\s+SecretKeySpec\s*\(\s*new\s+byte\s*\[\]\s*\{'
     )),
    ("CRYPTO_WEAK_KEYGEN",        "HIGH",
     re.compile(r'KeyGenerator\.getInstance\s*\(\s*"(?:DES|RC4)(?:/[^"]+)?"')),
    ("CRYPTO_LEGACY_BC_PROVIDER", "LOW",
     re.compile(r'Security\.addProvider\s*\(\s*new\s+BouncyCastleProvider|getInstance\([^)]*,\s*"BC"\s*\)')),
]


def _scan_file(path: str, rel: str) -> List[CryptoFinding]:
    out: List[CryptoFinding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return out
    for rule_id, sev, rx in _RULES:
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = m.group(0).replace("\n", " ")
            if len(snippet) > 200:
                snippet = snippet[:197] + "..."
            out.append(CryptoFinding(rule_id, sev, rel, line, snippet))
    return out


def _walk_and_scan(root: str) -> List[CryptoFinding]:
    out: List[CryptoFinding] = []
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


def _render_console(root: str, findings: List[CryptoFinding]) -> str:
    sep = "=" * 60
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines = [
        sep,
        f"{_BOLD}WEAK CRYPTO SCAN  {root}{_RST}",
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


def _render_json(root: str, findings: List[CryptoFinding]) -> str:
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

class AndroidAppCryptoScanCommand(Command):
    @property
    def name(self) -> str:
        return "app_crypto_scan"

    def help(self) -> str:
        return (
            "app_crypto_scan <directory> [--json]\n"
            "  Scan a decompiled Android source tree for weak crypto: DES /\n"
            "  RC4 / 3DES / Blowfish ciphers, AES ECB usage, MD5 / SHA-1\n"
            "  hashes, java.util.Random, zero IVs, hardcoded SecretKeySpec\n"
            "  values, weak KeyGenerator algorithms, legacy Bouncy Castle\n"
            "  provider registration.\n"
            "  --json  Emit findings as JSON instead of the console table.\n\n"
            "Examples:\n"
            "  app_crypto_scan ./decompiled/com.example.target/\n"
            "  app_crypto_scan ./decompiled/com.example.target/ --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        as_json = False
        if "--json" in args:
            as_json = True
            args = [a for a in args if a != "--json"]
        if len(args) != 1:
            console._print_message("INFO", "Usage: app_crypto_scan <directory> [--json]")
            return
        root = args[0]
        if not os.path.isdir(root):
            console._print_message("ERROR", f"Not a directory: {root}")
            return
        console._print_message("INFO", f"Scanning {root} for weak-crypto patterns ...")
        findings = _walk_and_scan(root)
        if as_json:
            print(_render_json(root, findings))
        else:
            print(_render_console(root, findings))


def register(registry_func):
    registry_func(AndroidAppCryptoScanCommand())
