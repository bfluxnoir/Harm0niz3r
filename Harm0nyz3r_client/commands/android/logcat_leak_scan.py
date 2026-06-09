# -*- coding: utf-8 -*-
# commands/android/logcat_leak_scan.py
"""
logcat_leak_scan - capture filtered logcat for a few seconds while the
operator drives the app, then grep the buffer for leakage patterns
(PII, auth tokens, financial PANs, ...).

Workflow
--------
  1. Resolve the package's PID via 'pidof' (with a 'ps -A' fallback).
  2. Open 'adb -s <serial> shell logcat --pid=<pid> *:<level>' as a
     subprocess that writes to a local capture file.
  3. Wait '--seconds N' (default 30) -- the operator is expected to
     drive the app during this window (log in, open a sensitive
     screen, hit the network, ...).
  4. Terminate the subprocess, read the capture file back, and run
     a fixed regex set against it.  PAN candidates also get a Luhn
     validity check.
  5. Render a finding report.

V1 rules (mapped to MASVS-PRIVACY-2 / MSTG-PRIVACY-2)
  EMAIL_ADDRESS              INFO
  IPV4_ADDRESS               INFO (handy as a pivot, not always
                                  sensitive)
  PHONE_NUMBER               LOW
  IBAN                       HIGH (financial identifier)
  PAN_CARD                   HIGH (Luhn-validated 13-19 digit number)
  JWT                        MEDIUM
  BEARER_TOKEN               MEDIUM
  AUTH_KEY_ASSIGN            HIGH ('password='/'token='/'apiKey=' with a
                                   non-trivial value -- common bad-logging
                                   shape)
  AWS_ACCESS_KEY_ID          HIGH
  GOOGLE_API_KEY             HIGH
"""

import json
import os
import re
import subprocess
import time
from typing import List, Optional

from commands.base import Command, CommandSource


_VALID_LEVELS = ("V", "D", "I", "W", "E", "F", "S")


# Patterns that don't need post-processing live here.
_SIMPLE_RULES = [
    ("EMAIL_ADDRESS",     "INFO",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("IPV4_ADDRESS",      "INFO",
     re.compile(
         r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
         r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b"
     )),
    ("IBAN",              "HIGH",
     re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")),
    ("JWT",               "MEDIUM",
     re.compile(
         r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{8,})\b"
     )),
    ("BEARER_TOKEN",      "MEDIUM",
     re.compile(r"\b[Bb]earer\s+[A-Za-z0-9_\-.=]{20,}\b")),
    ("AWS_ACCESS_KEY_ID", "HIGH",
     re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("GOOGLE_API_KEY",    "HIGH",
     re.compile(r"\b(AIza[0-9A-Za-z_\-]{32,40})\b")),
    ("AUTH_KEY_ASSIGN",   "HIGH",
     re.compile(
         r"(?i)\b(?:api[_-]?key|password|passwd|token|secret|auth"
         r"|bearer|access[_-]?token|refresh[_-]?token)"
         r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{8,})[\"']?"
     )),
    ("PHONE_NUMBER",      "LOW",
     # Liberal E.164-ish; the patterns above will catch anything more
     # specific.  Requires at least 9 digits to avoid grabbing IDs.
     re.compile(r"\+\d[\d\s\-().]{8,18}\d")),
]


# PAN: 13-19 digits with optional dashes/spaces, then Luhn-checked.
_PAN_RE = re.compile(r"\b(?:\d[\s-]?){12,18}\d\b")


def _luhn_valid(card: str) -> bool:
    digits = [int(c) for c in card if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ---------------------------------------------------------------------------
# Finding shape
# ---------------------------------------------------------------------------

class LeakFinding:
    __slots__ = ("rule", "severity", "line", "match")

    def __init__(self, rule, severity, line, match):
        self.rule = rule
        self.severity = severity
        self.line = line
        self.match = match

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _scan_text(text: str) -> List[LeakFinding]:
    out: List[LeakFinding] = []
    for ln, line in enumerate(text.splitlines(), start=1):
        for rule_id, sev, rx in _SIMPLE_RULES:
            for m in rx.finditer(line):
                matched = m.group(0)
                if len(matched) > 200:
                    matched = matched[:197] + "..."
                out.append(LeakFinding(rule_id, sev, ln, matched))
        for m in _PAN_RE.finditer(line):
            digits_only = re.sub(r"[^0-9]", "", m.group(0))
            if _luhn_valid(digits_only):
                # Mask the middle for the report
                masked = (
                    digits_only[:4] + "*" * (len(digits_only) - 8) + digits_only[-4:]
                    if len(digits_only) >= 8 else digits_only
                )
                out.append(LeakFinding("PAN_CARD", "HIGH", ln, masked))
    return out


# ---------------------------------------------------------------------------
# Logcat capture
# ---------------------------------------------------------------------------

def _resolve_pid(console, package: str) -> Optional[str]:
    out, _, ret = console._run_shell(["pidof", package])
    if ret == 0 and out.strip():
        return out.strip().split()[0]
    # fall back to 'ps -A'
    ps_out, _, _ = console._run_shell(["ps", "-A"])
    for ln in ps_out.splitlines():
        parts = ln.split()
        if len(parts) >= 9 and parts[-1] == package:
            return parts[1]
    return None


def _capture(console, package: str, pid: str, seconds: int, level: str, out_path: str) -> bool:
    cmd = [
        "adb", "-s", console.device_id, "shell",
        "logcat", "-T", "1", f"--pid={pid}", f"*:{level}",
    ]
    try:
        f = open(out_path, "w", encoding="utf-8", errors="replace")
    except OSError as e:
        console._print_message("ERROR", f"Could not open capture file: {e}")
        return False
    try:
        try:
            proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            console._print_message("ERROR", "'adb' not found in PATH.")
            return False

        console._print_message(
            "INFO",
            f"Capturing for {seconds}s -- drive the app now (log in, open "
            "sensitive screens, hit the network, ...).  Ctrl-C stops early."
        )
        try:
            proc.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except KeyboardInterrupt:
            console._print_message("INFO", "Capture interrupted by Ctrl-C.")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        f.close()
    return True


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


def _render_console(package: str, capture_path: str, findings: List[LeakFinding]) -> str:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    sep = "=" * 60
    lines = [
        sep,
        f"{_BOLD}LOGCAT LEAK SCAN  {package}{_RST}",
        sep,
        f"  Capture file : {capture_path}",
        f"  Findings     : {len(findings)} total  "
        f"({counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, "
        f"{counts['LOW']} LOW, {counts['INFO']} INFO)",
        "-" * 60,
    ]
    if not findings:
        lines.append("  Nothing flagged by the V1 rule set.")
        lines.append(sep)
        return "\n".join(lines)
    for f in sorted(findings, key=lambda x: (_SEV_ORDER.get(x.severity, 9), x.line)):
        color = _SEV_COLOR.get(f.severity, "")
        lines.append(
            f"  [{color}{f.severity}{_RST}] {_BOLD}{f.rule}{_RST}  line {f.line}"
        )
        lines.append(f"        {_DIM}{f.match}{_RST}")
    lines.append("")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(package: str, capture_path: str, findings: List[LeakFinding]) -> str:
    return json.dumps({
        "package":  package,
        "capture":  capture_path,
        "findings": [f.to_dict() for f in findings],
        "counts":   {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
        },
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidLogcatLeakScanCommand(Command):
    @property
    def name(self) -> str:
        return "logcat_leak_scan"

    def help(self) -> str:
        return (
            "logcat_leak_scan <package> [--seconds N] [--level V|D|I|W|E|F|S]\n"
            "                  [--out FILE] [--json]\n"
            "  Capture 'adb logcat --pid=<pid>' for N seconds (default 30) into\n"
            "  a local file while the operator drives the app, then regex-scan\n"
            "  the capture for PII / auth-token / financial-identifier patterns.\n"
            "  --seconds N   Capture window length in seconds (default 30).\n"
            "  --level X     Minimum log priority (default V = verbose).\n"
            "  --out FILE    Capture file path (default: logs/leak-<pkg>-<ts>.log).\n"
            "  --json        Emit findings as JSON instead of the console table.\n\n"
            "Examples:\n"
            "  logcat_leak_scan com.example.target\n"
            "  logcat_leak_scan com.example.target --seconds 60 --level I\n"
            "  logcat_leak_scan com.example.target --out /tmp/cap.log --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "logcat_leak_scan is only available from the CLI.")
            return
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        # --- arg parsing ---
        seconds = 30
        level = "V"
        out_path: Optional[str] = None
        as_json = False
        positional: List[str] = []

        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--json":
                as_json = True; i += 1
            elif tok == "--seconds" and i + 1 < len(args):
                try:
                    seconds = max(1, int(args[i + 1]))
                except ValueError:
                    console._print_message("WARNING", f"Invalid --seconds {args[i+1]!r}; using 30.")
                i += 2
            elif tok == "--level" and i + 1 < len(args):
                lv = args[i + 1].upper()
                if lv in _VALID_LEVELS:
                    level = lv
                else:
                    console._print_message("WARNING", f"Invalid --level {lv!r}; using V.")
                i += 2
            elif tok == "--out" and i + 1 < len(args):
                out_path = args[i + 1]; i += 2
            else:
                positional.append(tok); i += 1

        if len(positional) != 1:
            console._print_message(
                "INFO",
                "Usage: logcat_leak_scan <package> [--seconds N] "
                "[--level V|D|I|W|E|F|S] [--out FILE] [--json]"
            )
            return
        package = positional[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        # --- PID ---
        pid = _resolve_pid(console, package)
        if not pid:
            console._print_message("ERROR", f"{package} is not running on the device.")
            return

        # --- capture file path ---
        if out_path is None:
            os.makedirs("logs", exist_ok=True)
            out_path = os.path.join(
                "logs",
                f"leak-{package}-{time.strftime('%Y%m%d_%H%M%S')}.log"
            )

        console._print_message(
            "INFO",
            f"Tailing {package} (PID {pid}, level {level}) for {seconds}s into {out_path}"
        )
        ok = _capture(console, package, pid, seconds, level, out_path)
        if not ok:
            return

        # --- scan ---
        try:
            with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                buf = f.read()
        except OSError as e:
            console._print_message("ERROR", f"Could not re-read capture file: {e}")
            return

        findings = _scan_text(buf)
        if as_json:
            print(_render_json(package, out_path, findings))
        else:
            print(_render_console(package, out_path, findings))


def register(registry_func):
    registry_func(AndroidLogcatLeakScanCommand())
