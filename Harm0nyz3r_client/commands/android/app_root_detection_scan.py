# -*- coding: utf-8 -*-
# commands/android/app_root_detection_scan.py
"""
app_root_detection_scan - enumerate the root-detection signals an app
actually checks at runtime.  Static, regex-only scan over a decompiled
source tree (typical input is the output of app_decompile).

Why this exists
---------------
When pentesting against an app that refuses to launch on a rooted /
Magisk-equipped device, the question is rarely 'is it doing root
detection?' but 'WHICH root detection libraries / heuristics does it
ship?'  Once you know that, the root_bypass Frida preset (C19) tells
you which methods to hook.

V1 rule set (all INFO -- this is enumeration, not vulnerability scoring)
  ROOT_LIB_ROOTBEER         RootBeer (com.scottyab.rootbeer)
  ROOT_LIB_ROOTTOOLS        RootTools (com.stericson.RootTools)
  ROOT_LIB_SAFETYNET        SafetyNetAttestation / Play Integrity
                            attestation reference
  ROOT_LIB_MAGISK_DETECTOR  3rd-party Magisk detection helpers
  ROOT_SU_BINARY_PATH       String literal pointing at a canonical su
                            binary (/system/bin/su, /sbin/su,
                            /vendor/bin/su, /system/xbin/su, ...)
  ROOT_MAGISK_FILE_REF      String literal pointing at /sbin/magisk,
                            /data/adb/magisk*, MagiskHide*
  ROOT_BUILD_TAGS_TESTKEYS  Build.TAGS / 'test-keys' check
  ROOT_BUILD_FINGERPRINT    Build.FINGERPRINT containing 'generic' /
                            'userdebug' (emulator / userdebug build)
  ROOT_SYSPROP_DEBUGGABLE   getprop / SystemProperties.get for
                            'ro.debuggable'
  ROOT_SYSPROP_SECURE       getprop / SystemProperties.get for
                            'ro.secure'
  ROOT_RUNTIME_EXEC_SU      Runtime.exec("su") or
                            Runtime.exec("which su")
  ROOT_MAGISK_PKG_CHECK     PackageManager check for
                            com.topjohnwu.magisk or eu.chainfire.supersu

Each finding maps to MASVS-RESILIENCE / MSTG-RESILIENCE-1 in
mastg_report.
"""

import json
import os
import re
from typing import List

from commands.base import Command, CommandSource


class RootFinding:
    __slots__ = ("rule", "severity", "file", "line", "match")

    def __init__(self, rule, severity, file, line, match):
        self.rule = rule
        self.severity = severity
        self.file = file
        self.line = line
        self.match = match

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


_TEXT_EXTENSIONS = {".java", ".kt", ".smali", ".xml"}


# Each rule is (id, severity, regex).  Severity stays at INFO across the
# board so the report reads as "here are the signals" rather than implying
# any of these patterns is itself broken.
_RULES = [
    ("ROOT_LIB_ROOTBEER",       "INFO",
     re.compile(r"com[/.]scottyab[/.]rootbeer")),
    ("ROOT_LIB_ROOTTOOLS",      "INFO",
     re.compile(r"com[/.]stericson[/.]RootTools|RootTools\.isAccessGiven")),
    ("ROOT_LIB_SAFETYNET",      "INFO",
     re.compile(
         r"SafetyNetClient|SafetyNetApi\.attest|PlayIntegrity|"
         r"com[/.]google[/.]android[/.]gms[/.]safetynet"
     )),
    ("ROOT_LIB_MAGISK_DETECTOR", "INFO",
     re.compile(r"MagiskDetector|isMagiskInstalled|hasMagiskHide")),
    ("ROOT_SU_BINARY_PATH",     "INFO",
     re.compile(
         r"\"(?:/sbin/su|/system/bin/su|/system/xbin/su|/system/sd/xbin/su"
         r"|/data/local/xbin/su|/data/local/bin/su|/data/local/su"
         r"|/su/bin/su|/vendor/bin/su)\""
     )),
    ("ROOT_MAGISK_FILE_REF",    "INFO",
     re.compile(
         r"\"(?:/sbin/magisk|/sbin/.magisk|/data/adb/magisk|/data/adb/modules"
         r"|/cache/magisk\.log|MagiskHide|MagiskManager)\""
     )),
    ("ROOT_BUILD_TAGS_TESTKEYS", "INFO",
     re.compile(r'Build\.TAGS|"test-keys"')),
    ("ROOT_BUILD_FINGERPRINT",   "INFO",
     re.compile(
         r'Build\.FINGERPRINT|"generic"\s*\.equals|"userdebug"\s*\.equals'
     )),
    ("ROOT_SYSPROP_DEBUGGABLE", "INFO",
     re.compile(r'"ro\.debuggable"')),
    ("ROOT_SYSPROP_SECURE",     "INFO",
     re.compile(r'"ro\.secure"')),
    ("ROOT_RUNTIME_EXEC_SU",    "INFO",
     re.compile(
         r'Runtime[^\n]{0,40}\.exec\s*\(\s*"(?:which\s+su|su\s+-c|su|busybox)"'
         r"|getRuntime\(\)\.exec\s*\(\s*new\s+String\[\]\s*\{\s*\"(?:which|su)\""
     )),
    ("ROOT_MAGISK_PKG_CHECK",   "INFO",
     re.compile(
         r'"com\.topjohnwu\.magisk"|"eu\.chainfire\.supersu"|"de\.robv\.android\.xposed"'
     )),
]


def _scan_file(path: str, rel: str) -> List[RootFinding]:
    out: List[RootFinding] = []
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
            out.append(RootFinding(rule_id, sev, rel, line, snippet))
    return out


def _walk_and_scan(root: str) -> List[RootFinding]:
    out: List[RootFinding] = []
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

_BOLD = "\033[1m"; _DIM = "\033[2m"; _RST = "\033[0m"
_INFO = "\033[1;90m"


def _render_console(root: str, findings: List[RootFinding]) -> str:
    sep = "=" * 60
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f.rule, []).append(f)
    lines = [
        sep,
        f"{_BOLD}ROOT DETECTION SCAN  {root}{_RST}",
        sep,
        f"  Signals matched : {len(by_rule)} distinct rules, "
        f"{len(findings)} total hits",
        "-" * 60,
    ]
    if not findings:
        lines.append("  No root-detection patterns matched.")
        lines.append("  Either the app doesn't ship root detection, or the V1")
        lines.append("  rule set didn't catch its variant -- check manually.")
        lines.append(sep)
        return "\n".join(lines)
    for rule_id in sorted(by_rule.keys()):
        bucket = by_rule[rule_id]
        lines.append("")
        lines.append(f"  [{_INFO}INFO{_RST}] {_BOLD}{rule_id}{_RST}  ({len(bucket)} hit(s))")
        # Show up to 4 example hits with file:line + matched snippet
        for f in bucket[:4]:
            lines.append(f"    {f.file}:{f.line}  {_DIM}{f.match}{_RST}")
        if len(bucket) > 4:
            lines.append(f"    {_DIM}... and {len(bucket) - 4} more{_RST}")
    lines.append("")
    lines.append("  Next steps:")
    lines.append("    frida_run <pkg> --preset root_bypass --spawn")
    lines.append("  See commands/android/frida_presets/root_bypass.js for the")
    lines.append("  hook surface; combine with Magisk DenyList for kernel-level")
    lines.append("  checks Frida can't reach from userspace.")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(root: str, findings: List[RootFinding]) -> str:
    return json.dumps({
        "root":     root,
        "findings": [f.to_dict() for f in findings],
        "counts":   {
            "total":  len(findings),
            "rules":  len({f.rule for f in findings}),
        },
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidAppRootDetectionScanCommand(Command):
    @property
    def name(self) -> str:
        return "app_root_detection_scan"

    def help(self) -> str:
        return (
            "app_root_detection_scan <directory> [--json]\n"
            "  Walk a decompiled Android source tree (output of app_decompile)\n"
            "  for the most common root / Magisk / SafetyNet detection signals.\n"
            "  Output is enumerative (every finding is INFO) -- the point is\n"
            "  to see which heuristics the app ships so the root_bypass Frida\n"
            "  preset can be tuned.\n"
            "  --json  Emit findings as JSON instead of the console table.\n\n"
            "Examples:\n"
            "  app_root_detection_scan ./decompiled/com.example.target/\n"
            "  app_root_detection_scan ./decompiled/com.example.target/ --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        as_json = False
        if "--json" in args:
            as_json = True
            args = [a for a in args if a != "--json"]
        if len(args) != 1:
            console._print_message(
                "INFO",
                "Usage: app_root_detection_scan <directory> [--json]"
            )
            return
        root = args[0]
        if not os.path.isdir(root):
            console._print_message("ERROR", f"Not a directory: {root}")
            return
        console._print_message(
            "INFO", f"Scanning {root} for root-detection patterns ..."
        )
        findings = _walk_and_scan(root)
        if as_json:
            print(_render_json(root, findings))
        else:
            print(_render_console(root, findings))


def register(registry_func):
    registry_func(AndroidAppRootDetectionScanCommand())
