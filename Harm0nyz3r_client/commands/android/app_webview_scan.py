# -*- coding: utf-8 -*-
# commands/android/app_webview_scan.py
"""
app_webview_scan - regex scan over a decompiled Android source tree for
WebView misconfigurations.  Companion to app_decompile / app_secrets /
app_pinning_check; all of them slot into mastg_report under MASVS-PLATFORM.

Rules
-----
  WEBVIEW_JS_ENABLED                MEDIUM   setJavaScriptEnabled(true)
  WEBVIEW_FILE_ACCESS               HIGH     setAllowFileAccess(true)
  WEBVIEW_FILE_FROM_FILE_URLS       HIGH     setAllowFileAccessFromFileURLs(true)
  WEBVIEW_UNIVERSAL_ACCESS          HIGH     setAllowUniversalAccessFromFileURLs(true)
  WEBVIEW_JS_INTERFACE              HIGH     addJavascriptInterface(...)
  WEBVIEW_MIXED_CONTENT_ALLOW       MEDIUM   setMixedContentMode(...ALWAYS_ALLOW)
  WEBVIEW_SAVE_PASSWORD             LOW      setSavePassword(true)
  WEBVIEW_DEBUGGING                 MEDIUM   setWebContentsDebuggingEnabled(true)
  WEBVIEW_DOM_STORAGE               INFO     setDomStorageEnabled(true)
                                             (informational; very common)
  WEBVIEW_SHOULD_OVERRIDE_TRUE      MEDIUM   shouldOverrideUrlLoading returns
                                             true unconditionally (URL
                                             validation bypassed)
"""

import json
import os
import re
from typing import List

from commands.base import Command, CommandSource


class WebViewFinding:
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

_RULES = [
    ("WEBVIEW_JS_ENABLED",            "MEDIUM",
     re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)")),
    ("WEBVIEW_FILE_ACCESS",           "HIGH",
     re.compile(r"setAllowFileAccess\s*\(\s*true\s*\)")),
    ("WEBVIEW_FILE_FROM_FILE_URLS",   "HIGH",
     re.compile(r"setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)")),
    ("WEBVIEW_UNIVERSAL_ACCESS",      "HIGH",
     re.compile(r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)")),
    ("WEBVIEW_JS_INTERFACE",          "HIGH",
     re.compile(r"\.addJavascriptInterface\s*\(")),
    ("WEBVIEW_MIXED_CONTENT_ALLOW",   "MEDIUM",
     re.compile(r"setMixedContentMode\s*\(\s*(?:WebSettings\.)?MIXED_CONTENT_ALWAYS_ALLOW")),
    ("WEBVIEW_SAVE_PASSWORD",         "LOW",
     re.compile(r"setSavePassword\s*\(\s*true\s*\)")),
    ("WEBVIEW_DEBUGGING",             "MEDIUM",
     re.compile(r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)")),
    ("WEBVIEW_DOM_STORAGE",           "INFO",
     re.compile(r"setDomStorageEnabled\s*\(\s*true\s*\)")),
    # shouldOverrideUrlLoading that unconditionally returns true (the
    # textbook "open every URL inside the WebView even when the host says
    # otherwise" pattern).
    ("WEBVIEW_SHOULD_OVERRIDE_TRUE",  "MEDIUM",
     re.compile(
         r"shouldOverrideUrlLoading\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*return\s+true\s*;\s*\}",
         re.DOTALL,
     )),
]


def _scan_file(path: str, rel: str) -> List[WebViewFinding]:
    out: List[WebViewFinding] = []
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
            out.append(WebViewFinding(rule_id, sev, rel, line, snippet))
    return out


def _walk_and_scan(root: str) -> List[WebViewFinding]:
    out: List[WebViewFinding] = []
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


def _render_console(root: str, findings: List[WebViewFinding]) -> str:
    sep = "=" * 60
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines = [
        sep,
        f"{_BOLD}WEBVIEW MISCONFIG SCAN  {root}{_RST}",
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


def _render_json(root: str, findings: List[WebViewFinding]) -> str:
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

class AndroidAppWebViewScanCommand(Command):
    @property
    def name(self) -> str:
        return "app_webview_scan"

    def help(self) -> str:
        return (
            "app_webview_scan <directory> [--json]\n"
            "  Scan a decompiled Android source tree for WebView misconfig\n"
            "  (JS enabled, file access, JS interface, mixed-content, save\n"
            "  password, debugging, lax shouldOverrideUrlLoading).\n"
            "  --json  Emit findings as JSON instead of the console table.\n\n"
            "Examples:\n"
            "  app_webview_scan ./decompiled/com.example.target/\n"
            "  app_webview_scan ./decompiled/com.example.target/ --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        as_json = False
        if "--json" in args:
            as_json = True
            args = [a for a in args if a != "--json"]
        if len(args) != 1:
            console._print_message("INFO", "Usage: app_webview_scan <directory> [--json]")
            return
        root = args[0]
        if not os.path.isdir(root):
            console._print_message("ERROR", f"Not a directory: {root}")
            return
        console._print_message("INFO", f"Scanning {root} for WebView misconfig ...")
        findings = _walk_and_scan(root)
        if as_json:
            print(_render_json(root, findings))
        else:
            print(_render_console(root, findings))


def register(registry_func):
    registry_func(AndroidAppWebViewScanCommand())
