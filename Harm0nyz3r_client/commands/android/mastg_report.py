# -*- coding: utf-8 -*-
# commands/android/mastg_report.py
"""
mastg_report - run the static-analysis commands we already ship against a
target package and produce a single Markdown (or JSON) report whose
findings are organised by MASVS category and tagged with their MASTG
MSTG-* test IDs.

V1 composition
--------------
  app_scan                  manifest hardening, exported components,
                            dangerous permissions, target SDK,
                            deeplink-handler count
  app_provider_probe        read-only Content Provider probes
                            (READ_BASE / SQLI_QUOTE_BREAK / SQLI_UNION /
                            PATH_TRAVERSAL)
  app_deeplinks             handler enumeration with example URIs
  app_secrets               only if --secrets-dir is supplied (e.g. the
                            output of a prior 'app_decompile' run)

Findings from each command are normalised into a common ReportFinding
shape, mapped to (MASVS category, MASTG MSTG-* test ID) via the lookup
table near the top of this file, and grouped in the rendered report.
"""

import json
import os
import re
import time
from typing import List, Optional, Tuple

from commands.base import Command, CommandSource
from parsers.android_parser import parse_pm_dump, looks_thin

# Re-use the individual checkers so a fix in app_scan / app_provider_probe /
# app_deeplinks / app_secrets immediately benefits this report.
from commands.android.app_scan import (
    _run_scan as _run_app_scan,
    _score as _scan_score,
    _rate as _scan_rate,
    _counts as _scan_counts,
)
from commands.android.app_provider_probe import (
    _collect_providers,
    _run_probes,
)
from commands.android.app_deeplinks import _collect_handlers
from commands.android.app_secrets import _walk_and_scan as _secrets_walk


# ---------------------------------------------------------------------------
# Finding -> (MASVS category, MASTG MSTG-* test ID) lookup
# ---------------------------------------------------------------------------
#
# MASTG test IDs follow the MSTG-<CATEGORY>-<N> shape (e.g. MSTG-PLATFORM-3).
# We pick the closest single ID per finding; that does not preclude a finding
# from being relevant under multiple MASVS sub-controls, but a one-to-one map
# keeps the report navigable.

_MASVS_MAP: dict = {
    # app_scan -----------------------------------------------------------
    "DEBUGGABLE_FLAG":           ("MASVS-RESILIENCE", "MSTG-RESILIENCE-2"),
    "ALLOW_BACKUP_FLAG":         ("MASVS-STORAGE",    "MSTG-STORAGE-8"),
    "CLEARTEXT_TRAFFIC":         ("MASVS-NETWORK",    "MSTG-NETWORK-2"),
    "OUTDATED_TARGET_SDK":       ("MASVS-PLATFORM",   "MSTG-PLATFORM-1"),
    "EXPORTED_PROVIDER_NO_PERM": ("MASVS-PLATFORM",   "MSTG-PLATFORM-4"),
    "EXPORTED_ACTIVITY_NO_PERM": ("MASVS-PLATFORM",   "MSTG-PLATFORM-3"),
    "EXPORTED_SERVICE_NO_PERM":  ("MASVS-PLATFORM",   "MSTG-PLATFORM-4"),
    "EXPORTED_RECEIVER_NO_PERM": ("MASVS-PLATFORM",   "MSTG-PLATFORM-4"),
    "DANGEROUS_PERMS_REQUESTED": ("MASVS-PRIVACY",    "MSTG-PLATFORM-1"),
    "DANGEROUS_PERMS_GRANTED":   ("MASVS-PRIVACY",    "MSTG-PLATFORM-1"),
    "DEEPLINK_HANDLERS":         ("MASVS-PLATFORM",   "MSTG-PLATFORM-3"),
    # app_provider_probe -------------------------------------------------
    "READ_BASE":                 ("MASVS-PLATFORM",   "MSTG-PLATFORM-4"),
    "SQLI_QUOTE_BREAK":          ("MASVS-PLATFORM",   "MSTG-PLATFORM-4"),
    "SQLI_UNION":                ("MASVS-PLATFORM",   "MSTG-PLATFORM-4"),
    "PATH_TRAVERSAL":            ("MASVS-PLATFORM",   "MSTG-PLATFORM-4"),
    # app_secrets --------------------------------------------------------
    "AWS_ACCESS_KEY_ID":         ("MASVS-STORAGE",    "MSTG-STORAGE-1"),
    "GOOGLE_API_KEY":            ("MASVS-STORAGE",    "MSTG-STORAGE-1"),
    "STRIPE_LIVE_KEY":           ("MASVS-STORAGE",    "MSTG-STORAGE-1"),
    "STRIPE_PUBLIC_KEY":         ("MASVS-STORAGE",    "MSTG-STORAGE-1"),
    "SLACK_TOKEN":               ("MASVS-STORAGE",    "MSTG-STORAGE-1"),
    "GITHUB_PAT":                ("MASVS-STORAGE",    "MSTG-STORAGE-1"),
    "JWT":                       ("MASVS-STORAGE",    "MSTG-STORAGE-1"),
    "PRIVATE_KEY_BLOCK":         ("MASVS-CRYPTO",     "MSTG-CRYPTO-1"),
    "FIREBASE_DB_URL":           ("MASVS-NETWORK",    "MSTG-NETWORK-1"),
    "INTERNAL_URL_HTTP":         ("MASVS-NETWORK",    "MSTG-NETWORK-1"),
    "EMAIL":                     ("MASVS-PRIVACY",    "MSTG-PRIVACY-1"),
    "GENERIC_SECRET_ASSIGN":     ("MASVS-STORAGE",    "MSTG-STORAGE-1"),
}

_DEFAULT_CATEGORY: Tuple[str, str] = ("MASVS-CODE", "n/a")

_CATEGORY_ORDER = [
    "MASVS-STORAGE",
    "MASVS-CRYPTO",
    "MASVS-AUTH",
    "MASVS-NETWORK",
    "MASVS-PLATFORM",
    "MASVS-CODE",
    "MASVS-RESILIENCE",
    "MASVS-PRIVACY",
]
_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


# ---------------------------------------------------------------------------
# Normalised finding shape
# ---------------------------------------------------------------------------

class ReportFinding:
    __slots__ = (
        "source", "id", "severity", "title", "detail",
        "evidence", "recommendation", "category", "mastg",
    )

    def __init__(
        self,
        source: str,
        id: str,
        severity: str,
        title: str,
        detail: str,
        evidence: Optional[str] = None,
        recommendation: Optional[str] = None,
    ) -> None:
        self.source = source
        self.id = id
        self.severity = severity
        self.title = title
        self.detail = detail
        self.evidence = evidence
        self.recommendation = recommendation
        cat, mastg = _MASVS_MAP.get(id, _DEFAULT_CATEGORY)
        self.category = cat
        self.mastg = mastg

    def to_dict(self) -> dict:
        return {
            "source":         self.source,
            "id":             self.id,
            "severity":       self.severity,
            "title":          self.title,
            "detail":         self.detail,
            "evidence":       self.evidence,
            "recommendation": self.recommendation,
            "category":       self.category,
            "mastg":          self.mastg,
        }


# ---------------------------------------------------------------------------
# Collection helpers
# ---------------------------------------------------------------------------

def _from_app_scan(parsed: dict, raw: str) -> List[ReportFinding]:
    out: List[ReportFinding] = []
    for f in _run_app_scan(parsed, raw):
        out.append(ReportFinding(
            "app_scan", f.id, f.severity, f.title, f.detail,
            evidence=f.evidence, recommendation=f.recommendation,
        ))
    return out


def _from_provider_probe(console, providers: list) -> List[ReportFinding]:
    out: List[ReportFinding] = []
    for f in _run_probes(console, providers):
        out.append(ReportFinding(
            "app_provider_probe", f.probe, f.severity,
            f"{f.title}  [{f.authority}]", f.detail,
            evidence=f.evidence,
        ))
    return out


def _from_secrets(secrets_dir: str) -> List[ReportFinding]:
    out: List[ReportFinding] = []
    for f in _secrets_walk(secrets_dir):
        out.append(ReportFinding(
            "app_secrets", f.rule, f.severity,
            f"{f.rule} @ {f.file}:{f.line}",
            "Static-analysis pattern match in the decompiled source tree.",
            evidence=f.match,
        ))
    return out


def _deeplink_summary(handlers: list) -> List[ReportFinding]:
    # A single informational entry pointing the reader at the handler list.
    if not handlers:
        return []
    browsable = sum(1 for h in handlers if h.get("browsable"))
    examples = []
    for h in handlers[:5]:
        examples.extend(h.get("examples") or [])
    return [ReportFinding(
        "app_deeplinks", "DEEPLINK_HANDLERS", "INFO",
        f"{len(handlers)} deeplink handler(s) ({browsable} BROWSABLE)",
        "Components that declare an android.intent.action.VIEW intent filter. "
        "Use 'app_deeplinks' / 'app_deeplink' to enumerate and trigger them.",
        evidence="; ".join(examples[:5]) or None,
    )]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _markdown(package: str, parsed: dict, findings: List[ReportFinding]) -> str:
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    # Group by MASVS category
    by_cat: dict = {c: [] for c in _CATEGORY_ORDER}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    lines: List[str] = []
    lines.append(f"# MASTG-aligned Static Report — `{package}`")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Package | `{package}` |")
    lines.append(f"| versionName / versionCode | `{parsed.get('versionName')}` / `{parsed.get('versionCode')}` |")
    lines.append(f"| targetSdk / minSdk | `{parsed.get('targetSdk')}` / `{parsed.get('minSdk')}` |")
    lines.append(f"| Debuggable / System | `{parsed.get('debugMode')}` / `{parsed.get('systemApp')}` |")
    lines.append(f"| Scanned | `{time.strftime('%Y-%m-%d %H:%M:%S')}` |")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {sev} | {sev_counts.get(sev, 0)} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")
    lines.append("Coverage by MASVS category (V1 still has gaps — see the C bucket roadmap):")
    lines.append("")
    lines.append("| MASVS Category | Findings |")
    lines.append("|---|---|")
    for cat in _CATEGORY_ORDER:
        lines.append(f"| {cat} | {len(by_cat.get(cat, []))} |")
    if any(c not in _CATEGORY_ORDER for c in by_cat):
        for extra in by_cat:
            if extra not in _CATEGORY_ORDER:
                lines.append(f"| {extra} | {len(by_cat[extra])} |")
    lines.append("")

    # Per-category sections
    for cat in _CATEGORY_ORDER:
        bucket = sorted(by_cat.get(cat, []), key=lambda x: _SEV_ORDER.get(x.severity, 9))
        if not bucket:
            continue
        lines.append(f"## {cat}")
        lines.append("")
        for f in bucket:
            lines.append(f"### `[{f.severity}]` {f.id} — {f.title}")
            lines.append("")
            lines.append(f"- **MASTG test ID:** `{f.mastg}`")
            lines.append(f"- **Source command:** `{f.source}`")
            if f.evidence:
                ev = f.evidence
                if len(ev) > 600:
                    ev = ev[:597] + "..."
                lines.append(f"- **Evidence:**")
                lines.append("")
                lines.append("  ```")
                for el in ev.splitlines() or [ev]:
                    lines.append(f"  {el}")
                lines.append("  ```")
            lines.append("")
            lines.append(f.detail)
            lines.append("")
            if f.recommendation:
                lines.append(f"**Recommendation:** {f.recommendation}")
                lines.append("")
        lines.append("")

    if not findings:
        lines.append("## No findings")
        lines.append("")
        lines.append("Static V1 checks produced zero findings.  This does NOT mean the app is clean -- "
                     "it means the static rules we currently apply did not trigger.  Add network/TLS, "
                     "crypto, WebView and native-lib checks (C5..C19) for full MASTG coverage.")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("Generated by `mastg_report` (Harm0niz3r).")
    lines.append("")
    return "\n".join(lines)


def _json_payload(package: str, parsed: dict, findings: List[ReportFinding]) -> str:
    by_cat: dict = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f.to_dict())
    return json.dumps({
        "package":   package,
        "scanned":   time.strftime("%Y-%m-%d %H:%M:%S"),
        "version":   {"name": parsed.get("versionName"), "code": parsed.get("versionCode")},
        "targetSdk": parsed.get("targetSdk"),
        "minSdk":    parsed.get("minSdk"),
        "debug":     parsed.get("debugMode"),
        "system":    parsed.get("systemApp"),
        "counts":    {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
        },
        "by_category": by_cat,
        "findings":    [f.to_dict() for f in findings],
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidMastgReportCommand(Command):
    @property
    def name(self) -> str:
        return "mastg_report"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "mastg_report <package> [--out FILE] [--json] [--secrets-dir DIR]\n"
            "  Run app_scan + app_provider_probe + app_deeplinks against\n"
            "  <package>, organise findings by MASVS category and tag each\n"
            "  with the corresponding MASTG MSTG-* test ID.  Emits Markdown\n"
            "  to stdout by default.\n"
            "  --out FILE        Write the report to FILE instead of stdout.\n"
            "  --json            Emit a JSON payload instead of Markdown.\n"
            "  --secrets-dir DIR Also include findings from a previously\n"
            "                    decompiled tree (typically the output of\n"
            "                    'app_decompile').\n\n"
            "Examples:\n"
            "  mastg_report com.example.target\n"
            "  mastg_report com.example.target --out report.md\n"
            "  mastg_report com.example.target --secrets-dir ./decompiled/com.example.target/"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        out_file: Optional[str] = None
        as_json = False
        secrets_dir: Optional[str] = None
        positional: List[str] = []

        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--json":
                as_json = True
                i += 1
            elif tok == "--out" and i + 1 < len(args):
                out_file = args[i + 1]; i += 2
            elif tok == "--secrets-dir" and i + 1 < len(args):
                secrets_dir = args[i + 1]; i += 2
            else:
                positional.append(tok); i += 1

        if len(positional) != 1:
            console._print_message("INFO", "Usage: mastg_report <package> [--out FILE] [--json] [--secrets-dir DIR]")
            return
        package = positional[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        console._print_message("INFO", f"mastg_report: dumping {package} ...")
        stdout, stderr, retcode = console._run_shell(["pm", "dump", package])
        if retcode != 0 or not stdout:
            console._print_message("ERROR", f"pm dump failed: {stderr or 'no output'}")
            return
        parsed = parse_pm_dump(stdout, package)
        if looks_thin(parsed):
            console._print_message(
                "WARNING",
                "pm dump produced thin output -- the report may be incomplete; "
                "try 'agent_exec app_info <pkg>' for an apples-to-apples comparison."
            )

        console._print_message("INFO", "Running app_scan checks ...")
        findings: List[ReportFinding] = []
        findings.extend(_from_app_scan(parsed, stdout))

        providers = _collect_providers(parsed)
        if providers:
            console._print_message(
                "INFO",
                f"Running app_provider_probe across {len(providers)} provider(s) -- this can take a moment ..."
            )
            findings.extend(_from_provider_probe(console, providers))

        handlers = _collect_handlers(parsed)
        findings.extend(_deeplink_summary(handlers))

        if secrets_dir:
            if os.path.isdir(secrets_dir):
                console._print_message("INFO", f"Scanning secrets-dir {secrets_dir} ...")
                findings.extend(_from_secrets(secrets_dir))
            else:
                console._print_message(
                    "WARNING",
                    f"--secrets-dir {secrets_dir} is not a directory; skipping that section."
                )

        # Emit
        if as_json:
            body = _json_payload(package, parsed, findings)
        else:
            body = _markdown(package, parsed, findings)
        if out_file:
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(body)
                console._print_message(
                    "SUCCESS",
                    f"mastg_report: wrote {len(findings)} finding(s) to {out_file}"
                )
            except Exception as e:
                console._print_message("ERROR", f"Could not write {out_file}: {e}")
        else:
            print(body)
            console._print_message(
                "SUCCESS",
                f"mastg_report: emitted {len(findings)} finding(s)."
            )


def register(registry_func):
    registry_func(AndroidMastgReportCommand())
