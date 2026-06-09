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
    # app_nsc_check (C5) -------------------------------------------------
    "NSC_MISSING":               ("MASVS-NETWORK",    "MSTG-NETWORK-2"),
    "NSC_CLEARTEXT_BASE":        ("MASVS-NETWORK",    "MSTG-NETWORK-2"),
    "NSC_CLEARTEXT_DOMAIN":      ("MASVS-NETWORK",    "MSTG-NETWORK-2"),
    "NSC_USER_TRUST_ANCHORS":    ("MASVS-NETWORK",    "MSTG-NETWORK-3"),
    "NSC_DEBUG_OVERRIDES":       ("MASVS-NETWORK",    "MSTG-NETWORK-2"),
    "NSC_PIN_SET_PRESENT":       ("MASVS-NETWORK",    "MSTG-NETWORK-4"),
    "NSC_NO_PIN_SET":            ("MASVS-NETWORK",    "MSTG-NETWORK-4"),
    "MANIFEST_CLEARTEXT_TRUE":   ("MASVS-NETWORK",    "MSTG-NETWORK-2"),
    # app_pinning_check (C6) ---------------------------------------------
    "PINNING_OKHTTP_LIB":        ("MASVS-NETWORK",    "MSTG-NETWORK-4"),
    "PINNING_OKHTTP_SETTER":     ("MASVS-NETWORK",    "MSTG-NETWORK-4"),
    "PINNING_OKHTTP_PIN":        ("MASVS-NETWORK",    "MSTG-NETWORK-4"),
    "PINNING_TRUSTKIT":          ("MASVS-NETWORK",    "MSTG-NETWORK-4"),
    "PINNING_APPMATTUS_CT":      ("MASVS-NETWORK",    "MSTG-NETWORK-4"),
    "CONSCRYPT_TRUST_PROVIDER":  ("MASVS-NETWORK",    "MSTG-NETWORK-4"),
    "TRUST_ALL_CERTS":           ("MASVS-NETWORK",    "MSTG-NETWORK-3"),
    "HOSTNAME_VERIFIER_ALLOW_ALL": ("MASVS-NETWORK",  "MSTG-NETWORK-3"),
    # app_webview_scan (C11) ---------------------------------------------
    "WEBVIEW_JS_ENABLED":          ("MASVS-PLATFORM", "MSTG-PLATFORM-5"),
    "WEBVIEW_FILE_ACCESS":         ("MASVS-PLATFORM", "MSTG-PLATFORM-5"),
    "WEBVIEW_FILE_FROM_FILE_URLS": ("MASVS-PLATFORM", "MSTG-PLATFORM-5"),
    "WEBVIEW_UNIVERSAL_ACCESS":    ("MASVS-PLATFORM", "MSTG-PLATFORM-5"),
    "WEBVIEW_JS_INTERFACE":        ("MASVS-PLATFORM", "MSTG-PLATFORM-7"),
    "WEBVIEW_MIXED_CONTENT_ALLOW": ("MASVS-PLATFORM", "MSTG-PLATFORM-5"),
    "WEBVIEW_SAVE_PASSWORD":       ("MASVS-PLATFORM", "MSTG-PLATFORM-5"),
    "WEBVIEW_DEBUGGING":           ("MASVS-PLATFORM", "MSTG-PLATFORM-5"),
    "WEBVIEW_DOM_STORAGE":         ("MASVS-PLATFORM", "MSTG-PLATFORM-5"),
    "WEBVIEW_SHOULD_OVERRIDE_TRUE": ("MASVS-PLATFORM", "MSTG-PLATFORM-6"),
    # app_crypto_scan (C9) -----------------------------------------------
    "CRYPTO_DES_CIPHER":           ("MASVS-CRYPTO",   "MSTG-CRYPTO-2"),
    "CRYPTO_RC4_CIPHER":           ("MASVS-CRYPTO",   "MSTG-CRYPTO-2"),
    "CRYPTO_3DES_CIPHER":          ("MASVS-CRYPTO",   "MSTG-CRYPTO-2"),
    "CRYPTO_BLOWFISH_CIPHER":      ("MASVS-CRYPTO",   "MSTG-CRYPTO-2"),
    "CRYPTO_AES_ECB_MODE":         ("MASVS-CRYPTO",   "MSTG-CRYPTO-2"),
    "CRYPTO_AES_DEFAULT_MODE":     ("MASVS-CRYPTO",   "MSTG-CRYPTO-2"),
    "CRYPTO_MD5_HASH":             ("MASVS-CRYPTO",   "MSTG-CRYPTO-2"),
    "CRYPTO_SHA1_HASH":            ("MASVS-CRYPTO",   "MSTG-CRYPTO-2"),
    "CRYPTO_INSECURE_RANDOM":      ("MASVS-CRYPTO",   "MSTG-CRYPTO-6"),
    "CRYPTO_ZERO_IV":              ("MASVS-CRYPTO",   "MSTG-CRYPTO-3"),
    "CRYPTO_HARDCODED_KEY":        ("MASVS-CRYPTO",   "MSTG-CRYPTO-1"),
    "CRYPTO_WEAK_KEYGEN":          ("MASVS-CRYPTO",   "MSTG-CRYPTO-3"),
    "CRYPTO_LEGACY_BC_PROVIDER":   ("MASVS-CRYPTO",   "MSTG-CRYPTO-5"),
    # app_native_audit (C15) ---------------------------------------------
    "NATIVE_PIE_MISSING":          ("MASVS-CODE",     "MSTG-CODE-9"),
    "NATIVE_NX_MISSING":           ("MASVS-CODE",     "MSTG-CODE-9"),
    "NATIVE_NX_UNKNOWN":           ("MASVS-CODE",     "MSTG-CODE-9"),
    "NATIVE_RELRO_MISSING":        ("MASVS-CODE",     "MSTG-CODE-9"),
    "NATIVE_RELRO_PARTIAL":        ("MASVS-CODE",     "MSTG-CODE-9"),
    "NATIVE_STACK_CANARY_MISSING": ("MASVS-CODE",     "MSTG-CODE-9"),
    "NATIVE_FORTIFY_MISSING":      ("MASVS-CODE",     "MSTG-CODE-9"),
    # logcat_leak_scan (C4) ----------------------------------------------
    "EMAIL_ADDRESS":               ("MASVS-PRIVACY",  "MSTG-PRIVACY-2"),
    "IPV4_ADDRESS":                ("MASVS-PRIVACY",  "MSTG-PRIVACY-2"),
    "PHONE_NUMBER":                ("MASVS-PRIVACY",  "MSTG-PRIVACY-2"),
    "IBAN":                        ("MASVS-PRIVACY",  "MSTG-PRIVACY-2"),
    "PAN_CARD":                    ("MASVS-PRIVACY",  "MSTG-PRIVACY-2"),
    "JWT":                         ("MASVS-AUTH",     "MSTG-AUTH-1"),
    "BEARER_TOKEN":                ("MASVS-AUTH",     "MSTG-AUTH-1"),
    "AUTH_KEY_ASSIGN":             ("MASVS-AUTH",     "MSTG-AUTH-1"),
    # app_root_detection_scan (C17) -------------------------------------
    "ROOT_LIB_ROOTBEER":           ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
    "ROOT_LIB_ROOTTOOLS":          ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
    "ROOT_LIB_SAFETYNET":          ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
    "ROOT_LIB_MAGISK_DETECTOR":    ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
    "ROOT_SU_BINARY_PATH":         ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
    "ROOT_MAGISK_FILE_REF":        ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
    "ROOT_BUILD_TAGS_TESTKEYS":    ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
    "ROOT_BUILD_FINGERPRINT":      ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
    "ROOT_SYSPROP_DEBUGGABLE":     ("MASVS-RESILIENCE", "MSTG-RESILIENCE-2"),
    "ROOT_SYSPROP_SECURE":         ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
    "ROOT_RUNTIME_EXEC_SU":        ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
    "ROOT_MAGISK_PKG_CHECK":       ("MASVS-RESILIENCE", "MSTG-RESILIENCE-1"),
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


# ---------------------------------------------------------------------------
# HTML payload (C22)
# ---------------------------------------------------------------------------

def _h(value) -> str:
    """Minimal HTML escape -- the report never embeds untrusted markup, but
    finding strings can include '<', '>' and '&' that must not break the
    document."""
    s = str(value) if value is not None else ""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


_HTML_CSS = """
:root { color-scheme: light dark; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
  max-width: 1100px; margin: 0 auto; padding: 24px;
  color: #1a1a1a; background: #fafafa; line-height: 1.5; }
header { border-bottom: 2px solid #2c3e50; padding-bottom: 12px; margin-bottom: 24px; }
header h1 { margin: 0; font-size: 1.6em; color: #2c3e50; }
.meta { color: #666; font-size: 0.9em; margin-top: 6px; }
.meta code { background: #ececec; padding: 1px 6px; border-radius: 3px; }
.cards { display: flex; gap: 12px; margin: 24px 0; flex-wrap: wrap; }
.card { flex: 1 1 130px; padding: 14px 18px; border-radius: 8px; background: white;
  box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.card.high   { border-left: 4px solid #e74c3c; }
.card.medium { border-left: 4px solid #f39c12; }
.card.low    { border-left: 4px solid #3498db; }
.card.info   { border-left: 4px solid #95a5a6; }
.card .count { font-size: 1.8em; font-weight: 700; line-height: 1.0; }
.card .label { font-size: 0.85em; color: #666; margin-top: 4px; }
.coverage, .summary { background: white; border-radius: 8px; padding: 14px 18px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 24px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #eee; }
section.cat { margin-top: 32px; }
section.cat h2 { color: #2c3e50; border-bottom: 1px solid #ccc; padding-bottom: 6px;
  font-size: 1.2em; }
details { background: white; border-radius: 8px; padding: 10px 16px; margin: 10px 0;
  box-shadow: 0 1px 2px rgba(0,0,0,0.06); }
details[open] { box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
summary { cursor: pointer; font-weight: 600; outline: none; }
.sev { display: inline-block; padding: 2px 10px; border-radius: 4px;
  font-size: 0.75em; font-weight: 700; letter-spacing: 0.04em;
  margin-right: 10px; vertical-align: middle; }
.sev-HIGH   { background: #e74c3c; color: white; }
.sev-MEDIUM { background: #f39c12; color: white; }
.sev-LOW    { background: #3498db; color: white; }
.sev-INFO   { background: #95a5a6; color: white; }
dl { margin: 12px 0 4px 0; }
dt { font-weight: 600; margin-top: 8px; color: #555; font-size: 0.9em; }
dd { margin: 2px 0 6px 16px; }
pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto;
  font-size: 0.85em; font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: pre-wrap; word-break: break-word; }
.empty { background: white; padding: 20px; border-radius: 8px; color: #666;
  text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
footer { margin-top: 48px; padding-top: 12px; border-top: 1px solid #ddd;
  color: #666; font-size: 0.85em; }
"""


def _html_payload(package: str, parsed: dict, findings: List[ReportFinding]) -> str:
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    by_cat: dict = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    out: List[str] = []
    out.append("<!DOCTYPE html>")
    out.append('<html lang="en"><head>')
    out.append('<meta charset="utf-8">')
    out.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    out.append(f"<title>Harm0niz3r MASTG report &mdash; {_h(package)}</title>")
    out.append(f"<style>{_HTML_CSS}</style>")
    out.append("</head><body>")

    out.append("<header>")
    out.append(f"<h1>MASTG-aligned Static Report</h1>")
    out.append('<div class="meta">')
    out.append(f"Package: <code>{_h(package)}</code> &mdash; ")
    out.append(
        f"version <code>{_h(parsed.get('versionName'))}</code> "
        f"(code <code>{_h(parsed.get('versionCode'))}</code>) &mdash; "
    )
    out.append(
        f"targetSdk <code>{_h(parsed.get('targetSdk'))}</code> / "
        f"minSdk <code>{_h(parsed.get('minSdk'))}</code> &mdash; "
    )
    out.append(
        f"Debug=<code>{_h(parsed.get('debugMode'))}</code> "
        f"System=<code>{_h(parsed.get('systemApp'))}</code> &mdash; "
    )
    out.append(f"Scanned <code>{_h(time.strftime('%Y-%m-%d %H:%M:%S'))}</code>")
    out.append("</div>")
    out.append("</header>")

    # Severity cards
    out.append('<div class="cards">')
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        out.append(
            f'<div class="card {sev.lower()}">'
            f'<div class="count">{sev_counts.get(sev, 0)}</div>'
            f'<div class="label">{sev}</div>'
            f"</div>"
        )
    out.append(
        f'<div class="card"><div class="count">{len(findings)}</div>'
        f'<div class="label">TOTAL</div></div>'
    )
    out.append("</div>")

    # MASVS coverage table
    out.append('<div class="coverage">')
    out.append("<h3 style=\"margin-top:0\">MASVS coverage</h3>")
    out.append("<table>")
    out.append("<thead><tr><th>MASVS category</th><th>Findings</th></tr></thead><tbody>")
    for cat in _CATEGORY_ORDER:
        out.append(
            f"<tr><td>{_h(cat)}</td><td>{len(by_cat.get(cat, []))}</td></tr>"
        )
    for extra in by_cat:
        if extra not in _CATEGORY_ORDER:
            out.append(
                f"<tr><td>{_h(extra)}</td><td>{len(by_cat[extra])}</td></tr>"
            )
    out.append("</tbody></table>")
    out.append("</div>")

    # Per-category sections
    if not findings:
        out.append(
            '<div class="empty">No findings.  Either the app is clean against '
            "the V1 static rules, or the rules didn't catch its particular shape "
            "(coverage is still being expanded -- see the C bucket roadmap).</div>"
        )
    else:
        for cat in _CATEGORY_ORDER:
            bucket = sorted(
                by_cat.get(cat, []), key=lambda x: _SEV_ORDER.get(x.severity, 9)
            )
            if not bucket:
                continue
            out.append('<section class="cat">')
            out.append(f"<h2>{_h(cat)}</h2>")
            for f in bucket:
                out.append("<details>")
                out.append(
                    f'<summary><span class="sev sev-{_h(f.severity)}">'
                    f"{_h(f.severity)}</span>{_h(f.title)} "
                    f"<small style=\"color:#888;font-weight:400;\">"
                    f"&nbsp;[{_h(f.id)}]</small></summary>"
                )
                out.append("<dl>")
                out.append(f"<dt>MASTG test ID</dt><dd><code>{_h(f.mastg)}</code></dd>")
                out.append(
                    f"<dt>Source command</dt><dd><code>{_h(f.source)}</code></dd>"
                )
                if f.evidence:
                    ev = f.evidence
                    if len(ev) > 1200:
                        ev = ev[:1197] + "..."
                    out.append(f"<dt>Evidence</dt><dd><pre>{_h(ev)}</pre></dd>")
                out.append(f"<dt>Detail</dt><dd>{_h(f.detail)}</dd>")
                if f.recommendation:
                    out.append(
                        f"<dt>Recommendation</dt><dd>{_h(f.recommendation)}</dd>"
                    )
                out.append("</dl>")
                out.append("</details>")
            out.append("</section>")

    out.append("<footer>Generated by <code>mastg_report</code> "
               "(Harm0niz3r).</footer>")
    out.append("</body></html>")
    return "\n".join(out)


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
            "mastg_report <package> [--out FILE] [--json | --html] [--secrets-dir DIR]\n"
            "  Run app_scan + app_provider_probe + app_deeplinks against\n"
            "  <package>, organise findings by MASVS category and tag each\n"
            "  with the corresponding MASTG MSTG-* test ID.  Emits Markdown\n"
            "  to stdout by default.\n"
            "  --out FILE        Write the report to FILE instead of stdout.\n"
            "  --json            Emit a JSON payload instead of Markdown.\n"
            "  --html            Emit a self-contained HTML page (inline CSS,\n"
            "                    no JS, <details> collapsibles, severity\n"
            "                    badges).\n"
            "  --secrets-dir DIR Also include findings from a previously\n"
            "                    decompiled tree (typically the output of\n"
            "                    'app_decompile').\n\n"
            "Examples:\n"
            "  mastg_report com.example.target\n"
            "  mastg_report com.example.target --out report.md\n"
            "  mastg_report com.example.target --html --out report.html\n"
            "  mastg_report com.example.target --secrets-dir ./decompiled/com.example.target/"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        out_file: Optional[str] = None
        as_json = False
        as_html = False
        secrets_dir: Optional[str] = None
        positional: List[str] = []

        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--json":
                as_json = True
                i += 1
            elif tok == "--html":
                as_html = True
                i += 1
            elif tok == "--out" and i + 1 < len(args):
                out_file = args[i + 1]; i += 2
            elif tok == "--secrets-dir" and i + 1 < len(args):
                secrets_dir = args[i + 1]; i += 2
            else:
                positional.append(tok); i += 1

        if as_json and as_html:
            console._print_message(
                "ERROR",
                "--json and --html are mutually exclusive."
            )
            return

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
        elif as_html:
            body = _html_payload(package, parsed, findings)
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
