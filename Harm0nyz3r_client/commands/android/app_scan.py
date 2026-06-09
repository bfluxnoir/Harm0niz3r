# -*- coding: utf-8 -*-
# commands/android/app_scan.py
"""
app_scan - automated static security scan against an installed Android APK.

V1 checks (no APK pull required, no agent dependency):
  - android:debuggable flag
  - android:allowBackup flag
  - android:usesCleartextTraffic flag
  - outdated targetSdk (< 30)
  - exported components without permission guard
      Provider  -> HIGH   (data exposure)
      Activity  -> MEDIUM
      Service   -> MEDIUM
      Receiver  -> LOW
  - dangerous permissions requested
  - dangerous permissions granted (install/runtime)
  - deeplink-handler enumeration (INFO; points to manual review)

All checks are derived from `pm dump <package>` so the command works against
any installed package over plain adb.  Agent dependency is intentionally
avoided so the report can be generated even when the on-device agent isn't
running.
"""

import json
import re
from typing import List, Optional

from commands.base import Command, CommandSource
from parsers.android_parser import parse_pm_dump, looks_thin, thin_warning
from commands.android.app_permissions import _DANGEROUS_PERMS


# Severity scoring weights and the resulting rating bands.
_SEVERITY_SCORE = {"HIGH": 5, "MEDIUM": 3, "LOW": 1, "INFO": 0}

# ANSI colour codes (kept local so the command is self-contained).
_SEV_COLOR = {
    "HIGH":   "\033[1;91m",
    "MEDIUM": "\033[1;93m",
    "LOW":    "\033[1;94m",
    "INFO":   "\033[1;90m",
}
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RST = "\033[0m"


class Finding:
    """A single security observation from a check."""

    __slots__ = ("id", "severity", "title", "detail", "evidence", "recommendation")

    def __init__(
        self,
        id_: str,
        severity: str,
        title: str,
        detail: str,
        evidence: Optional[str] = None,
        recommendation: Optional[str] = None,
    ) -> None:
        self.id = id_
        self.severity = severity
        self.title = title
        self.detail = detail
        self.evidence = evidence
        self.recommendation = recommendation

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


# ---------------------------------------------------------------------------
# Individual checks (each returns Finding | None or List[Finding])
# ---------------------------------------------------------------------------

def _check_debuggable(parsed: dict) -> Optional[Finding]:
    if parsed.get("debugMode"):
        return Finding(
            "DEBUGGABLE_FLAG", "HIGH",
            "Application is debuggable",
            "android:debuggable=true allows jdb / Frida / Stetho to attach without "
            "root and inspect or modify process memory at will.",
            evidence="flags include DEBUGGABLE",
            recommendation="Remove android:debuggable from the release manifest "
                          "or build a non-debug variant.",
        )
    return None


def _check_allow_backup(raw_dump: str) -> Optional[Finding]:
    m = re.search(r"flags=\[([^\]]*)\]", raw_dump)
    if m and "ALLOW_BACKUP" in m.group(1):
        return Finding(
            "ALLOW_BACKUP_FLAG", "MEDIUM",
            "Application allows backup",
            "android:allowBackup=true permits `adb backup` to extract the app's "
            "internal data (databases, shared_prefs, files).",
            evidence="flags include ALLOW_BACKUP",
            recommendation="Set android:allowBackup=\"false\" in the manifest, "
                          "or define a careful backup rules file.",
        )
    return None


def _check_cleartext(raw_dump: str) -> Optional[Finding]:
    # 'pm dump' surfaces this on most devices but not always; if absent we skip.
    m = re.search(r"usesCleartextTraffic=(true|false)", raw_dump)
    if m and m.group(1) == "true":
        return Finding(
            "CLEARTEXT_TRAFFIC", "MEDIUM",
            "Cleartext network traffic permitted",
            "android:usesCleartextTraffic=true permits HTTP (non-TLS) traffic.",
            evidence="usesCleartextTraffic=true",
            recommendation="Set usesCleartextTraffic=\"false\" (or omit) and only use HTTPS. "
                          "Use a network_security_config to whitelist specific dev domains "
                          "if absolutely necessary.",
        )
    return None


def _check_target_sdk(parsed: dict) -> Optional[Finding]:
    target = parsed.get("targetSdk")
    if isinstance(target, int) and target < 30:
        return Finding(
            "OUTDATED_TARGET_SDK", "LOW",
            f"targetSdk {target} is below 30",
            "Old targetSdk values opt the app out of modern security hardening "
            "(scoped storage, package visibility, background-activity-start "
            "restrictions, runtime permission improvements).",
            evidence=f"targetSdk={target}",
            recommendation="Raise targetSdk to at least 30, preferably the current platform.",
        )
    return None


def _check_exported_components(parsed: dict) -> List[Finding]:
    out: List[Finding] = []
    for comp in parsed.get("exposedComponents", []):
        if not comp.get("visible"):
            continue
        if comp.get("permissionsRequired"):
            continue  # has a permission guard
        ctype = comp.get("type", "?")
        name = comp.get("name", "?")
        if ctype == "Provider":
            sev = "HIGH"
            detail = ("Exported Content Provider with no permission requirement; "
                      "any other app can query or update it.")
            rec = ("Add android:permission, set android:exported=\"false\", or guard "
                   "with android:readPermission / writePermission.")
        elif ctype in ("Activity", "Service"):
            sev = "MEDIUM"
            detail = (f"Exported {ctype} with no permission requirement; reachable "
                      "from any other app via Intent.")
            rec = (f"Add android:permission to the {ctype}, or set android:exported="
                   "\"false\" if it doesn't need cross-app access.")
        else:  # Receiver
            sev = "LOW"
            detail = ("Exported BroadcastReceiver with no permission requirement; "
                      "any app can deliver broadcasts to it.")
            rec = ("Add android:permission to the receiver, or set android:exported="
                   "\"false\".")
        out.append(Finding(
            f"EXPORTED_{ctype.upper()}_NO_PERM",
            sev,
            f"Exported {ctype} without permission guard: {name}",
            detail,
            evidence=name,
            recommendation=rec,
        ))
    return out


def _check_dangerous_permissions(parsed: dict) -> List[Finding]:
    requested = (
        parsed.get("requestedAppPermissions")
        or parsed.get("requiredAppPermissions")
        or []
    )
    granted = set(parsed.get("grantedPermissions") or [])
    dangerous_req = sorted(p for p in requested if p in _DANGEROUS_PERMS)
    dangerous_grant = sorted(p for p in dangerous_req if p in granted)

    out: List[Finding] = []
    if dangerous_req:
        out.append(Finding(
            "DANGEROUS_PERMS_REQUESTED", "INFO",
            f"{len(dangerous_req)} dangerous permission(s) requested",
            "Permissions Android classifies as 'dangerous' are present in the manifest.",
            evidence=", ".join(dangerous_req),
        ))
    if dangerous_grant:
        out.append(Finding(
            "DANGEROUS_PERMS_GRANTED", "MEDIUM",
            f"{len(dangerous_grant)} dangerous permission(s) granted",
            "These permissions are currently granted, so the app can already use them "
            "without further user interaction.",
            evidence=", ".join(dangerous_grant),
        ))
    return out


def _check_deeplinks(parsed: dict) -> Optional[Finding]:
    handlers = []
    for comp in parsed.get("exposedComponents", []):
        for skill in comp.get("skills", []):
            if skill.get("action") == "android.intent.action.VIEW":
                handlers.append(comp.get("name"))
                break
    if not handlers:
        return None
    return Finding(
        "DEEPLINK_HANDLERS", "INFO",
        f"{len(handlers)} component(s) handle deeplinks",
        "Components with an android.intent.action.VIEW intent filter respond to "
        "deeplinks.  Each is worth testing manually for auth bypass / IDOR / "
        "unauthenticated routes.",
        evidence=", ".join(handlers),
        recommendation="Use 'app_deeplink <uri>' to trigger each handler and confirm "
                       "it enforces auth before performing sensitive actions.",
    )


def _run_scan(parsed: dict, raw_dump: str) -> List[Finding]:
    findings: List[Finding] = []
    for fn in (_check_debuggable, _check_target_sdk):
        f = fn(parsed)
        if f:
            findings.append(f)
    for fn in (_check_allow_backup, _check_cleartext):
        f = fn(raw_dump)
        if f:
            findings.append(f)
    findings.extend(_check_exported_components(parsed))
    findings.extend(_check_dangerous_permissions(parsed))
    f = _check_deeplinks(parsed)
    if f:
        findings.append(f)
    return findings


def _rate(score: int) -> str:
    if score >= 15:
        return "CRITICAL"
    if score >= 10:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "CLEAN"


def _score(findings: List[Finding]) -> int:
    return sum(_SEVERITY_SCORE.get(f.severity, 0) for f in findings)


def _counts(findings: List[Finding]) -> dict:
    out = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def _render_console(parsed: dict, findings: List[Finding]) -> str:
    pkg = parsed.get("packageName", "UNKNOWN")
    score = _score(findings)
    rating = _rate(score)
    counts = _counts(findings)
    rating_color = _SEV_COLOR.get(
        "HIGH" if rating in ("CRITICAL", "HIGH") else
        "MEDIUM" if rating == "MEDIUM" else
        "LOW" if rating == "LOW" else "INFO",
        ""
    )
    sep = "=" * 60
    lines = []
    lines.append(sep)
    lines.append(f"{_BOLD}APP SCAN  {pkg}{_RST}")
    lines.append(sep)
    lines.append(f"  Version    : {parsed.get('versionName')} (code {parsed.get('versionCode')})")
    lines.append(f"  Target SDK : {parsed.get('targetSdk')}   Min SDK: {parsed.get('minSdk')}")
    lines.append(f"  Debuggable : {parsed.get('debugMode')}")
    lines.append(f"  System app : {parsed.get('systemApp')}")
    lines.append("")
    lines.append(f"  Score    : {score}   Rating: {rating_color}{rating}{_RST}")
    lines.append(
        "  Findings : "
        f"{len(findings)} total  "
        f"({counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, "
        f"{counts['LOW']} LOW, {counts['INFO']} INFO)"
    )
    lines.append("-" * 60)

    if not findings:
        lines.append("  No issues detected by the V1 static checks.")
        lines.append(sep)
        return "\n".join(lines)

    for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
        color = _SEV_COLOR.get(f.severity, "")
        lines.append("")
        lines.append(f"  [{color}{f.severity}{_RST}] {_BOLD}{f.id}{_RST} : {f.title}")
        lines.append(f"        Detail        : {f.detail}")
        if f.evidence:
            ev = f.evidence
            # Truncate huge evidence lines to keep the console readable.
            if len(ev) > 240:
                ev = ev[:237] + "..."
            lines.append(f"        Evidence      : {_DIM}{ev}{_RST}")
        if f.recommendation:
            lines.append(f"        Recommendation: {f.recommendation}")

    lines.append("")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(parsed: dict, findings: List[Finding]) -> str:
    payload = {
        "package": parsed.get("packageName"),
        "version": {
            "name": parsed.get("versionName"),
            "code": parsed.get("versionCode"),
        },
        "targetSdk": parsed.get("targetSdk"),
        "minSdk": parsed.get("minSdk"),
        "debuggable": parsed.get("debugMode"),
        "systemApp": parsed.get("systemApp"),
        "score": _score(findings),
        "rating": _rate(_score(findings)),
        "counts": _counts(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


class AndroidAppScanCommand(Command):
    """
    Automated static security scan of an installed Android package.
    Combines the existing pm-dump parser with a set of severity-tagged
    checks and prints (or returns) a risk-scored report.
    """

    @property
    def name(self) -> str:
        return "app_scan"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_scan <package> [--json] [--log]\n"
            "  Run a static security scan against an installed APK and print\n"
            "  a risk-scored report.  Checks: debuggable, allowBackup,\n"
            "  cleartext, targetSdk, exported components without permission,\n"
            "  dangerous permissions requested vs granted, deeplink handlers.\n"
            "  --json  Emit the full report as JSON instead of the pretty console view.\n\n"
            "Examples:\n"
            "  app_scan com.example.app\n"
            "  app_scan com.example.app --json"
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
            console._print_message("INFO", "Usage: app_scan <package> [--json]")
            return

        package = args[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: '{package}'")
            return

        console._print_message("INFO", f"Scanning {package} ...")
        stdout, stderr, retcode = console._run_shell(["pm", "dump", package])
        if retcode != 0 or not stdout:
            console._print_message("ERROR", f"pm dump failed: {stderr or 'no output'}")
            return

        parsed = parse_pm_dump(stdout, package)
        if looks_thin(parsed):
            console._print_message("WARNING", thin_warning(package, "app_scan"))
        findings = _run_scan(parsed, stdout)

        if as_json:
            print(_render_json(parsed, findings))
        else:
            print(_render_console(parsed, findings))


def register(registry_func):
    registry_func(AndroidAppScanCommand())
