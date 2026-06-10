# -*- coding: utf-8 -*-
# commands/android/app_nsc_check.py
"""
app_nsc_check - audit an Android app's Network Security Config (NSC).

Two modes:

  app_nsc_check <package> [--apktool PATH] [--out DIR] [--json]
      Pull the APK installed for <package>, decode it with apktool, and
      audit AndroidManifest.xml + res/xml/network_security_config.xml.

  app_nsc_check --nsc-file <path> [--manifest-file <path>] [--json]
      Skip the apktool dance; parse user-supplied XML files instead.
      Useful when apktool isn't on PATH or when you've already extracted
      the resources by hand.

Findings (each tagged by id + severity)

  NSC_MISSING                  INFO   Manifest does not reference an NSC --
                                      the implicit defaults apply.
  NSC_CLEARTEXT_BASE           HIGH   base-config permits cleartext.
  NSC_CLEARTEXT_DOMAIN         MEDIUM A specific domain-config permits
                                      cleartext.
  NSC_USER_TRUST_ANCHORS       HIGH   Trusts user-installed CAs (Burp setup
                                      is trivial).
  NSC_DEBUG_OVERRIDES          INFO   debug-overrides defined -- audit that
                                      they aren't shipping in release.
  NSC_PIN_SET_PRESENT          INFO   A <pin-set> is declared for one or
                                      more domains -- worth confirming
                                      it's enforced at runtime via
                                      app_pinning_check / Frida.
  NSC_NO_PIN_SET               LOW    No <pin-set> anywhere in the config.
  MANIFEST_CLEARTEXT_TRUE      HIGH   android:usesCleartextTraffic=\"true\"
                                      on <application>.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

from commands.base import Command, CommandSource


_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


class NscFinding:
    __slots__ = ("id", "severity", "title", "detail", "evidence", "recommendation")

    def __init__(self, id, severity, title, detail, evidence=None, recommendation=None):
        self.id = id
        self.severity = severity
        self.title = title
        self.detail = detail
        self.evidence = evidence
        self.recommendation = recommendation

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_manifest(manifest_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (network_security_config_resource_ref, usesCleartextTraffic_attr)."""
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    app = root.find("application")
    if app is None:
        return None, None
    nsc_ref = app.attrib.get(_ANDROID_NS + "networkSecurityConfig")
    cleartext = app.attrib.get(_ANDROID_NS + "usesCleartextTraffic")
    return nsc_ref, cleartext


def _domains_for(config_elem) -> List[str]:
    out = []
    for d in config_elem.findall("domain"):
        if d.text:
            out.append(d.text.strip())
    return out


def _parse_nsc(nsc_path: str) -> List[NscFinding]:
    findings: List[NscFinding] = []
    tree = ET.parse(nsc_path)
    root = tree.getroot()

    pin_set_seen = False

    # --- base-config ---
    for bc in root.findall("base-config"):
        if bc.attrib.get("cleartextTrafficPermitted") == "true":
            findings.append(NscFinding(
                "NSC_CLEARTEXT_BASE", "HIGH",
                "Network Security Config permits cleartext traffic (base-config)",
                "The base configuration sets cleartextTrafficPermitted=\"true\", "
                "so the app may speak plain HTTP to any domain that doesn't have "
                "a more restrictive override.",
                evidence="<base-config cleartextTrafficPermitted=\"true\">",
                recommendation="Set cleartextTrafficPermitted=\"false\" on the "
                               "base-config and whitelist specific dev domains "
                               "via <domain-config> only if absolutely required.",
            ))
        for ta in bc.findall("trust-anchors"):
            for cert in ta.findall("certificates"):
                if cert.attrib.get("src") == "user":
                    findings.append(NscFinding(
                        "NSC_USER_TRUST_ANCHORS", "HIGH",
                        "Trusts user-installed CAs in the base-config",
                        "A user-installed CA is enough to intercept TLS traffic "
                        "with Burp / mitmproxy on a non-rooted device.",
                        evidence="<trust-anchors><certificates src=\"user\"/></trust-anchors> (base-config)",
                        recommendation="Drop the user trust anchor for release "
                                       "builds; rely on system anchors only.",
                    ))

    # --- domain-config(s) ---
    for dc in root.findall("domain-config"):
        domains = _domains_for(dc) or ["(no <domain> child)"]
        if dc.attrib.get("cleartextTrafficPermitted") == "true":
            findings.append(NscFinding(
                "NSC_CLEARTEXT_DOMAIN", "MEDIUM",
                f"Cleartext permitted for {', '.join(domains)}",
                "A <domain-config> explicitly permits cleartext traffic for the "
                "listed domains.",
                evidence=f"<domain-config> domains={domains}",
                recommendation="Remove the cleartext exception or scope it to a "
                               "narrow dev/staging domain.",
            ))
        for ta in dc.findall("trust-anchors"):
            for cert in ta.findall("certificates"):
                if cert.attrib.get("src") == "user":
                    findings.append(NscFinding(
                        "NSC_USER_TRUST_ANCHORS", "HIGH",
                        f"Trusts user-installed CAs for {', '.join(domains)}",
                        "A user-installed CA is enough to intercept TLS traffic.",
                        evidence=f"<domain-config> domains={domains} (user CA)",
                        recommendation="Drop user trust anchors in release builds.",
                    ))
        if dc.find("pin-set") is not None:
            pin_set_seen = True
            findings.append(NscFinding(
                "NSC_PIN_SET_PRESENT", "INFO",
                f"Pin-set declared for {', '.join(domains)}",
                "A <pin-set> is configured.  Worth confirming at runtime "
                "(app_pinning_check / Frida) that pinning is actually enforced "
                "and not bypassed via a custom TrustManager.",
                evidence=f"<domain-config> domains={domains} (pin-set)",
            ))

    if not pin_set_seen:
        findings.append(NscFinding(
            "NSC_NO_PIN_SET", "LOW",
            "No <pin-set> declared in NSC",
            "No certificate pinning is configured via the NSC.  The app may "
            "still implement pinning in code (OkHttp CertificatePinner, custom "
            "TrustManager); run app_pinning_check on the decompiled tree to "
            "confirm.",
        ))

    if root.find("debug-overrides") is not None:
        findings.append(NscFinding(
            "NSC_DEBUG_OVERRIDES", "INFO",
            "<debug-overrides> is defined",
            "Debug overrides ship in the APK; verify they aren't honoured by "
            "release builds (they shouldn't be) and don't leak via signature "
            "spoofing tricks.",
            evidence="<debug-overrides> element present",
        ))

    return findings


def _from_manifest_only(cleartext_attr: Optional[str]) -> List[NscFinding]:
    findings: List[NscFinding] = []
    if cleartext_attr == "true":
        findings.append(NscFinding(
            "MANIFEST_CLEARTEXT_TRUE", "HIGH",
            "android:usesCleartextTraffic=\"true\" on <application>",
            "The application-level attribute opts the entire app back into "
            "cleartext traffic, bypassing the API 28+ default deny.",
            evidence="<application android:usesCleartextTraffic=\"true\">",
            recommendation="Set the attribute to \"false\" or remove it; rely on "
                           "an NSC <domain-config> to whitelist specific dev "
                           "domains if needed.",
        ))
    return findings


# ---------------------------------------------------------------------------
# Live path: apktool decode
# ---------------------------------------------------------------------------

def _resolve_nsc_resource_path(decoded_root: str, nsc_ref: Optional[str]) -> Optional[str]:
    """
    Given the apktool output root and the @xml/<name> reference from the
    manifest, return the absolute path of the NSC XML file (or None when
    it can't be located, which is itself a finding worth surfacing).
    """
    if not nsc_ref:
        return None
    m = re.match(r"@([a-zA-Z0-9_]+)/([a-zA-Z0-9_]+)", nsc_ref)
    if not m:
        # apktool sometimes resolves the reference directly; try treating it
        # as a path relative to the decoded root.
        candidate = os.path.join(decoded_root, "res", nsc_ref.lstrip("@/"))
        return candidate if os.path.isfile(candidate) else None
    kind, name = m.group(1), m.group(2)
    candidate = os.path.join(decoded_root, "res", kind, f"{name}.xml")
    return candidate if os.path.isfile(candidate) else None


def _live_decode_and_parse(
    console,
    package: str,
    apktool_bin: str,
    work_dir: str,
) -> Tuple[List[NscFinding], Optional[str]]:
    """
    Pull the APK, decode it with apktool, parse manifest + NSC.
    Returns (findings, decoded_root_or_None_on_failure).
    """
    # 1) resolve installed APK path
    stdout, stderr, retcode = console._run_shell(["pm", "path", package])
    if retcode != 0 or not stdout:
        console._print_message("ERROR", f"pm path failed: {stderr or 'no output'}")
        return [], None
    paths = [
        line[len("package:"):].strip()
        for line in stdout.splitlines()
        if line.startswith("package:") and line.strip().endswith("/base.apk")
    ]
    if not paths:
        # fall back to first apk if base.apk isn't there
        all_paths = [
            line[len("package:"):].strip()
            for line in stdout.splitlines() if line.startswith("package:")
        ]
        if not all_paths:
            console._print_message("ERROR", "No APK paths returned by 'pm path'.")
            return [], None
        paths = all_paths[:1]

    remote = paths[0]
    local_apk = os.path.join(work_dir, os.path.basename(remote))
    bridge_args = console.platform.pull_file_args(console.device_id, remote, local_apk)
    _, perr, pret = console._run_bridge(bridge_args)
    if pret != 0 or not os.path.exists(local_apk):
        console._print_message("ERROR", f"Could not pull APK: {perr or 'unknown error'}")
        return [], None

    # 2) apktool decode
    decoded_root = os.path.join(work_dir, "decoded")
    cmd = [apktool_bin, "d", "-f", local_apk, "-o", decoded_root, "-q"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        console._print_message("ERROR", f"apktool not runnable: '{apktool_bin}'.")
        return [], None
    except Exception as e:
        console._print_message("ERROR", f"apktool invocation failed: {e}")
        return [], None
    if proc.returncode != 0:
        console._print_message(
            "ERROR",
            f"apktool exited {proc.returncode}: {(proc.stderr or proc.stdout)[:240]}"
        )
        return [], None

    # 3) parse manifest -> find NSC ref
    manifest_path = os.path.join(decoded_root, "AndroidManifest.xml")
    if not os.path.isfile(manifest_path):
        console._print_message("ERROR", "Decoded tree has no AndroidManifest.xml.")
        return [], decoded_root
    try:
        nsc_ref, cleartext_attr = _parse_manifest(manifest_path)
    except ET.ParseError as e:
        console._print_message("ERROR", f"Could not parse decoded manifest: {e}")
        return [], decoded_root

    findings = _from_manifest_only(cleartext_attr)

    if not nsc_ref:
        findings.append(NscFinding(
            "NSC_MISSING", "INFO",
            "App does not declare a Network Security Config",
            "Without an NSC the API-default cleartext policy applies "
            "(targetSdk 28+ defaults to deny).  Verify targetSdk and any "
            "android:usesCleartextTraffic manifest override.",
        ))
        return findings, decoded_root

    nsc_path = _resolve_nsc_resource_path(decoded_root, nsc_ref)
    if not nsc_path:
        console._print_message(
            "WARNING",
            f"NSC reference '{nsc_ref}' could not be resolved in the decoded tree."
        )
        return findings, decoded_root
    try:
        findings.extend(_parse_nsc(nsc_path))
    except ET.ParseError as e:
        console._print_message("ERROR", f"NSC XML parse error: {e}")
    return findings, decoded_root


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


def _render_console(label: str, findings: List[NscFinding]) -> str:
    sep = "=" * 60
    lines = [
        sep,
        f"{_BOLD}NSC AUDIT  {label}{_RST}",
        sep,
        f"  Findings : {len(findings)} total",
        "-" * 60,
    ]
    if not findings:
        lines.append("  Nothing flagged by the NSC checks.")
        lines.append(sep)
        return "\n".join(lines)
    for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
        color = _SEV_COLOR.get(f.severity, "")
        lines.append("")
        lines.append(f"  [{color}{f.severity}{_RST}] {_BOLD}{f.id}{_RST} : {f.title}")
        if f.evidence:
            lines.append(f"        Evidence       : {_DIM}{f.evidence}{_RST}")
        lines.append(f"        Detail         : {f.detail}")
        if f.recommendation:
            lines.append(f"        Recommendation : {f.recommendation}")
    lines.append("")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(label: str, findings: List[NscFinding]) -> str:
    return json.dumps({
        "subject":  label,
        "findings": [f.to_dict() for f in findings],
        "counts":   {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
        },
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidAppNscCheckCommand(Command):
    @property
    def name(self) -> str:
        return "app_nsc_check"

    def help(self) -> str:
        return (
            "app_nsc_check <package> [--apktool PATH] [--out DIR] [--json]\n"
            "  Pull the APK for <package>, decode it with apktool, audit\n"
            "  AndroidManifest.xml + the referenced Network Security Config.\n"
            "  --apktool PATH  Path to the apktool binary (default: 'apktool').\n"
            "  --out DIR       Keep the decoded apktool output under this dir\n"
            "                  (default: a temp dir that's removed on exit).\n"
            "  --json          Emit JSON instead of the console table.\n\n"
            "app_nsc_check --nsc-file <path> [--manifest-file <path>] [--json]\n"
            "  Parse user-supplied XML files instead of going via apktool.\n"
            "  Useful when apktool isn't on PATH or you already extracted the\n"
            "  XML by hand.  At least --nsc-file is required for this mode.\n\n"
            "Examples:\n"
            "  app_nsc_check com.example.target\n"
            "  app_nsc_check com.example.target --apktool /opt/apktool/apktool\n"
            "  app_nsc_check --nsc-file ./res/xml/network_security_config.xml --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        # --- arg parsing ---
        as_json = False
        apktool_override: Optional[str] = None
        out_dir: Optional[str] = None
        nsc_file: Optional[str] = None
        manifest_file: Optional[str] = None
        positional: List[str] = []

        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--json":
                as_json = True; i += 1
            elif tok == "--apktool" and i + 1 < len(args):
                apktool_override = args[i + 1]; i += 2
            elif tok == "--out" and i + 1 < len(args):
                out_dir = args[i + 1]; i += 2
            elif tok == "--nsc-file" and i + 1 < len(args):
                nsc_file = args[i + 1]; i += 2
            elif tok == "--manifest-file" and i + 1 < len(args):
                manifest_file = args[i + 1]; i += 2
            else:
                positional.append(tok); i += 1

        # --- file mode ---
        if nsc_file or manifest_file:
            if not nsc_file and not manifest_file:
                console._print_message(
                    "INFO",
                    "Need at least --nsc-file <path> or --manifest-file <path>."
                )
                return
            findings: List[NscFinding] = []
            label_parts: List[str] = []
            if manifest_file:
                if not os.path.isfile(manifest_file):
                    console._print_message("ERROR", f"Manifest not found: {manifest_file}")
                    return
                try:
                    _, cleartext_attr = _parse_manifest(manifest_file)
                except ET.ParseError as e:
                    console._print_message("ERROR", f"Manifest parse error: {e}")
                    return
                findings.extend(_from_manifest_only(cleartext_attr))
                label_parts.append(os.path.basename(manifest_file))
            if nsc_file:
                if not os.path.isfile(nsc_file):
                    console._print_message("ERROR", f"NSC file not found: {nsc_file}")
                    return
                try:
                    findings.extend(_parse_nsc(nsc_file))
                except ET.ParseError as e:
                    console._print_message("ERROR", f"NSC parse error: {e}")
                    return
                label_parts.append(os.path.basename(nsc_file))
            label = " + ".join(label_parts) or "(file mode)"
            print(_render_json(label, findings) if as_json else _render_console(label, findings))
            return

        # --- package mode ---
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return
        if len(positional) != 1:
            console._print_message(
                "INFO",
                "Usage: app_nsc_check <package> [--apktool PATH] [--out DIR] [--json]"
            )
            return
        package = positional[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        # Resolution: --apktool flag wins; otherwise consult tools.json /
        # tools.local.json (the F bucket central resolver); finally fall
        # back to PATH lookup.
        if apktool_override:
            apktool_bin = (
                apktool_override
                if os.path.isfile(apktool_override)
                else shutil.which(apktool_override)
            )
        else:
            from tools import resolve_tool
            apktool_bin = resolve_tool("apktool")
        if not apktool_bin:
            console._print_message(
                "ERROR",
                "apktool not found.  Either:\n"
                "  - install from https://apktool.org/ and add to PATH\n"
                "  - set 'apktool' in Harm0nyz3r_client/tools.local.json to the absolute path\n"
                "  - pass --apktool <path> for a one-shot override\n"
                "  - or use file mode: --nsc-file <path> [--manifest-file <path>]"
            )
            return

        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            work_dir = out_dir
            cleanup = False
        else:
            work_dir = tempfile.mkdtemp(prefix="harm0nyz3r-nsc-")
            cleanup = True
        try:
            findings, _decoded = _live_decode_and_parse(
                console, package, apktool_bin, work_dir
            )
        finally:
            if cleanup:
                try:
                    shutil.rmtree(work_dir, ignore_errors=True)
                except Exception:
                    pass

        print(_render_json(package, findings) if as_json else _render_console(package, findings))


def register(registry_func):
    registry_func(AndroidAppNscCheckCommand())
