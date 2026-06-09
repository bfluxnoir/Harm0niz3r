"""Tests for commands/android/app_nsc_check.py (parse layer only)."""

import os
import tempfile

from commands.android.app_nsc_check import (
    _parse_manifest, _parse_nsc, _from_manifest_only,
)


# A minimal manifest that references an NSC and forces cleartext on.
_MANIFEST_WITH_NSC = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.target">
  <application
      android:label="Target"
      android:networkSecurityConfig="@xml/network_security_config"
      android:usesCleartextTraffic="true">
  </application>
</manifest>
"""

_MANIFEST_NO_NSC = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.target">
  <application android:label="Target"/>
</manifest>
"""

# An NSC with most of the failure modes the scanner should catch.
_NSC_BAD = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain>dev.example.com</domain>
    <trust-anchors>
      <certificates src="user"/>
    </trust-anchors>
  </domain-config>
  <domain-config>
    <domain>secure.example.com</domain>
    <pin-set expiration="2026-01-01">
      <pin digest="SHA-256">AAAA</pin>
      <pin digest="SHA-256">BBBB</pin>
    </pin-set>
  </domain-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user"/>
    </trust-anchors>
  </debug-overrides>
</network-security-config>
"""

_NSC_CLEAN = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system"/>
    </trust-anchors>
  </base-config>
  <domain-config>
    <domain>api.example.com</domain>
    <pin-set>
      <pin digest="SHA-256">deadbeef</pin>
    </pin-set>
  </domain-config>
</network-security-config>
"""


def _write(path: str, body: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


def test_manifest_extracts_nsc_ref_and_cleartext():
    tmp = tempfile.mkdtemp()
    p = os.path.join(tmp, "AndroidManifest.xml")
    _write(p, _MANIFEST_WITH_NSC)
    nsc_ref, cleartext = _parse_manifest(p)
    assert nsc_ref == "@xml/network_security_config"
    assert cleartext == "true"


def test_manifest_without_nsc_returns_none_for_ref():
    tmp = tempfile.mkdtemp()
    p = os.path.join(tmp, "AndroidManifest.xml")
    _write(p, _MANIFEST_NO_NSC)
    nsc_ref, cleartext = _parse_manifest(p)
    assert nsc_ref is None
    assert cleartext is None


def test_manifest_cleartext_true_is_flagged():
    findings = _from_manifest_only("true")
    assert any(f.id == "MANIFEST_CLEARTEXT_TRUE" and f.severity == "HIGH" for f in findings)


def test_manifest_cleartext_false_is_clean():
    assert _from_manifest_only("false") == []


def test_bad_nsc_catches_all_expected_failure_modes():
    tmp = tempfile.mkdtemp()
    p = os.path.join(tmp, "nsc.xml")
    _write(p, _NSC_BAD)
    findings = _parse_nsc(p)
    ids = {f.id for f in findings}
    assert "NSC_CLEARTEXT_BASE" in ids
    assert "NSC_CLEARTEXT_DOMAIN" in ids
    assert "NSC_USER_TRUST_ANCHORS" in ids
    assert "NSC_PIN_SET_PRESENT" in ids
    assert "NSC_DEBUG_OVERRIDES" in ids
    # NSC_NO_PIN_SET should NOT fire because there is a pin-set
    assert "NSC_NO_PIN_SET" not in ids


def test_clean_nsc_only_reports_informational_pin_present():
    tmp = tempfile.mkdtemp()
    p = os.path.join(tmp, "nsc.xml")
    _write(p, _NSC_CLEAN)
    findings = _parse_nsc(p)
    sev_by_id = {f.id: f.severity for f in findings}
    assert "NSC_CLEARTEXT_BASE" not in sev_by_id
    assert "NSC_USER_TRUST_ANCHORS" not in sev_by_id
    assert "NSC_PIN_SET_PRESENT" in sev_by_id
    assert sev_by_id["NSC_PIN_SET_PRESENT"] == "INFO"


def test_nsc_without_pin_set_emits_no_pin_set_finding():
    minimal = """<?xml version="1.0"?>
    <network-security-config>
      <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
          <certificates src="system"/>
        </trust-anchors>
      </base-config>
    </network-security-config>
    """
    tmp = tempfile.mkdtemp()
    p = os.path.join(tmp, "nsc.xml")
    _write(p, minimal)
    findings = _parse_nsc(p)
    assert any(f.id == "NSC_NO_PIN_SET" for f in findings)
