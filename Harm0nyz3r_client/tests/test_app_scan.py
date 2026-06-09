"""Tests for commands/android/app_scan.py."""

import json

from commands.android.app_scan import (
    _run_scan, _score, _rate, _counts,
    _render_console, _render_json,
)


_HIGH_RISK_PARSED = {
    "packageName": "com.example.weak",
    "versionName": "1.0.0",
    "versionCode": 1,
    "targetSdk": 28,
    "minSdk": 21,
    "debugMode": True,
    "systemApp": False,
    "requestedAppPermissions": [
        "android.permission.CAMERA",
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET",
    ],
    "grantedPermissions": [
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
    ],
    "exposedComponents": [
        {
            "name": "com.example.weak.LoginActivity",
            "type": "Activity",
            "visible": True,
            "permissionsRequired": [],
            "skills": [{"action": "android.intent.action.VIEW", "scheme": "myapp"}],
        },
        {
            "name": "com.example.weak.UserProvider",
            "type": "Provider",
            "visible": True,
            "permissionsRequired": [],
            "skills": [],
            "authority": "com.example.weak.users",
        },
        {
            "name": "com.example.weak.UpdateReceiver",
            "type": "Receiver",
            "visible": True,
            "permissionsRequired": [],
            "skills": [],
        },
        {
            "name": "com.example.weak.GuardedActivity",
            "type": "Activity",
            "visible": True,
            "permissionsRequired": ["com.example.SECURE"],
            "skills": [],
        },
    ],
}

_HIGH_RISK_RAW = (
    "flags=[ HAS_CODE ALLOW_BACKUP DEBUGGABLE ALLOW_CLEAR_USER_DATA ] "
    "usesCleartextTraffic=true"
)


def test_high_risk_app_triggers_all_expected_findings():
    findings = _run_scan(_HIGH_RISK_PARSED, _HIGH_RISK_RAW)
    ids = {f.id for f in findings}
    expected = {
        "ALLOW_BACKUP_FLAG",
        "CLEARTEXT_TRAFFIC",
        "DANGEROUS_PERMS_GRANTED",
        "DANGEROUS_PERMS_REQUESTED",
        "DEBUGGABLE_FLAG",
        "DEEPLINK_HANDLERS",
        "EXPORTED_ACTIVITY_NO_PERM",
        "EXPORTED_PROVIDER_NO_PERM",
        "EXPORTED_RECEIVER_NO_PERM",
        "OUTDATED_TARGET_SDK",
    }
    assert ids == expected
    # GuardedActivity must NOT produce a finding because it has a permission.
    assert not any(
        "GuardedActivity" in (f.evidence or "") for f in findings
    )


def test_high_risk_app_rates_critical_or_high():
    findings = _run_scan(_HIGH_RISK_PARSED, _HIGH_RISK_RAW)
    score = _score(findings)
    rating = _rate(score)
    assert score >= 10
    assert rating in ("CRITICAL", "HIGH")


def test_clean_app_yields_zero_score():
    parsed = dict(_HIGH_RISK_PARSED)
    parsed["debugMode"] = False
    parsed["targetSdk"] = 34
    parsed["requestedAppPermissions"] = []
    parsed["grantedPermissions"] = []
    parsed["exposedComponents"] = []
    findings = _run_scan(parsed, "flags=[ HAS_CODE ]")
    assert _score(findings) == 0
    assert _rate(0) == "CLEAN"


def test_json_render_round_trips():
    findings = _run_scan(_HIGH_RISK_PARSED, _HIGH_RISK_RAW)
    payload = _render_json(_HIGH_RISK_PARSED, findings)
    data = json.loads(payload)
    assert data["package"] == "com.example.weak"
    assert data["rating"] in ("CRITICAL", "HIGH")
    assert any(
        f["id"] == "EXPORTED_PROVIDER_NO_PERM" and f["severity"] == "HIGH"
        for f in data["findings"]
    )


def test_console_render_mentions_top_findings():
    findings = _run_scan(_HIGH_RISK_PARSED, _HIGH_RISK_RAW)
    out = _render_console(_HIGH_RISK_PARSED, findings)
    assert "APP SCAN" in out
    assert "DEBUGGABLE_FLAG" in out
    assert "EXPORTED_PROVIDER_NO_PERM" in out


def test_counts_structure():
    findings = _run_scan(_HIGH_RISK_PARSED, _HIGH_RISK_RAW)
    counts = _counts(findings)
    assert set(counts) == {"HIGH", "MEDIUM", "LOW", "INFO"}
    assert sum(counts.values()) == len(findings)
