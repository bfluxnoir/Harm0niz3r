"""Tests for parsers/android_parser.py."""

from parsers.android_parser import (
    parse_pm_dump,
    parse_package_list,
    parse_content_query,
    parse_query_activities,
    looks_thin,
    thin_warning,
    _parse_intent_filters,
)


# ---------------------------------------------------------------------------
# parse_pm_dump
# ---------------------------------------------------------------------------

def test_stock_pm_dump_parses_cleanly():
    stock = """
        Package [com.example.app]:
          versionCode=42
          versionName=1.2.3
          targetSdk=33
          minSdk=24
          flags=[ DEBUGGABLE ALLOW_BACKUP ]
          requested permissions:
            android.permission.INTERNET
            android.permission.CAMERA
          install permissions:
            android.permission.INTERNET: granted=true
    """
    parsed = parse_pm_dump(stock, "com.example.app")
    assert parsed["versionName"] == "1.2.3"
    assert parsed["versionCode"] == 42
    assert parsed["targetSdk"] == 33
    assert parsed["minSdk"] == 24
    assert parsed["debugMode"] is True
    assert "android.permission.INTERNET" in parsed["requestedAppPermissions"]
    assert "android.permission.CAMERA" in parsed["requestedAppPermissions"]
    assert "android.permission.INTERNET" in parsed["grantedPermissions"]
    assert not looks_thin(parsed)


def test_alternative_field_spellings():
    """OEMs sometimes emit targetSdkVersion / minSdkVersion."""
    alt = """
        Package [com.x.y]:
          versionCode=7
          versionName=9.9
          targetSdkVersion=34
          minSdkVersion=26
          requested permissions:
            androidx.lifecycle.SOMETHING
            org.test.LEGACY
    """
    parsed = parse_pm_dump(alt, "com.x.y")
    assert parsed["targetSdk"] == 34
    assert parsed["minSdk"] == 26
    assert "androidx.lifecycle.SOMETHING" in parsed["requestedAppPermissions"]
    assert "org.test.LEGACY" in parsed["requestedAppPermissions"]


def test_vendor_array_form_requested_permissions():
    """Some vendor builds emit the requested permissions inline as [a, b, c]."""
    array = """
        Package [com.vendor.app]:
          versionName=2.0
          targetSdk=33
          requested permissions: [android.permission.INTERNET, android.permission.BLUETOOTH]
    """
    parsed = parse_pm_dump(array, "com.vendor.app")
    assert "android.permission.INTERNET" in parsed["requestedAppPermissions"]
    assert "android.permission.BLUETOOTH" in parsed["requestedAppPermissions"]


# ---------------------------------------------------------------------------
# looks_thin / thin_warning
# ---------------------------------------------------------------------------

def test_looks_thin_true_for_empty_dump():
    parsed = parse_pm_dump("", "com.empty")
    assert looks_thin(parsed)


def test_looks_thin_true_for_useless_dump():
    parsed = parse_pm_dump("Package [com.thin]: (no useful data)", "com.thin")
    assert looks_thin(parsed)


def test_thin_warning_text_mentions_agent_path():
    msg = thin_warning("com.x", "app_info")
    assert "com.x" in msg
    assert "agent_exec" in msg
    assert "--via-agent" in msg


# ---------------------------------------------------------------------------
# Intent filters (B10 enrichment)
# ---------------------------------------------------------------------------

def test_intent_filters_extract_host_and_path():
    block = """
        com.example.app/.LoginActivity:
          filter 67890def
            Action: "android.intent.action.VIEW"
            Category: "android.intent.category.DEFAULT"
            Category: "android.intent.category.BROWSABLE"
            Scheme: "https"
            Authority: "login.example.com": -1
            Path: "PatternMatcher{LITERAL: /panel}"
          filter aaaabbbb
            Action: "android.intent.action.VIEW"
            Scheme: "myapp"
            Authority: "admin": -1
            Path: "PatternMatcher{PREFIX: /v1}"
    """
    skills = _parse_intent_filters(block)
    assert len(skills) == 2

    https = skills[0]
    assert https["action"] == "android.intent.action.VIEW"
    assert https["scheme"] == "https"
    assert https["host"] == "login.example.com"
    assert https["path"] == "/panel"
    assert https["pathType"] == "LITERAL"
    assert "android.intent.category.BROWSABLE" in https["categories"]

    custom = skills[1]
    assert custom["scheme"] == "myapp"
    assert custom["host"] == "admin"
    assert custom["pathType"] == "PREFIX"


# ---------------------------------------------------------------------------
# parse_package_list
# ---------------------------------------------------------------------------

def test_parse_package_list_extracts_pairs():
    sample = (
        "package:/data/app/~~abc==/com.example.a-XYZ==/base.apk=com.example.a\n"
        "package:/data/app/~~def==/com.example.b-WPQ==/base.apk=com.example.b\n"
    )
    packages = parse_package_list(sample)
    names = sorted(p["packageName"] for p in packages)
    assert names == ["com.example.a", "com.example.b"]


# ---------------------------------------------------------------------------
# parse_content_query
# ---------------------------------------------------------------------------

def test_parse_content_query_rows():
    out = (
        "Row: 0 _id=1, name=admin, password=secret\n"
        "Row: 1 _id=2, name=user, password=hunter2\n"
    )
    parsed = parse_content_query(out, "content://x/users")
    assert parsed["uri"] == "content://x/users"
    assert len(parsed["rows"]) == 2
    assert parsed["rows"][0]["name"] == "admin"
    assert parsed["rows"][1]["password"] == "hunter2"


# ---------------------------------------------------------------------------
# parse_query_activities
# ---------------------------------------------------------------------------

def test_parse_query_activities_basic():
    sample = (
        "Activity Resolver Table:\n"
        "  Non-Data Actions:\n"
        "    android.intent.action.VIEW:\n"
        "        3fe45a com.example.app/.Browser filter abc\n"
        "          Action: \"android.intent.action.VIEW\"\n"
    )
    rows = parse_query_activities(sample)
    assert any(
        r["packageName"] == "com.example.app" and r["activityName"] == "com.example.app.Browser"
        for r in rows
    )
