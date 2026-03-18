"""
parsers/ios_parser.py
----------------------
Parsers for iOS application metadata.

Phase 3 will fill out all the parsing logic here.
"""

import plistlib
from typing import Optional


# ---------------------------------------------------------------------------
# App list  (pymobiledevice3 / ideviceinstaller -l)
# ---------------------------------------------------------------------------

def parse_app_list(raw_output: str) -> list:
    """
    Parse app list output from ideviceinstaller or pymobiledevice3.

    TODO (Phase 3): Full implementation.

    Returns:
        List of dicts: [{"bundleId": str, "name": str, "version": str}, ...]
    """
    apps = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        # ideviceinstaller format: com.example.app, AppName, 1.0
        parts = [p.strip() for p in line.split(",", 2)]
        if len(parts) >= 1:
            entry = {"bundleId": parts[0]}
            if len(parts) >= 2:
                entry["name"] = parts[1]
            if len(parts) >= 3:
                entry["version"] = parts[2]
            apps.append(entry)
    return apps


# ---------------------------------------------------------------------------
# App info  (Info.plist extracted via AFC / pymobiledevice3)
# ---------------------------------------------------------------------------

def parse_info_plist(plist_data: bytes, bundle_id: str) -> dict:
    """
    Parse an iOS app's Info.plist binary/XML into a structured dict.

    TODO (Phase 3): Full implementation — extract:
      - CFBundleIdentifier, CFBundleVersion, CFBundleShortVersionString
      - NSAppTransportSecurity (ATS) settings
      - URL schemes (CFBundleURLTypes → CFBundleURLSchemes)
      - exported document types (CFBundleDocumentTypes)
      - background modes (UIBackgroundModes)
      - entitlements (from embedded.mobileprovision or ldid)

    Returns:
        Parsed app info dict.
    """
    result = {
        "bundleId": bundle_id,
        "debugMode": False,
        "systemApp": False,
        "requiredAppPermissions": [],
        "exposedComponents": [],
    }

    try:
        plist = plistlib.loads(plist_data)
    except Exception:
        return result

    result["bundleId"] = plist.get("CFBundleIdentifier", bundle_id)

    # URL schemes → analogous to HarmonyOS skills/intents
    url_types = plist.get("CFBundleURLTypes", [])
    for url_type in url_types:
        schemes = url_type.get("CFBundleURLSchemes", [])
        for scheme in schemes:
            result["exposedComponents"].append({
                "name": url_type.get("CFBundleURLName", scheme),
                "type": "URLScheme",
                "visible": True,
                "permissionsRequired": [],
                "skills": [{"scheme": scheme}],
            })

    # Privacy permission keys
    privacy_keys = [
        "NSCameraUsageDescription",
        "NSMicrophoneUsageDescription",
        "NSLocationWhenInUseUsageDescription",
        "NSContactsUsageDescription",
        "NSPhotoLibraryUsageDescription",
    ]
    for key in privacy_keys:
        if key in plist:
            result["requiredAppPermissions"].append(key)

    return result
