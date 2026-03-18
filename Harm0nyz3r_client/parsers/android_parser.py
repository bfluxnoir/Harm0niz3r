"""
parsers/android_parser.py
--------------------------
Parsers for Android package manager ('pm dump', 'pm list packages')
and activity manager ('am') output.

All public functions return dicts whose shape matches harmonyos_parser output
where possible, so platform-agnostic display code can work unchanged.
"""

import re
from typing import Optional


# ---------------------------------------------------------------------------
# App list  (adb shell pm list packages -f)
# ---------------------------------------------------------------------------

def parse_package_list(pm_output: str) -> list:
    """
    Parse 'adb shell pm list packages -f' output.

    Sample line:
        package:/data/app/~~abc==/com.example.app-XYZ==/base.apk=com.example.app

    Returns:
        [{"packageName": str, "apkPath": str}, ...]
    """
    packages = []
    for line in pm_output.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        body = line[len("package:"):]
        eq_idx = body.rfind("=")
        if eq_idx == -1:
            continue
        apk_path = body[:eq_idx]
        package_name = body[eq_idx + 1:]
        if package_name:
            packages.append({"packageName": package_name, "apkPath": apk_path})
    return packages


# ---------------------------------------------------------------------------
# Full package dump  (adb shell pm dump <package>)
# ---------------------------------------------------------------------------

def parse_pm_dump(dump_output: str, package_name: str) -> dict:
    """
    Parse 'adb shell pm dump <package>' output into a structured dict.

    Extracts:
      - versionName / versionCode / targetSdk / minSdk
      - debugMode / systemApp flags
      - requested permissions
      - granted (install + runtime) permissions
      - exported components with their intent filters

    Returns a dict compatible with harmonyos_parser.parse_app_dump_string():
        {
            "packageName": str,
            "debugMode": bool,
            "systemApp": bool,
            "versionName": str | None,
            "versionCode": int | None,
            "targetSdk": int | None,
            "minSdk": int | None,
            "requiredAppPermissions": [...],
            "grantedPermissions": [...],
            "exposedComponents": [
                {
                    "name": str,
                    "type": str,          # "Activity" | "Service" | "Receiver" | "Provider"
                    "visible": bool,      # True == exported=true
                    "permissionsRequired": [...],
                    "skills": [...],      # intent filters mapped to skill-like dicts
                    "authority": str,     # Provider only
                },
                ...
            ]
        }
    """
    result = {
        "packageName": package_name,
        "debugMode": False,
        "systemApp": False,
        "versionName": None,
        "versionCode": None,
        "targetSdk": None,
        "minSdk": None,
        "requiredAppPermissions": [],
        "grantedPermissions": [],
        "exposedComponents": [],
    }

    # --- Flags (debug / system) ---
    flags_match = re.search(r"flags=\[([^\]]*)\]", dump_output)
    if flags_match:
        flags_str = flags_match.group(1)
        result["debugMode"] = "DEBUGGABLE" in flags_str
        result["systemApp"] = "SYSTEM" in flags_str

    # --- Version info ---
    m = re.search(r"versionCode=(\d+)", dump_output)
    if m:
        result["versionCode"] = int(m.group(1))
    m = re.search(r"versionName=(\S+)", dump_output)
    if m:
        result["versionName"] = m.group(1)
    m = re.search(r"targetSdk=(\d+)", dump_output)
    if m:
        result["targetSdk"] = int(m.group(1))
    m = re.search(r"minSdk=(\d+)", dump_output)
    if m:
        result["minSdk"] = int(m.group(1))

    # --- Requested permissions ---
    req_block = re.search(
        r"requested permissions:(.*?)(?:\n\s{4}\S|\Z)", dump_output, re.DOTALL
    )
    if req_block:
        for perm in re.findall(r"android\.\S+|com\.\S+|org\.\S+", req_block.group(1)):
            if perm not in result["requiredAppPermissions"]:
                result["requiredAppPermissions"].append(perm)

    # --- Granted permissions (install + runtime) ---
    for block_name in ("install permissions", "runtime permissions"):
        block = re.search(
            rf"{block_name}:(.*?)(?:\n\s{{4}}\S|\Z)", dump_output, re.DOTALL
        )
        if block:
            for m in re.finditer(r"([\w.]+):\s*granted=true", block.group(1)):
                perm = m.group(1)
                if perm not in result["grantedPermissions"]:
                    result["grantedPermissions"].append(perm)

    # --- Exported components ---
    result["exposedComponents"] = _parse_components(dump_output, package_name)

    return result


# ---------------------------------------------------------------------------
# Component parsing helpers
# ---------------------------------------------------------------------------

def _parse_components(dump_output: str, package_name: str) -> list:
    """
    Extract Activities, Services, Receivers and Providers from 'pm dump' output,
    including export status, required permissions, and intent filters.
    """
    components = []

    for comp_type in ("Activities", "Services", "Receivers", "Providers"):
        singular = comp_type.rstrip("s") if comp_type != "Services" else "Service"
        # Match the section header and capture until the next top-level section
        section_pattern = re.compile(
            rf"^\s+{comp_type}:\s*\n(.*?)(?=^\s+\w+:|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        section = section_pattern.search(dump_output)
        if not section:
            continue

        section_text = section.group(1)

        # Each component entry starts with "    <packageName>/.<ClassName>:" or "    <fullClassName>:"
        comp_pattern = re.compile(
            rf"^\s+({re.escape(package_name)}/[\w.$]+|{re.escape(package_name)}\.[\w.$]+):",
            re.MULTILINE,
        )

        entries = list(comp_pattern.finditer(section_text))
        for idx, entry in enumerate(entries):
            comp_name = entry.group(1)
            # Normalise "com.example/.Foo" → "com.example.Foo"
            if "/" in comp_name:
                pkg, cls = comp_name.split("/", 1)
                if cls.startswith("."):
                    comp_name = pkg + cls
                else:
                    comp_name = cls

            # Grab this component's block (up to the next component entry)
            start = entry.end()
            end = entries[idx + 1].start() if idx + 1 < len(entries) else len(section_text)
            block = section_text[start:end]

            # exported flag
            exported_m = re.search(r"exported=(true|false)", block)
            exported = exported_m and exported_m.group(1) == "true"

            # permission required
            perm_m = re.search(r"permission=([\w.]+|null)", block)
            permission = []
            if perm_m and perm_m.group(1) != "null":
                permission = [perm_m.group(1)]

            # authority (Providers only)
            authority = None
            if comp_type == "Providers":
                auth_m = re.search(r"authority=([\w.,]+)", block)
                if auth_m:
                    authority = auth_m.group(1)

            # intent filters → skills
            skills = _parse_intent_filters(block)

            entry_dict = {
                "name": comp_name,
                "type": singular,
                "visible": bool(exported),
                "permissionsRequired": permission,
                "skills": skills,
            }
            if authority:
                entry_dict["authority"] = authority

            components.append(entry_dict)

    return components


def _parse_intent_filters(block: str) -> list:
    """
    Extract intent filters from a component block and map them to skill dicts
    (matching harmonyos_parser's 'skills' format):

        {"action": str, "entity": str, "scheme": str, "type": str}
    """
    skills = []

    # Each filter block starts with "IntentFilter:" or "filter"
    filter_blocks = re.split(r"(?:IntentFilter:|filter\s+\w+)", block)

    for fb in filter_blocks[1:]:  # skip everything before first filter
        skill: dict = {}

        action_m = re.search(r'Action:\s*"([^"]+)"', fb)
        if action_m:
            skill["action"] = action_m.group(1)

        category_m = re.search(r'Category:\s*"([^"]+)"', fb)
        if category_m:
            skill["entity"] = category_m.group(1)

        scheme_m = re.search(r'Scheme:\s*"([^"]+)"', fb)
        if scheme_m:
            skill["scheme"] = scheme_m.group(1)

        mime_m = re.search(r'Type:\s*"([^"]+)"', fb)
        if mime_m:
            skill["type"] = mime_m.group(1)

        if skill:
            skills.append(skill)

    return skills


# ---------------------------------------------------------------------------
# App surface wrapper  (matches harmonyos_parser.parse_app_dump_string() API)
# ---------------------------------------------------------------------------

def parse_app_surface(dump_output: str, package_name: str) -> dict:
    """
    Build the full attack surface dict from 'pm dump <package>' output.
    Returns the same dict shape as harmonyos_parser.parse_app_dump_string().
    """
    return parse_pm_dump(dump_output, package_name)


# ---------------------------------------------------------------------------
# Visible / exported activities  (adb shell pm query-activities)
# ---------------------------------------------------------------------------

def parse_query_activities(pm_query_output: str) -> list:
    """
    Parse 'adb shell pm query-activities -a <action>' output.

    Sample output:
        Activity Resolver Table:
          Non-Data Actions:
            android.intent.action.VIEW:
              3fe45a com.example.app/.BrowserActivity filter abc123
                Action: "android.intent.action.VIEW"
                Category: "android.intent.category.BROWSABLE"

    Returns:
        [{"packageName": str, "activityName": str, "action": str}, ...]
    """
    results = []
    comp_pattern = re.compile(
        r"^\s+\w+\s+([\w.]+)/(\.?[\w.$]+)\s+filter", re.MULTILINE
    )
    for m in comp_pattern.finditer(pm_query_output):
        pkg = m.group(1)
        cls = m.group(2)
        if cls.startswith("."):
            full_name = pkg + cls
        else:
            full_name = cls
        results.append({
            "packageName": pkg,
            "activityName": full_name,
        })
    return results


# ---------------------------------------------------------------------------
# Content provider query  (adb shell content query --uri ...)
# ---------------------------------------------------------------------------

def parse_content_query(content_output: str, uri: str) -> dict:
    """
    Parse 'adb shell content query --uri <uri>' output.

    Sample output:
        Row: 0 _id=1, name=admin, password=secret
        Row: 1 _id=2, name=user, password=123456

    Returns:
        {"uri": str, "rows": [{"_id": ..., ...}, ...]}
    """
    rows = []
    for line in content_output.splitlines():
        line = line.strip()
        if not line.startswith("Row:"):
            continue
        # Strip the "Row: N " prefix
        row_body = re.sub(r"^Row:\s*\d+\s*", "", line)
        row = {}
        for field in row_body.split(", "):
            if "=" in field:
                key, _, value = field.partition("=")
                row[key.strip()] = value.strip()
        if row:
            rows.append(row)

    return {"uri": uri, "rows": rows}
