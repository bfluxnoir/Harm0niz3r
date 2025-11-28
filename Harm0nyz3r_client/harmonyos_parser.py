import json
import re

def parse_app_dump_string(dump_string: str) -> dict:
    """
    Parses a single HarmonyOS app dump string (from hdc bm dump -n <namespace>)
    into a structured dictionary containing relevant app information.

    Args:
        dump_string: The raw string content of a single app dump file.

    Returns:
        A dictionary representing the parsed app information.

    Raises:
        ValueError: If the dump string format is invalid or JSON parsing fails.
    """
    # Ensure dump_string is not None or empty before processing
    if not dump_string or not isinstance(dump_string, str):
        raise ValueError("Input dump_string is empty or not a string.")

    # Split the string by the first newline to separate bundle name line from JSON content
    lines = dump_string.strip().split('\n', 1)
    if len(lines) < 2:
        # This can happen if the dump_string is just the bundle name line or empty after strip
        raise ValueError(f"Invalid dump string format: expected at least two lines (bundle name and JSON content). Received: '{dump_string.strip()}'")

    bundle_name_line = lines[0]
    json_content_str = lines[1]

    # Extract bundleName (e.g., "com.dekra.dvha:")
    match = re.match(r'([^:]+):', bundle_name_line)
    if not match:
        # This is the most likely place for the 'NoneType' error if bundle_name_line doesn't match
        raise ValueError(f"Could not parse bundle name from: '{bundle_name_line}'. Expected format 'bundle.name:{{...}}'")
    bundle_name = match.group(1).strip()

    # Parse the main JSON content
    try:
        app_data = json.loads(json_content_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON content for {bundle_name}: {e}\nContent snippet:\n{json_content_str[:500]}...")

    result = {
        "bundleName": bundle_name,
        "debugMode": app_data.get("applicationInfo", {}).get("debug", False),
        "systemApp": app_data.get("applicationInfo", {}).get("isSystemApp", False),
        "requiredAppPermissions": app_data.get("reqPermissions", []), # ADDED: Extract top-level required permissions
        "exposedComponents": []
    }

    # Helper function to extract and format skills
    def extract_skills(skills_list):
        parsed_skills = []
        if not isinstance(skills_list, list): # Ensure skills_list is a list
            return parsed_skills

        for skill_info in skills_list:
            if not isinstance(skill_info, dict): # Ensure each skill_info is a dictionary
                continue

            skill_dict = {}
            # Safely get list items and check if they are not empty
            actions = skill_info.get("actions")
            if isinstance(actions, list) and actions:
                skill_dict["action"] = actions[0]

            entities = skill_info.get("entities")
            if isinstance(entities, list) and entities:
                skill_dict["entity"] = entities[0]
            
            uris = skill_info.get("uris")
            if isinstance(uris, list) and uris:
                # Extract scheme, type, and utd from the first URI if present
                uri_info = uris[0]
                if isinstance(uri_info, dict): # Ensure uri_info is a dictionary
                    if "scheme" in uri_info:
                        skill_dict["scheme"] = uri_info["scheme"]
                    if "type" in uri_info:
                        skill_dict["type"] = uri_info["type"]
                    utd = uri_info.get("utd")
                    if isinstance(utd, list) and utd:
                        skill_dict["utd"] = utd

            if skill_dict: # Only add to parsed_skills if any relevant data was extracted
                parsed_skills.append(skill_dict)
        return parsed_skills

    # Mapping for integer extension types to string names (based on HarmonyOS docs and common patterns)
    extension_type_map = {
        0: "form",
        1: "widget",
        2: "service",
        3: "backup",
        4: "accessibility",
        5: "dataShare",
        6: "staticSubscriber",
        7: "wallpaper",
        8: "notification",
        9: "fileAccess",
        10: "dataClean",
        11: "commonEvent",
        12: "inputMethod",
        13: "sysDialog/common",
        14: "sys/visualExtension",
        15: "sys/commonUI",
        500: "UIExtensionAbility"
    }

    # Iterate through hapModuleInfos to find abilities and extensions
    hap_module_infos = app_data.get("hapModuleInfos", [])
    if not isinstance(hap_module_infos, list): # Ensure hapModuleInfos is a list
        hap_module_infos = []

    for module_info in hap_module_infos:
        if not isinstance(module_info, dict): # Ensure each module_info is a dictionary
            continue

        # Process 'abilityInfos' nested within each module
        ability_infos = module_info.get("abilityInfos", [])
        if not isinstance(ability_infos, list): # Ensure abilityInfos is a list
            ability_infos = []

        for ability in ability_infos:
            if not isinstance(ability, dict): # Ensure each ability is a dictionary
                continue

            component = {
                "name": ability.get("name"),
                "type": "Ability",
                "visible": ability.get("visible", False),
                "permissionsRequired": ability.get("permissions", []),
                "skills": extract_skills(ability.get("skills", []))
            }
            result["exposedComponents"].append(component)

        # Process 'extensionInfos' nested within each module
        extension_infos = module_info.get("extensionInfos", [])
        if not isinstance(extension_infos, list): # Ensure extensionInfos is a list
            extension_infos = []

        for extension in extension_infos:
            if not isinstance(extension, dict): # Ensure each extension is a dictionary
                continue

            ext_type_name_str = extension.get("typeName")
            if not ext_type_name_str:
                ext_type_name_str = extension_type_map.get(extension.get("type"), f"unknown_ext_type_{extension.get('type')}")

            component = {
                "name": extension.get("name"),
                "type": f"Extension ({ext_type_name_str})",
                "visible": extension.get("visible", False),
                "permissionsRequired": extension.get("permissions", []),
                "skills": extract_skills(extension.get("skills", []))
            }
            # NEW: Add dataShareUri if available and it's a dataShare type
            if ext_type_name_str == "dataShare" and "uri" in extension:
                component["dataShareUri"] = extension["uri"]

            result["exposedComponents"].append(component)

    return result
