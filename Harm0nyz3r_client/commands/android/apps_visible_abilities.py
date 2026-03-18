# commands/android/apps_visible_abilities.py
import json
from typing import List

from commands.base import Command, CommandSource
from parsers.android_parser import parse_package_list, parse_pm_dump


def _extract_exported_activities(console, send_to_app: bool = False) -> None:
    """
    Enumerate all packages, parse pm dump for each, and collect exported
    Activities that have no required permission (analogous to HarmonyOS
    apps_visible_abilities).
    """
    if not console.hdc_device_id:
        console._print_message("ERROR", "No Android device connected via adb.")
        return

    console._print_message("INFO", "Fetching package list...")
    stdout, stderr, retcode = console._get_hdc_shell_output(
        ["pm", "list", "packages", "-f", "-3"]  # third-party only for speed
    )
    if retcode != 0 or not stdout:
        console._print_message("ERROR", f"pm list packages failed: {stderr or 'no output'}")
        return

    packages = [p["packageName"] for p in parse_package_list(stdout)]
    console._print_message("INFO", f"Found {len(packages)} third-party packages. Scanning...")

    exported_activities = []

    for pkg in packages:
        app_stdout, _, app_ret = console._get_hdc_shell_output(["pm", "dump", pkg])
        if app_ret != 0 or not app_stdout:
            continue
        try:
            parsed = parse_pm_dump(app_stdout, pkg)
        except Exception:
            continue

        for comp in parsed.get("exposedComponents", []):
            if (
                comp.get("type") == "Activity"
                and comp.get("visible") is True
                and not comp.get("permissionsRequired")
            ):
                exported_activities.append({
                    "app": pkg,
                    "activity": comp.get("name"),
                    "skills": comp.get("skills", []),
                })

    print(f"\n=== Exported Activities (no permission required) ===")
    print(f"Total: {len(exported_activities)}")
    for item in exported_activities:
        print(f"\n  App     : {item['app']}")
        print(f"  Activity: {item['activity']}")
        if item["skills"]:
            print("  Intent Filters:")
            for s in item["skills"]:
                kv = " ".join(f"{k}={v}" for k, v in s.items() if v)
                print(f"    - {kv}")

    if send_to_app and console.connected:
        console.send_data_to_app(
            "HDC_OUTPUT_EXPOSED_ABILITIES:"
            + json.dumps(exported_activities, ensure_ascii=False)
        )
        console._print_message("INFO", f"Sent {len(exported_activities)} activities to agent.")


class AndroidAppsVisibleAbilitiesCommand(Command):
    @property
    def name(self) -> str:
        return "apps_visible_abilities"

    def help(self) -> str:
        return (
            "apps_visible_abilities [-a]\n"
            "  List exported Activities with no permission requirement.\n"
            "  Scans all third-party packages via 'pm dump'. May take a while.\n"
            "  -a  Send results to the Android agent."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        send_to_app = source == "app"
        if "-a" in args:
            send_to_app = True
            args = [a for a in args if a != "-a"]

        if args:
            console._print_message("INFO", "Usage: apps_visible_abilities [-a]")
            return

        if send_to_app and not console.connected:
            console._print_message("WARNING", "Not connected to agent.")
            send_to_app = False

        _extract_exported_activities(console, send_to_app=send_to_app)


def register(registry_func):
    registry_func(AndroidAppsVisibleAbilitiesCommand())
