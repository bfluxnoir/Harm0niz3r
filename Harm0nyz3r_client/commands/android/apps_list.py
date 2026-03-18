# commands/android/apps_list.py
import json
from typing import List

from commands.base import Command, CommandSource
from parsers.android_parser import parse_package_list


class AndroidAppsListCommand(Command):
    @property
    def name(self) -> str:
        return "apps_list"

    @property
    def aliases(self) -> List[str]:
        return ["packages"]

    def help(self) -> str:
        return (
            "apps_list [-a] [-3]   – List installed packages via 'pm list packages'\n"
            "  -3   Third-party packages only\n"
            "  -a   Send results to the Android agent (if connected)"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        send_to_app = source == "app"
        third_party_only = False

        if "-3" in args:
            third_party_only = True
            args = [a for a in args if a != "-3"]
        if "-a" in args:
            send_to_app = True
            args = [a for a in args if a != "-a"]

        if args:
            console._print_message("INFO", "Usage: apps_list [-3] [-a]")
            return

        if send_to_app and not console.connected:
            console._print_message("WARNING", "Not connected to agent. Printing to console.")
            send_to_app = False

        pm_args = ["pm", "list", "packages", "-f"]
        if third_party_only:
            pm_args.append("-3")

        stdout, stderr, retcode = console._get_hdc_shell_output(pm_args)

        if retcode != 0:
            console._print_message("ERROR", f"pm list packages failed: {stderr or 'no output'}")
            return

        packages = parse_package_list(stdout)

        if send_to_app and console.connected:
            payload = json.dumps([p["packageName"] for p in packages])
            console.send_data_to_app(f"HDC_OUTPUT_ALL_APPS:{payload}")
            console._print_message("INFO", f"Sent {len(packages)} packages to agent.")
        else:
            print(f"\n--- Installed Packages ({len(packages)}) ---")
            for p in packages:
                print(f"  {p['packageName']}")
            print("--------------------------------------------\n")


def register(registry_func):
    registry_func(AndroidAppsListCommand())
