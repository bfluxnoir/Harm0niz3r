# commands/android/app_info.py
import json
import re
from typing import List

from commands.base import Command, CommandSource
from parsers.android_parser import parse_pm_dump, looks_thin, thin_warning


class AndroidAppInfoCommand(Command):
    @property
    def name(self) -> str:
        return "app_info"

    def help(self) -> str:
        return "app_info <package> [-a]   – Show info for a package via 'pm dump <package>'"

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        send_to_app = source == "app"

        if "-a" in args:
            send_to_app = True
            args = [a for a in args if a != "-a"]

        if len(args) != 1:
            console._print_message("INFO", "Usage: app_info <package> [-a]")
            return

        package = args[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: '{package}'")
            return

        if send_to_app and not console.connected:
            console._print_message("WARNING", "Not connected to agent. Printing to console.")
            send_to_app = False

        stdout, stderr, retcode = console._run_shell(["pm", "dump", package])

        if retcode != 0 or not stdout:
            console._print_message("ERROR", f"pm dump failed: {stderr or 'no output'}")
            if send_to_app and console.connected:
                console.send_data_to_app(f"ERROR_RESULT:pm dump failed for {package}")
            return

        parsed = parse_pm_dump(stdout, package)
        if looks_thin(parsed):
            console._print_message("WARNING", thin_warning(package, "app_info"))

        if send_to_app and console.connected:
            console.send_data_to_app(f"APP_INFO_RESULT:{json.dumps(parsed)}")
        else:
            print(f"\n--- App Info: {package} ---")
            print(f"  Version    : {parsed.get('versionName')} (code {parsed.get('versionCode')})")
            print(f"  Target SDK : {parsed.get('targetSdk')}   Min SDK: {parsed.get('minSdk')}")
            print(f"  Debug      : {parsed.get('debugMode')}")
            print(f"  System App : {parsed.get('systemApp')}")
            perms = parsed.get("requestedAppPermissions", [])
            print(f"  Permissions: {len(perms)}")
            for p in perms:
                print(f"    - {p}")
            print("----------------------------\n")


def register(registry_func):
    registry_func(AndroidAppInfoCommand())
