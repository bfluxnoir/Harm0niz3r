# commands/android/app_surface.py
import json
import re
from typing import List

from commands.base import Command, CommandSource
from parsers.android_parser import parse_app_surface


def format_app_surface_for_console(parsed: dict) -> str:
    lines = []
    pkg = parsed.get("packageName", "UNKNOWN")
    lines.append(f"App Surface: {pkg}")
    lines.append("=" * (len(lines[-1])))

    components = parsed.get("exposedComponents", [])
    if not components:
        lines.append("No exported components found.")
    else:
        for comp in components:
            ctype = comp.get("type", "UNKNOWN")
            name = comp.get("name", "UNKNOWN")
            visible = comp.get("visible", False)
            perms = comp.get("permissionsRequired", [])
            skills = comp.get("skills", [])
            authority = comp.get("authority")

            lines.append(f"\n[{ctype}] {name}")
            lines.append(f"  Exported    : {visible}")
            lines.append(f"  Permission  : {', '.join(perms) if perms else '(none)'}")
            if authority:
                lines.append(f"  Authority   : {authority}")
            if skills:
                lines.append("  Intent Filters:")
                for s in skills:
                    kv = " ".join(f"{k}={v}" for k, v in s.items() if v)
                    lines.append(f"    - {kv}")
            else:
                lines.append("  Intent Filters: (none)")

    return "\n".join(lines)


class AndroidAppSurfaceCommand(Command):
    @property
    def name(self) -> str:
        return "app_surface"

    def help(self) -> str:
        return (
            "app_surface <package> [-a]\n"
            "  Parse 'pm dump <package>' and show exported components.\n"
            "  -a  Send parsed JSON to the Android agent."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        send_to_app = source == "app"

        if "-a" in args:
            send_to_app = True
            args = [a for a in args if a != "-a"]

        if len(args) != 1:
            console._print_message("INFO", "Usage: app_surface <package> [-a]")
            return

        package = args[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: '{package}'")
            return

        if send_to_app and not console.connected:
            console._print_message("WARNING", "Not connected to agent. Printing to console.")
            send_to_app = False

        stdout, stderr, retcode = console._get_hdc_shell_output(["pm", "dump", package])

        if retcode != 0 or not stdout:
            err = stderr or "no output"
            console._print_message("ERROR", f"pm dump failed: {err}")
            if send_to_app and console.connected:
                console.send_data_to_app(f"HDC_OUTPUT_ERROR:{err}")
            return

        parsed = parse_app_surface(stdout, package)

        if send_to_app and console.connected:
            console.send_data_to_app(f"HDC_OUTPUT_APP_SURFACE_JSON:{json.dumps(parsed)}")
            console._print_message("INFO", f"App surface sent to agent for {package}.")
        else:
            print(f"\n{format_app_surface_for_console(parsed)}\n")


def register(registry_func):
    registry_func(AndroidAppSurfaceCommand())
