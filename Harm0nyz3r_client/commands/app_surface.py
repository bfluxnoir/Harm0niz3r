# commands/app_surface.py
import json
import re
from typing import List

from .base import Command, CommandSource
from harmonyos_parser import parse_app_dump_string


def format_app_surface_for_console(parsed_data: dict) -> str:
    """
    Convert the parsed app surface (from parse_app_dump_string) into a
    human-readable string for console output.

    This replaces the old HarmonyOSClientConsole._format_app_surface_for_console.

    You can adapt this to match exactly what you had before.
    """
    # ----- Simple example implementation -----
    lines: List[str] = []

    bundle_name = parsed_data.get("bundleName", "UNKNOWN_BUNDLE")
    lines.append(f"App Surface for: {bundle_name}")
    lines.append("=" * (len(lines[-1])))

    # Exposed components (abilities, extensions, etc.)
    exposed = parsed_data.get("exposedComponents", [])
    if not exposed:
        lines.append("No exposed components found.")
    else:
        for comp in exposed:
            if not isinstance(comp, dict):
                continue

            ctype = comp.get("type", "UNKNOWN").title()
            name = comp.get("name", "UNKNOWN")
            visible = comp.get("visible")
            perms = comp.get("permissionsRequired", [])
            skills = comp.get("skills", [])

            lines.append(f"\n[{ctype}] {name}")
            lines.append(f"  Visible          : {visible}")
            lines.append(
                "  Permissions      : "
                + (", ".join(perms) if perms else "(none)")
            )

            if skills:
                lines.append("  Skills (intent filters):")
                for skill in skills:
                    if isinstance(skill, dict):
                        # key=value key2=value2 ...
                        kv_str = " ".join(
                            f"{k}={v}" for k, v in skill.items() if v
                        )
                        lines.append(f"    - {kv_str}")
            else:
                lines.append("  Skills (intent filters): (none)")

    return "\n".join(lines)

    # If you had a more elaborate version, just paste its logic instead
    # and return the final string.


class AppSurfaceCommand(Command):
    @property
    def name(self) -> str:
        return "app_surface"

    @property
    def supports_logging(self) -> bool:
        # No logging wrapper for this command (unless you want it)
        return False

    def help(self) -> str:
        return (
            "app_surface <namespace> [-a]\n"
            "  Parse 'bm dump -n <namespace>' and show exposed components.\n"
            "  With -a, send parsed JSON to the HarmonyOS app; otherwise, show\n"
            "  a human-readable summary in this console."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Usage (CLI):
          app_surface <namespace> [-a]

        From the app:
          app_surface <namespace>

        Behaviour:
          - Runs: bm dump -n <namespace>
          - If '-a' or from app: sends JSON to app (HDC_OUTPUT_APP_SURFACE_JSON)
          - Else: prints human-readable summary to console via
                  format_app_surface_for_console().
        """
        send_to_app = False

        # --------------------
        # Argument parsing
        # --------------------
        if source == "app":
            # From app: expect exactly one arg: namespace
            if len(args) != 1:
                error_msg = (
                    "Invalid app_surface command from app: Expected <namespace>. "
                    "Usage: app_surface <namespace>"
                )
                console._print_message("ERROR", error_msg)
                console.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
                return

            namespace = args[0]
            send_to_app = True  # For app-originated, we always send results back

        else:
            # CLI: handle optional '-a' flag
            if "-a" in args:
                send_to_app = True
                args = [a for a in args if a != "-a"]

            if len(args) != 1:
                console._print_message(
                    "INFO",
                    "Usage: app_surface <namespace> [-a]"
                )
                return

            namespace = args[0]

        # --------------------
        # Basic validation
        # --------------------
        if not re.match(r"^[a-zA-Z0-9._-]+$", namespace):
            msg = f"Invalid namespace format: '{namespace}'."
            console._print_message("ERROR", msg)
            if source == "app":
                console.send_data_to_app(f"HDC_OUTPUT_ERROR:{msg}")
            return

        # If we want to send to app but not connected, fall back to console-only
        if send_to_app and not console.connected:
            console._print_message(
                "WARNING",
                "Not connected to HarmonyOS app. Printing human-readable output to console instead."
            )
            send_to_app = False

        # --------------------
        # Execute HDC command
        # --------------------
        stdout, stderr, retcode = console._get_hdc_shell_output(
            ["bm", "dump", "-n", namespace]
        )

        if retcode == 0 and stdout:
            # Try to parse app dump
            try:
                parsed_data = parse_app_dump_string(stdout)
            except Exception as e:
                error_msg = f"Error parsing app dump for {namespace}: {e}"
                console._print_message("ERROR", error_msg)
                if send_to_app and console.connected:
                    console.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
                else:
                    print(
                        f"\n--- Error parsing app surface for {namespace} ---\n"
                        f"{error_msg}\n"
                        "-----------------------------------\n"
                    )
                return

            # Decide whether to send JSON to app or print to console
            if send_to_app and console.connected:
                try:
                    json_output = json.dumps(parsed_data, indent=2)
                    console._print_message(
                        "INFO",
                        f"Sending parsed app surface JSON to HarmonyOS app for {namespace}."
                    )
                    console.send_data_to_app(
                        f"HDC_OUTPUT_APP_SURFACE_JSON:{json_output}"
                    )
                except ValueError as e:
                    error_msg = (
                        f"Error converting parsed app surface to JSON for "
                        f"{namespace}: {e}"
                    )
                    console._print_message("ERROR", error_msg)
                    console.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
            else:
                # Human-readable console output using local helper
                human_readable_output = format_app_surface_for_console(parsed_data)
                console._print_message(
                    "INFO",
                    f"Output will be printed to this console (human-readable format) for {namespace}."
                )
                print(
                    f"\n{human_readable_output}\n"
                    "-----------------------------------\n"
                )

        else:
            # Error running bm dump
            error_msg = (
                stderr
                if stderr
                else f"HDC command failed or returned no output for {namespace} "
                     f"(exit code: {retcode})."
            )
            console._print_message(
                "ERROR",
                f"HDC command for app_surface failed: {error_msg}"
            )
            if send_to_app and console.connected:
                console.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
            else:
                print(
                    f"\n--- HDC Command Error for app_surface({namespace}) ---\n"
                    f"{error_msg}\n"
                    "-----------------------------------\n"
                )


def register(registry_func):
    registry_func(AppSurfaceCommand())
