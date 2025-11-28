# commands/apps_visible_abilities.py
import json
from typing import List

from .base import Command, CommandSource
from harmonyos_parser import parse_app_dump_string


def extract_visible_abilities(console, send_to_app: bool = False):
    """
    Returns all invokable abilities (Visible: Yes, no permissions, skips Entry/MainAbility).
    If send_to_app, data is sent in JSON format to HOS app.

    This is the same logic you previously had in HarmonyOSClientConsole.extract_visible_abilities,
    just adapted to use 'console' instead of 'self'.
    """
    if not console.hdc_device_id:
        console._print_message("ERROR", "No HarmonyOS device connected via hdc.")
        return

    # 1. Extract app list
    console._print_message("INFO", "Obtaining app list...")
    stdout, stderr, retcode = console._execute_hdc_command(
        ["-t", console.hdc_device_id, "shell", "bm", "dump", "-a"]
    )
    if retcode != 0 or not stdout:
        console._print_message(
            "ERROR",
            f"Error while executing bm dump -a: {stderr or 'no output'}"
        )
        return

    bundles = [line.strip() for line in stdout.splitlines() if line.strip()]
    console._print_message("INFO", f"Found {len(bundles)} instaled apps.")

    filtered_abilities = []

    for bundle in bundles:
        console._print_message("DEBUG", f"Processing bundle: {bundle}")
        app_stdout, app_stderr, app_retcode = console._get_hdc_shell_output(
            ["bm", "dump", "-n", bundle]
        )

        if app_retcode != 0 or not app_stdout:
            continue

        try:
            parsed = parse_app_dump_string(app_stdout)
            if not isinstance(parsed, dict):
                continue

            for comp in parsed.get("exposedComponents", []):
                if (
                    not isinstance(comp, dict)
                    or comp.get("type", "").lower() != "ability"
                ):
                    continue

                # Apply filters: Visible: Yes, no Permissions and no EntryAbility nor MainAbility
                if (
                    comp.get("visible") is True
                    and not comp.get("permissionsRequired", [])
                    and not any(
                        x in comp.get("name", "").lower()
                        for x in ["entryability", "mainability"]
                    )
                ):
                    skills = comp.get("skills", [])
                    if not isinstance(skills, list):
                        skills = []

                    filtered_abilities.append(
                        {
                            "app": parsed.get("bundleName", bundle),
                            "ability": comp.get("name", "UNKNOWN"),
                            "skills": skills,
                        }
                    )

        except Exception as e:
            console._print_message("DEBUG", f"Error processing {bundle}: {str(e)}")
            continue

    # --- Show filtered abilities through CLI ---
    print("\n=== Filtered Abilities ===")
    print(
        f"Total: {len(filtered_abilities)} "
        "(Visible:Yes, No Permissions, No Entry/Main)"
    )
    for ability in filtered_abilities:
        print(f"\nApp: {ability['app']}")
        print(f"Ability: {ability['ability']}")
        if ability["skills"]:
            print("Intent Filters (skills):")
            for skill in ability["skills"]:
                if isinstance(skill, dict):
                    print(
                        " - "
                        + " ".join(
                            [f"{k}={v}" for k, v in skill.items() if v]
                        )
                    )

    # --- Send filtered ability list to client ---
    if send_to_app and console.connected:
        try:
            payload = (
                "HDC_OUTPUT_EXPOSED_ABILITIES:"
                + json.dumps(filtered_abilities, ensure_ascii=False)
            )
            console.send_data_to_app(payload)
            console._print_message(
                "INFO",
                f"{len(filtered_abilities)} filtered abilities were sent to the app.",
            )
        except Exception as e:
            console._print_message("ERROR", f"Error al enviar a la app: {e}")


class AppsVisibleAbilitiesCommand(Command):
    @property
    def name(self) -> str:
        return "apps_visible_abilities"

    @property
    def supports_logging(self) -> bool:
        # No logging for this command
        return False

    def help(self) -> str:
        return (
            "apps_visible_abilities [-a]\n"
            "  List invokable abilities (Visible: Yes, no permissions, no Entry/MainAbility)\n"
            "  Use -a to send results to the HarmonyOS app."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Usage (CLI):
            apps_visible_abilities [-a]

        From app:
            apps_visible_abilities   (always sends to app)
        """
        send_to_app = False

        if source == "app":
            send_to_app = True
            if len(args) != 0:
                console._print_message(
                    "INFO",
                    "apps_visible_abilities from app does not accept arguments.",
                )
                return
        else:
            if "-a" in args:
                send_to_app = True
                args = [a for a in args if a != "-a"]

            if len(args) != 0:
                console._print_message(
                    "INFO",
                    "Usage: apps_visible_abilities [-a]"
                )
                return

        # If user requested send_to_app but there is no connection, fall back to CLI output only
        if send_to_app and not console.connected:
            console._print_message(
                "WARNING",
                "Not connected to HarmonyOS app. "
                "Results will only be printed to the console."
            )
            send_to_app = False

        extract_visible_abilities(console, send_to_app=send_to_app)


def register(registry_func):
    registry_func(AppsVisibleAbilitiesCommand())
