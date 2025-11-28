# commands/app_ability_want.py
import re
from typing import List

from .base import Command, CommandSource


class AppAbilityWithWantCommand(Command):
    @property
    def name(self) -> str:
        return "app_ability_want"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_ability_want <namespace> <ability> [key=value ...] [--log]\n"
            "  Start an ability with Want parameters.\n\n"
            "Examples:\n"
            "  app_ability_want com.example.app MainAbility name=jorge age=40\n"
            "  app_ability_want com.example.app MainAbility action=ohos.want.action.view\n"
            "  app_ability_want com.example.app MainAbility uri=https://example.com\n"
            "  app_ability_want com.example.app MainAbility premium=true points=140\n"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.hdc_device_id:
            console._print_message("ERROR", "No HarmonyOS device connected via hdc.")
            return

        if len(args) < 2:
            console._print_message("INFO", self.help())
            return

        namespace = args[0]
        ability = args[1]
        params = args[2:]  # everything else: key=value

        # Validate namespace
        if not re.match(r"^[a-zA-Z0-9._-]+$", namespace):
            console._print_message("ERROR", f"Invalid namespace: {namespace}")
            return

        # Validate ability
        if not re.match(r"^[a-zA-Z0-9._/-]+$", ability):
            console._print_message("ERROR", f"Invalid ability: {ability}")
            return

        cmd = ["aa", "start", "-a", ability, "-b", namespace]

        # Parse each key=value
        for p in params:
            if "=" not in p:
                console._print_message("WARNING", f"Skipping invalid param: {p}")
                continue

            key, value = p.split("=", 1)

            # Special fields
            if key == "action":
                cmd += ["-A", value]
                continue

            if key == "uri":
                cmd += ["-U", value]
                continue

            if key == "entity":
                cmd += ["-e", value]
                continue

            if key == "mime":
                cmd += ["-t", value]
                continue

            # Detect type
            if value.lower() in ("true", "false"):
                cmd += ["--pb", key, value.lower()]
            elif re.match(r"^\d+$", value):
                cmd += ["--pi", key, value]
            else:
                cmd += ["--ps", key, value]

        console._print_message("INFO", f"Executing Want-based aa start...")
        console._print_message("DEBUG", f"Final command: {' '.join(cmd)}")

        stdout, stderr, ret = console._get_hdc_shell_output(cmd)

        if ret == 0:
            console._print_message("INFO", "Ability started successfully.")
            if stdout:
                print(stdout)
        else:
            console._print_message("ERROR", "Failed to start ability.")
            if stdout:
                print("STDOUT:\n" + stdout)
            if stderr:
                print("STDERR:\n" + stderr)


def register(registry_func):
    registry_func(AppAbilityWithWantCommand())
