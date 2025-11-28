# commands/app_ability.py
import re
from typing import List

from .base import Command, CommandSource


class AppAbilityCommand(Command):
    @property
    def name(self) -> str:
        return "app_ability"

    @property
    def supports_logging(self) -> bool:
        # ✅ This command now supports the --log wrapper
        # The console will:
        #   - call _start_device_logging_for_command("app_ability") before execute()
        #   - call _stop_and_fetch_device_logging_for_command("app_ability") after execute()
        return True

    def help(self) -> str:
        return (
            "app_ability <namespace> <abilityName> [--log]\n"
            "  Start a specific ability using:\n"
            "    hdc shell aa start -a <abilityName> -b <namespace>\n"
            "  Output is printed to this console; the real effect is seen on the device UI.\n"
            "  Use --log to capture device logs while the ability is started."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Usage:
            app_ability <namespace> <abilityName> [--log]

        Behaviour:
          - Requires an HDC-connected device (hdc_device_id must be set).
          - Runs: hdc -t <id> shell aa start -a <abilityName> -b <namespace>
          - Prints stdout/stderr to the console.

        Note:
          - '--log' is handled outside in HarmonyOSClientConsole.execute_command():
              * If supports_logging is True, device logging will be started/stopped.
          - 'args' here no longer contains '--log'.
        """
        # Must have a connected device for aa start
        if not console.hdc_device_id:
            console._print_message(
                "ERROR",
                "No HarmonyOS device connected via hdc. "
                "Please connect a device before running 'app_ability'."
            )
            return

        # We expect exactly two arguments: <namespace> <abilityName>
        if len(args) != 2:
            console._print_message(
                "INFO",
                "Usage: app_ability <namespace> <abilityName> [--log]\n"
                "  Example: app_ability com.example.myapp MainAbility --log"
            )
            return

        namespace = args[0]
        ability_name = args[1]

        # Basic validation – keep it permissive but catch obvious nonsense
        if not re.match(r"^[a-zA-Z0-9._-]+$", namespace):
            console._print_message(
                "ERROR",
                f"Invalid namespace format: '{namespace}'. "
                "Expected something like 'com.example.myapp'."
            )
            return

        # Ability name may be simple (MainAbility) or qualified (com.example.MainAbility)
        if not re.match(r"^[a-zA-Z0-9._/-]+$", ability_name):
            console._print_message(
                "ERROR",
                f"Invalid ability name format: '{ability_name}'."
            )
            return

        console._print_message(
            "INFO",
            f"Starting ability '{ability_name}' from app '{namespace}'..."
        )

        # Build and execute the aa start command via hdc
        cmd = ["aa", "start", "-a", ability_name, "-b", namespace]
        stdout, stderr, ret = console._get_hdc_shell_output(cmd)

        if ret == 0:
            console._print_message(
                "INFO",
                "aa start command executed successfully. Check the device for UI changes."
            )
            if stdout:
                print("\n--- aa start output (stdout) ---")
                print(stdout.rstrip("\n"))
                print("--------------------------------\n")
        else:
            console._print_message(
                "ERROR",
                "aa start command failed."
            )
            if stdout:
                print("\n--- aa start stdout ---")
                print(stdout.rstrip("\n"))
            if stderr:
                print("\n--- aa start stderr ---")
                print(stderr.rstrip("\n"))
            print("\n--------------------------------\n")


def register(registry_func):
    registry_func(AppAbilityCommand())
