# commands/android/app_ability.py
import re
from typing import List

from commands.base import Command, CommandSource


class AndroidAppAbilityCommand(Command):
    @property
    def name(self) -> str:
        return "app_ability"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_ability <package> <activity> [--log]\n"
            "  Start an Activity via 'am start -n <package>/<activity>'.\n"
            "  Example: app_ability com.example.app .MainActivity"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.hdc_device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        if len(args) != 2:
            console._print_message("INFO", "Usage: app_ability <package> <activity> [--log]")
            return

        package, activity = args[0], args[1]

        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: '{package}'")
            return

        # Normalise: ensure activity is fully qualified
        if not activity.startswith(".") and "." not in activity:
            activity = "." + activity
        component = f"{package}/{activity}"

        console._print_message("INFO", f"Starting Activity: {component}")
        stdout, stderr, ret = console._get_hdc_shell_output(["am", "start", "-n", component])

        if ret == 0:
            console._print_message("INFO", "am start executed. Check device for result.")
            if stdout:
                print(f"\n--- am start output ---\n{stdout.rstrip()}\n-----------------------\n")
        else:
            console._print_message("ERROR", "am start failed.")
            if stdout:
                print(f"STDOUT:\n{stdout}")
            if stderr:
                print(f"STDERR:\n{stderr}")


def register(registry_func):
    registry_func(AndroidAppAbilityCommand())
