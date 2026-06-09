# commands/android/app_activity_start.py
import re
from typing import List

from commands.base import Command, CommandSource


class AndroidAppActivityStartCommand(Command):
    """
    Start an Activity by component name via 'am start -n <pkg>/<activity>'.

    The previous name 'app_ability' (HarmonyOS-flavoured) is kept as an
    alias for users coming from the HarmonyOS side of the tool.
    """

    @property
    def name(self) -> str:
        return "app_activity_start"

    @property
    def aliases(self) -> List[str]:
        # Back-compat: old muscle-memory + tab-completion still works.
        return ["app_ability"]

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_activity_start <package> <activity> [--log]   "
            "(alias: app_ability)\n"
            "  Start an Activity via 'am start -n <package>/<activity>'.\n"
            "  Example: app_activity_start com.example.app .MainActivity"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        if len(args) != 2:
            console._print_message(
                "INFO",
                "Usage: app_activity_start <package> <activity> [--log]"
            )
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
        stdout, stderr, ret = console._run_shell(["am", "start", "-n", component])

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
    registry_func(AndroidAppActivityStartCommand())
