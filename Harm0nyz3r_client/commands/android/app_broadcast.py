# commands/android/app_broadcast.py
import re
from typing import List

from commands.base import Command, CommandSource


class AndroidAppBroadcastCommand(Command):
    """
    Android-specific: send a broadcast intent to an exported receiver.
    Equivalent of invoking a BroadcastReceiver via 'am broadcast'.
    """

    @property
    def name(self) -> str:
        return "app_broadcast"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_broadcast <action> [-n <package/receiver>] [key=value ...] [--log]\n"
            "  Send a broadcast intent via 'am broadcast'.\n\n"
            "Examples:\n"
            "  app_broadcast android.intent.action.BOOT_COMPLETED\n"
            "  app_broadcast com.example.REFRESH -n com.example.app/.UpdateReceiver\n"
            "  app_broadcast com.example.LOGIN_EVENT -n com.example.app/.AuthReceiver token=abc123"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.hdc_device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        if not args:
            console._print_message("INFO", self.help())
            return

        action = args[0]
        cmd = ["am", "broadcast", "-a", action]

        i = 1
        while i < len(args):
            token = args[i]
            if token == "-n" and i + 1 < len(args):
                component = args[i + 1]
                cmd += ["-n", component]
                i += 2
            elif "=" in token:
                key, _, value = token.partition("=")
                if value.lower() in ("true", "false"):
                    cmd += ["--ez", key, value.lower()]
                elif re.fullmatch(r"-?\d+", value):
                    cmd += ["--ei", key, value]
                else:
                    cmd += ["--es", key, value]
                i += 1
            else:
                console._print_message("WARNING", f"Skipping unrecognised argument: {token}")
                i += 1

        console._print_message("INFO", f"Sending broadcast: action='{action}'")
        stdout, stderr, ret = console._get_hdc_shell_output(cmd)

        if ret == 0:
            console._print_message("INFO", "Broadcast sent.")
            if stdout:
                print(f"\n--- am broadcast output ---\n{stdout.rstrip()}\n---------------------------\n")
        else:
            console._print_message("ERROR", "am broadcast failed.")
            if stdout:
                print(f"STDOUT:\n{stdout}")
            if stderr:
                print(f"STDERR:\n{stderr}")


def register(registry_func):
    registry_func(AndroidAppBroadcastCommand())
