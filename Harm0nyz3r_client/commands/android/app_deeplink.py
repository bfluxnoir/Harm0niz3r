# commands/android/app_deeplink.py
from typing import List

from commands.base import Command, CommandSource


class AndroidAppDeeplinkCommand(Command):
    """
    Android-specific: trigger a deep link via 'am start -a VIEW -d <uri>'.
    Tests how apps handle incoming deep links and whether access controls are enforced.
    """

    @property
    def name(self) -> str:
        return "app_deeplink"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_deeplink <uri> [-n <package/activity>] [--log]\n"
            "  Trigger a deep link via 'am start -a android.intent.action.VIEW -d <uri>'.\n\n"
            "Examples:\n"
            "  app_deeplink myapp://home\n"
            "  app_deeplink https://example.com/reset?token=abc -n com.example.app/.WebActivity\n"
            "  app_deeplink myapp://admin/panel"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.hdc_device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        if not args:
            console._print_message("INFO", self.help())
            return

        uri = args[0]
        cmd = ["am", "start", "-a", "android.intent.action.VIEW", "-d", uri]

        i = 1
        while i < len(args):
            if args[i] == "-n" and i + 1 < len(args):
                cmd += ["-n", args[i + 1]]
                i += 2
            else:
                i += 1

        console._print_message("INFO", f"Triggering deep link: {uri}")
        stdout, stderr, ret = console._get_hdc_shell_output(cmd)

        if ret == 0:
            console._print_message("INFO", "Deep link triggered. Check device for response.")
            if stdout:
                print(f"\n--- am start output ---\n{stdout.rstrip()}\n-----------------------\n")
        else:
            console._print_message("ERROR", "am start failed.")
            if stdout:
                print(f"STDOUT:\n{stdout}")
            if stderr:
                print(f"STDERR:\n{stderr}")


def register(registry_func):
    registry_func(AndroidAppDeeplinkCommand())
