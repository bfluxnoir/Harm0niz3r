# commands/android/app_ability_want.py
import re
from typing import List

from commands.base import Command, CommandSource


def _infer_type(value: str) -> str:
    if value.lower() in ("true", "false"):
        return "bool"
    if re.fullmatch(r"-?\d+", value):
        return "int"
    return "string"


class AndroidAppAbilityWantCommand(Command):
    @property
    def name(self) -> str:
        return "app_ability_want"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_ability_want <package> <activity> [key=value ...] [--log]\n"
            "  Start an Activity with Intent extras via 'am start'.\n\n"
            "Special keys:\n"
            "  action=<value>   → -a <action>\n"
            "  data=<uri>       → -d <uri>\n"
            "  mime=<type>      → -t <type>\n"
            "  category=<cat>   → -c <category>\n"
            "  component=<pkg/class>  → -n <component>\n"
            "  Any other key    → extra (type auto-inferred: string/int/bool)\n\n"
            "Examples:\n"
            "  app_ability_want com.example.app .DeepLinkActivity action=android.intent.action.VIEW data=myapp://home\n"
            "  app_ability_want com.example.app .LoginActivity username=admin isAdmin=true"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.hdc_device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        if len(args) < 2:
            console._print_message("INFO", self.help())
            return

        package, activity = args[0], args[1]
        params = args[2:]

        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: '{package}'")
            return

        if not activity.startswith(".") and "." not in activity:
            activity = "." + activity
        component = f"{package}/{activity}"

        cmd = ["am", "start", "-n", component]

        for p in params:
            if "=" not in p:
                console._print_message("WARNING", f"Skipping invalid param (no '='): {p}")
                continue
            key, _, value = p.partition("=")

            if key == "action":
                cmd += ["-a", value]
            elif key == "data":
                cmd += ["-d", value]
            elif key == "mime":
                cmd += ["-t", value]
            elif key == "category":
                cmd += ["-c", value]
            elif key == "component":
                # Override component
                cmd[3] = value
            else:
                vtype = _infer_type(value)
                if vtype == "bool":
                    cmd += ["--ez", key, value.lower()]
                elif vtype == "int":
                    cmd += ["--ei", key, value]
                else:
                    cmd += ["--es", key, value]

        console._print_message("INFO", f"Executing: am start {' '.join(cmd[2:])}")
        stdout, stderr, ret = console._get_hdc_shell_output(cmd)

        if ret == 0:
            console._print_message("INFO", "Activity started successfully.")
            if stdout:
                print(stdout)
        else:
            console._print_message("ERROR", "am start failed.")
            if stdout:
                print(f"STDOUT:\n{stdout}")
            if stderr:
                print(f"STDERR:\n{stderr}")


def register(registry_func):
    registry_func(AndroidAppAbilityWantCommand())
