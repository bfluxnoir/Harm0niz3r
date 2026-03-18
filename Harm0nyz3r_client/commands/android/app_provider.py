# commands/android/app_provider.py
import json
import re
from typing import List

from commands.base import Command, CommandSource
from parsers.android_parser import parse_pm_dump, parse_content_query


class AndroidAppProviderCommand(Command):
    """
    Android-specific: enumerate and query exported Content Providers.
    Analogous to HarmonyOS app_udmf.
    """

    @property
    def name(self) -> str:
        return "app_provider"

    @property
    def aliases(self) -> List[str]:
        return ["app_udmf"]   # alias so HarmonyOS muscle-memory still works

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_provider <package> [uri] [-a] [--log]\n"
            "  Enumerate exported Content Providers for <package>.\n"
            "  If <uri> is given, query that provider directly.\n"
            "  -a  Send results to the Android agent.\n\n"
            "Examples:\n"
            "  app_provider com.example.app\n"
            "  app_provider com.example.app content://com.example.provider/users\n"
            "  app_provider com.example.app content://com.example.provider/secrets --log"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.hdc_device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        send_to_app = source == "app"
        if "-a" in args:
            send_to_app = True
            args = [a for a in args if a != "-a"]

        if not args:
            console._print_message("INFO", self.help())
            return

        package = args[0]
        uri = args[1] if len(args) >= 2 else None

        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: '{package}'")
            return

        if send_to_app and not console.connected:
            console._print_message("WARNING", "Not connected to agent. Printing to console.")
            send_to_app = False

        # --- Enumerate providers ---
        stdout, stderr, ret = console._get_hdc_shell_output(["pm", "dump", package])
        if ret != 0 or not stdout:
            console._print_message("ERROR", f"pm dump failed: {stderr or 'no output'}")
            return

        parsed = parse_pm_dump(stdout, package)
        providers = [c for c in parsed.get("exposedComponents", []) if c.get("type") == "Provider"]

        print(f"\n--- Content Providers: {package} ({len(providers)}) ---")
        for p in providers:
            exported_tag = "EXPORTED" if p.get("visible") else "internal"
            auth = p.get("authority", "N/A")
            perm = ", ".join(p.get("permissionsRequired", [])) or "(none)"
            print(f"  [{exported_tag}] {p.get('name')}")
            print(f"    Authority  : {auth}")
            print(f"    Permission : {perm}")
        print()

        # --- Query a specific URI if given ---
        if uri:
            console._print_message("INFO", f"Querying: {uri}")
            q_stdout, q_stderr, q_ret = console._get_hdc_shell_output(
                ["content", "query", "--uri", uri]
            )
            if q_ret != 0:
                console._print_message("ERROR", f"content query failed: {q_stderr or 'no output'}")
                return

            result = parse_content_query(q_stdout, uri)
            print(f"--- Query Result: {uri} ---")
            if result["rows"]:
                for row in result["rows"]:
                    print(f"  {row}")
            else:
                print("  No rows returned (or provider requires permissions).")
            print()

            if send_to_app and console.connected:
                console.send_data_to_app(f"UDMF_QUERY_RESULT:{json.dumps(result)}")


def register(registry_func):
    registry_func(AndroidAppProviderCommand())
