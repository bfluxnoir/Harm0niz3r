# commands/app_info.py
import re
from typing import List
from .base import Command, CommandSource


class AppInfoCommand(Command):
    @property
    def name(self) -> str:
        return "app_info"

    @property
    def supports_logging(self) -> bool:
        # Allow using: app_info <namespace> [-a] [--log]
        return False

    def help(self) -> str:
        return "app_info <namespace> [-a]   – Show detailed info for a specific app (bundle)"

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Usage (CLI):
          app_info <namespace> [-a] 

        From the app:
          app_info <namespace>     (results will be sent back to the app)

        Behaviour:
          - Runs: bm dump -n <namespace>
          - If '-a' (or source == 'app'), results are sent back to the HarmonyOS app
            with type 'HDC_OUTPUT_APP_DETAILS'.
          - Otherwise, info is only printed to the console.

        Note: the '--log' flag is handled outside this method by
              HarmonyOSClientConsole.execute_command().
        """
        send_to_app = False

        # --------------------
        # Argument parsing
        # --------------------
        if source == "app":
            # For app-originated calls, expect exactly one argument: the namespace
            if len(args) != 1:
                console._print_message("INFO", "Usage from app: app_info <namespace>")
                return
            namespace = args[0]
            send_to_app = True
        else:
            # CLI: handle optional '-a'
            if "-a" in args:
                send_to_app = True
                args = [a for a in args if a != "-a"]

            if len(args) != 1:
                console._print_message("INFO", "Usage: app_info <namespace> [-a] [--log]")
                return

            namespace = args[0]

        # --------------------
        # Basic validation
        # --------------------
        if not re.match(r"^[a-zA-Z0-9._-]+$", namespace):
            console._print_message("ERROR", f"Invalid namespace format: '{namespace}'.")
            return

        # If we want to send to app but are not connected, fall back to console only
        if send_to_app and not console.connected:
            console._print_message(
                "WARNING",
                "Not connected to HarmonyOS app. Printing to console instead."
            )
            send_to_app = False

        # --------------------
        # Execute HDC command
        # --------------------
        console._execute_and_handle_hdc_command(
            ["bm", "dump", "-n", namespace],
            send_to_app_type="HDC_OUTPUT_APP_DETAILS" if send_to_app else None,
            console_output_prefix=f"--- Details for {namespace} ---"
        )


def register(registry_func):
    """
    Called from Harm0nyz3r.py to register this command instance.

    Example in HarmonyOSClientConsole._register_builtin_commands():

        from commands import app_info
        app_info.register(register_command)
    """
    registry_func(AppInfoCommand())
