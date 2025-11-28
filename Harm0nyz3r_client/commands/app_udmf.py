# commands/app_udmf.py
import re
from typing import List

from .base import Command, CommandSource


class AppUdmfCommand(Command):
    @property
    def name(self) -> str:
        return "app_udmf"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_udmf <namespace> [groupId] [--log]\n"
            "  Query UDMF for a specific app and optional group ID (default: 'flag').\n"
            "  Results are returned from the HarmonyOS app and displayed here.\n"
            "  Use --log to capture device logs while the request is processed."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Usage (CLI):
            app_udmf <namespace> [groupId] [--log]

        Behaviour:
          - Requires an active connection to the HarmonyOS app.
          - Sends a COMMAND_REQUEST 'udmf_query_single_app <namespace> <groupId>' to the app.
          - The app is responsible for querying UDMF and sending back results, which
            the console will display when received.

        Note:
          - '--log' is handled outside in HarmonyOSClientConsole.execute_command():
              * If supports_logging is True, device logging will be started/stopped.
          - 'args' here no longer contains '--log'.
        """
        # Must be connected to the HarmonyOS app
        if not console.connected:
            console._print_message(
                "ERROR",
                "Not connected to the HarmonyOS app. Cannot query UDMF."
            )
            return

        # Expect 1 or 2 arguments: <namespace> [groupId]
        if len(args) < 1 or len(args) > 2:
            console._print_message(
                "INFO",
                "Usage: app_udmf <namespace> [groupId] (groupId defaults to 'flag')."
            )
            return

        namespace = args[0]
        group_id = args[1] if len(args) == 2 else "flag"

        # Basic validation
        if not re.match(r"^[a-zA-Z0-9\._-]+$", namespace):
            console._print_message("ERROR", f"Invalid namespace format: '{namespace}'.")
            return

        if not re.match(r"^[a-zA-Z0-9\._-]+$", group_id):
            console._print_message("ERROR", f"Invalid group ID format: '{group_id}'.")
            return

        console._print_message(
            "INFO",
            f"Requesting UDMF for app '{namespace}' with group ID '{group_id}' from HarmonyOS app."
        )

        # Send command to the HarmonyOS app – app side handles the actual UDMF query
        console.send_data_to_app(
            f"COMMAND_REQUEST:udmf_query_single_app {namespace} {group_id}"
        )


def register(registry_func):
    registry_func(AppUdmfCommand())
