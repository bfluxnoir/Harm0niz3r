# commands/apps_udmf.py
import re
from typing import List

from .base import Command, CommandSource


class AppsUdmfCommand(Command):
    @property
    def name(self) -> str:
        return "apps_udmf"

    @property
    def supports_logging(self) -> bool:
        # No log wrapping for this command
        return False

    def help(self) -> str:
        return (
            "apps_udmf [groupId]\n"
            "  Query UDMF for all installed apps, optionally specifying groupId\n"
            "  (default: 'flag'). Results are returned from the HarmonyOS app."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Usage (CLI):
            apps_udmf [groupId]

        Behaviour:
            - Requires active connection to the HarmonyOS app.
            - Sends request:
                COMMAND_REQUEST:udmf_query_all_apps <groupId>
            - HarmonyOS app performs UDMF lookup for all apps and sends results back.
        """

        # -----------------------------
        # Must be connected to the app
        # -----------------------------
        if not console.connected:
            console._print_message(
                "ERROR",
                "Not connected to the HarmonyOS app. Cannot query UDMF."
            )
            return

        # -----------------------------
        # Parse group ID
        # -----------------------------
        if len(args) > 1:
            console._print_message(
                "INFO",
                "Usage: apps_udmf [groupId] (default groupId is 'flag')"
            )
            return

        group_id = args[0] if len(args) == 1 else "flag"

        if not re.match(r"^[a-zA-Z0-9._-]+$", group_id):
            console._print_message("ERROR", f"Invalid group ID format: '{group_id}'.")
            return

        console._print_message(
            "INFO",
            f"Requesting UDMF list for ALL apps with group ID '{group_id}'."
        )

        # -----------------------------
        # Send to HarmonyOS app
        # -----------------------------
        console.send_data_to_app(
            f"COMMAND_REQUEST:udmf_query_all_apps {group_id}"
        )


def register(registry_func):
    registry_func(AppsUdmfCommand())
