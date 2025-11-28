# commands/apps_list.py
from typing import List
from .base import Command, CommandSource


class AppsListCommand(Command):
    @property
    def name(self) -> str:
        return "apps_list"

    @property
    def supports_logging(self) -> bool:
        # This tells the console that '--log' is valid for this command
        # and that it should wrap execution with start/stop device logging.
        return False

    def help(self) -> str:
        return "apps_list [-a]   – Run 'bm dump -a' and optionally send results to the app"

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Usage (CLI):
          apps_list [-a] 

        From the app:
          apps_list         (treated as '-a' automatically)

        Behaviour:
          - Runs 'bm dump -a' via console._execute_and_handle_hdc_command()
          - If '-a' or source == 'app', results are sent back to the app.
          - Device logging (start/stop + fetch log file) is handled outside,
            in HarmonyOSClientConsole.execute_command(), when '--log' is used.
        """
        send_to_app = False

        # If the command originates from the app, treat as if '-a' was used
        if source == "app":
            send_to_app = True
        else:
            # CLI: check for -a flag
            if "-a" in args:
                send_to_app = True
                args = [a for a in args if a != "-a"]

            # No extra args expected (apart from --log, which is already stripped)
            if len(args) > 0:
                console._print_message("INFO", "Usage: apps_list [-a] [--log]")
                return

        # If we want to send to app but there's no active connection, fall back to console only
        if send_to_app and not console.connected:
            console._print_message(
                "WARNING",
                "Not connected to HarmonyOS app. Printing to console instead."
            )
            send_to_app = False

        # Run the actual HDC command using your existing helper
        console._execute_and_handle_hdc_command(
            ["bm", "dump", "-a"],
            send_to_app_type="HDC_OUTPUT_ALL_APPS" if send_to_app else None,
            console_output_prefix="--- Installed Applications List ---"
        )


def register(registry_func):
    registry_func(AppsListCommand())
