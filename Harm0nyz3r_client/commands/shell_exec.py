# commands/shell_exec.py

import time
from typing import List

from .base import Command, CommandSource


SHELL_EXEC_PROMPT = "(app Sandb0x) $> "


class ShellExecCommand(Command):
    @property
    def name(self) -> str:
        return "shell_exec"

    @property
    def aliases(self) -> List[str]:
        # No aliases for now, but you could add ["sh"] etc.
        return []

    def help(self) -> str:
        return (
            "shell_exec                - Open an interactive pseudo-shell in the app sandbox.\n"
            "                              Type commands to run inside the app; 'exit' to quit."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Interactive shell that sends commands to the app via:
            COMMAND_REQUEST:shell_exec <command>

        The app should answer with:
            EXEC_RESULT:<output>

        This is intended for CLI usage only.
        """
        if source != "cli":
            console._print_message(
                "WARNING",
                "shell_exec is only intended to be invoked from the CLI."
            )
            return

        while True:
            if not console.connected:
                console._print_message(
                    "ERROR",
                    "Not connected to the HarmonyOS app. Cannot execute commands."
                )
                console._sandbox_shell_active = False
                break

            console._sandbox_shell_active = True

            try:
                command_to_run = input(SHELL_EXEC_PROMPT).strip()

                if command_to_run in ("exit", "quit"):
                    print("Exiting shell.")
                    console._sandbox_shell_active = False
                    return

                # Reset last result and send the command to the app
                console.exec_result = None
                sent_ok = console.send_data_to_app(
                    f"COMMAND_REQUEST:shell_exec {command_to_run}"
                )
                if not sent_ok:
                    console._print_message(
                        "ERROR",
                        "Failed to send command to app."
                    )
                    continue

                # Wait up to 5 seconds for EXEC_RESULT from the receive loop
                wait_time = 0.0
                while (
                    console.exec_result is None
                    and wait_time < 5.0
                    and console.connected
                ):
                    time.sleep(0.1)
                    wait_time += 0.1

                if console.exec_result is None:
                    console._print_message(
                        "WARN",
                        "No response received from app after command."
                    )
                else:
                    print(f"    {console.exec_result}")
                    # Optionally clear after consumption
                    console.exec_result = None

            except KeyboardInterrupt:
                print("\nUse 'exit' to quit the shell.")
                # Keep the shell running until user types exit/quit
            except Exception as e:
                print(f"Error: {e}")
                console._sandbox_shell_active = False
                return


def register(register_func) -> None:
    """
    Register function called from Harm0nyz3r._register_builtin_commands().
    """
    register_func(ShellExecCommand())
