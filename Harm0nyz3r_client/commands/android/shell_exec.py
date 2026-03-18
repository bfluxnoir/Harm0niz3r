# commands/android/shell_exec.py
import time
from typing import List

from commands.base import Command, CommandSource

_PROMPT = "(adb shell) $> "
_SANDBOX_PROMPT = "(run-as {pkg}) $> "


class AndroidShellExecCommand(Command):
    """
    Interactive shell over adb.

    Two modes:
      shell_exec           → plain 'adb shell' interactive session
      shell_exec <package> → 'adb shell run-as <package>' (app sandbox, requires debuggable)
    """

    @property
    def name(self) -> str:
        return "shell_exec"

    def help(self) -> str:
        return (
            "shell_exec [package]\n"
            "  Open an interactive shell via adb.\n"
            "  Without <package>: plain adb shell.\n"
            "  With <package>   : run-as <package> (app sandbox — requires debuggable build).\n"
            "  Type 'exit' to quit."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "shell_exec is only available from the CLI.")
            return

        if not console.hdc_device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        sandbox_pkg = args[0] if args else None
        prompt = _SANDBOX_PROMPT.format(pkg=sandbox_pkg) if sandbox_pkg else _PROMPT

        if sandbox_pkg:
            console._print_message(
                "INFO",
                f"Opening sandbox shell for '{sandbox_pkg}' via run-as. "
                "App must be debuggable."
            )
        else:
            console._print_message("INFO", "Opening adb shell. Type 'exit' to quit.")

        while True:
            if not console.hdc_device_id:
                console._print_message("ERROR", "Device disconnected.")
                break
            try:
                command_to_run = input(prompt).strip()
                if command_to_run in ("exit", "quit"):
                    print("Exiting shell.")
                    break
                if not command_to_run:
                    continue

                if sandbox_pkg:
                    shell_cmd = ["run-as", sandbox_pkg, "sh", "-c", command_to_run]
                else:
                    # Split into tokens so the shell interprets the command
                    shell_cmd = ["sh", "-c", command_to_run]

                stdout, stderr, ret = console._get_hdc_shell_output(shell_cmd)

                if stdout:
                    print(stdout)
                if stderr:
                    print(f"[stderr] {stderr}")

            except KeyboardInterrupt:
                print("\nUse 'exit' to quit the shell.")
            except EOFError:
                break
            except Exception as e:
                print(f"Error: {e}")
                break


def register(registry_func):
    registry_func(AndroidShellExecCommand())
