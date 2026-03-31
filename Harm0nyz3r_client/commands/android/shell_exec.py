# -*- coding: utf-8 -*-
# commands/android/shell_exec.py
import subprocess
from typing import List

from commands.base import Command, CommandSource


class AndroidShellExecCommand(Command):
    """
    Interactive adb shell with full terminal passthrough.

    Two modes:
      shell_exec           → 'adb -s DEVICE shell'
                             Full interactive shell; 'su -' works on rooted devices.
      shell_exec <package> → 'adb -s DEVICE shell run-as <package>'
                             App-sandbox shell (requires debuggable build).

    The subprocess inherits the terminal directly (no pipe capture), so stateful
    commands (cd, export …) and interactive programs (su, vim, top …) all behave
    exactly as they would in a native 'adb shell' session.  Type 'exit' to return.
    """

    @property
    def name(self) -> str:
        return "shell_exec"

    def help(self) -> str:
        return (
            "shell_exec [package]  – Open a direct interactive adb shell.\n"
            "  No args  : plain adb shell  (type 'su -' for root on rooted devices).\n"
            "  <package>: run-as <package> sandbox  (requires debuggable build).\n"
            "  Type 'exit' to close the session and return to Harm0nyz3r."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "shell_exec is only available from the CLI.")
            return

        if not console.hdc_device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        sandbox_pkg = args[0] if args else None

        if sandbox_pkg:
            cmd = ["adb", "-s", console.hdc_device_id, "shell", "run-as", sandbox_pkg]
            console._print_message(
                "INFO",
                f"Opening sandbox shell for '{sandbox_pkg}'  (run-as).  "
                "App must be a debuggable build."
            )
        else:
            cmd = ["adb", "-s", console.hdc_device_id, "shell"]
            console._print_message(
                "INFO",
                "Opening interactive adb shell.  Type 'exit' to return to Harm0nyz3r."
            )

        console._print_message("DEBUG", f"Launching: {' '.join(cmd)}")

        try:
            # No capture_output / no pipe redirection.
            # stdin, stdout and stderr are inherited from the parent terminal so the
            # shell is fully interactive: su, cd, vim, top … all work as expected.
            subprocess.run(cmd, check=False)
        except FileNotFoundError:
            console._print_message("ERROR", "'adb' not found in PATH.")
            return
        except KeyboardInterrupt:
            pass   # Ctrl-C was already handled by the shell itself
        except Exception as e:
            console._print_message("ERROR", f"Shell error: {e}")
            return

        console._print_message("INFO", "Shell session ended.")


def register(registry_func):
    registry_func(AndroidShellExecCommand())
