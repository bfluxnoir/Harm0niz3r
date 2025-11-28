# commands/run_script.py
import os
import shlex
from typing import List

from .base import Command, CommandSource


class RunScriptCommand(Command):
    @property
    def name(self) -> str:
        return "run_script"

    @property
    def supports_logging(self) -> bool:
        # Script commands themselves don't use --log; inner commands decide.
        return False

    def help(self) -> str:
        return (
            "run_script <file>\n"
            "  Execute a script file containing console commands, one per line.\n"
            "  Empty lines and lines starting with '#' are ignored.\n"
            "  You may include any command you would type interactively, e.g.:\n"
            "\n"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Usage:
            run_script script.txt

        Script format:
          - One command per line
          - Empty lines ignored
          - Lines starting with '#' ignored
          - All console commands allowed.
        """
        if len(args) != 1:
            console._print_message("INFO", self.help())
            return

        script_path = os.path.abspath(args[0])

        if not os.path.isfile(script_path):
            console._print_message("ERROR", f"Script file not found: {script_path}")
            return

        console._print_message("INFO", f"Running script: {script_path}")

        try:
            with open(script_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            console._print_message("ERROR", f"Failed to read script: {e}")
            return

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Skip blank lines
            if not line:
                continue

            # Skip comments
            if line.startswith("#"):
                continue

            console._print_message("INFO", f"[SCRIPT] Executing line {line_no}: {line}")

            try:
                # Just reuse the same line dispatcher, but tag source as "script"
                # so execute_command/commands can behave differently if they want.
                console.process_command_line(line, source="script")
            except Exception as e:
                console._print_message(
                    "ERROR",
                    f"[SCRIPT] Exception while executing line {line_no}: {e}",
                )
                # Continue with the next line
                continue

        console._print_message("INFO", "Script execution completed.")

def register(registry_func):
    registry_func(RunScriptCommand())