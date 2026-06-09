# -*- coding: utf-8 -*-
# commands/android/logcat_tail.py
"""
logcat_tail - stream 'adb logcat' filtered to a package's PID.

V1 keeps it deliberately simple:
  - look up the PID once via 'pidof <package>'
  - exec 'adb -s <serial> shell logcat --pid=<pid> *:<level>' inherited
    (stdin/stdout/stderr pass through), so Ctrl-C goes straight to adb
  - return to the prompt when adb exits

Requires Android 7.0+ for the 'logcat --pid' filter, which the Harm0niz3r
agent already requires (manifest minSdk = 26).
"""

import re
import subprocess
from typing import List

from commands.base import Command, CommandSource

_VALID_LEVELS = ("V", "D", "I", "W", "E", "F", "S")


class AndroidLogcatTailCommand(Command):
    @property
    def name(self) -> str:
        return "logcat_tail"

    def help(self) -> str:
        return (
            "logcat_tail <package> [--level V|D|I|W|E|F|S]\n"
            "  Tail 'adb logcat' filtered to the running PID of <package>.\n"
            "  Inherits the terminal -- press Ctrl-C to stop and return.\n"
            "  --level  Minimum log priority (default V = verbose).\n\n"
            "Examples:\n"
            "  logcat_tail com.example.target\n"
            "  logcat_tail com.example.target --level W"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "logcat_tail is only available from the CLI.")
            return
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        level = "V"
        if "--level" in args:
            idx = args.index("--level")
            if idx + 1 < len(args):
                lv = args[idx + 1].upper()
                if lv in _VALID_LEVELS:
                    level = lv
                else:
                    console._print_message(
                        "WARNING",
                        f"Invalid --level '{args[idx + 1]}', defaulting to V."
                    )
                args = args[:idx] + args[idx + 2:]
            else:
                args = args[:idx]

        if len(args) != 1:
            console._print_message("INFO", "Usage: logcat_tail <package> [--level V|D|I|W|E|F|S]")
            return

        package = args[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        # Resolve PID via 'pidof'.  Fall back to 'ps -A | grep' if pidof isn't
        # present (some custom AOSP builds drop it).
        console._print_message("INFO", f"Looking up PID for {package} ...")
        pid_out, _, ret = console._run_shell(["pidof", package])
        pid = pid_out.strip().split()[0] if pid_out.strip() else None
        if not pid:
            ps_out, _, _ = console._run_shell(["ps", "-A"])
            for line in ps_out.splitlines():
                parts = line.split()
                if len(parts) >= 9 and parts[-1] == package:
                    pid = parts[1]
                    break
        if not pid:
            console._print_message("ERROR", f"{package} is not running on the device.")
            return

        console._print_message(
            "INFO",
            f"Tailing logcat for {package} (PID {pid}, level {level}) -- press Ctrl-C to stop."
        )

        cmd = [
            "adb", "-s", console.device_id, "shell",
            "logcat", f"--pid={pid}", f"*:{level}",
        ]
        try:
            subprocess.run(cmd, check=False)
        except KeyboardInterrupt:
            pass  # adb already saw the signal
        except FileNotFoundError:
            console._print_message("ERROR", "'adb' not found in PATH.")
            return
        except Exception as e:
            console._print_message("ERROR", f"logcat error: {e}")
            return

        console._print_message("INFO", "logcat_tail finished.")


def register(registry_func):
    registry_func(AndroidLogcatTailCommand())
