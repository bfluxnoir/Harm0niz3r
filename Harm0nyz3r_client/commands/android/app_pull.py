# -*- coding: utf-8 -*-
# commands/android/app_pull.py
"""
app_pull - resolve every APK file installed for a package and copy each to
the host, ready for static analysis.

Implementation
- 'pm path <package>' returns one or more 'package:/data/app/.../base.apk'
  lines (multiple lines on split-APK installs).
- Each path is pulled via the active platform adapter's pull_file_args
  helper (works for both adb and hdc).
- Output goes into '<out_dir>/<package>/' with original filenames kept,
  so split apks land alongside base.apk.
"""

import os
import re
from typing import List

from commands.base import Command, CommandSource


class AndroidAppPullCommand(Command):
    @property
    def name(self) -> str:
        return "app_pull"

    def help(self) -> str:
        return (
            "app_pull <package> [--out DIR]\n"
            "  Pull every APK file installed for <package> to the host.\n"
            "  --out  Output directory (default: ./pulled-apks/<package>/).\n\n"
            "Examples:\n"
            "  app_pull com.example.target\n"
            "  app_pull com.example.target --out ./analysis/"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        out_dir = None
        if "--out" in args:
            idx = args.index("--out")
            if idx + 1 < len(args):
                out_dir = args[idx + 1]
                args = args[:idx] + args[idx + 2:]
            else:
                args = args[:idx]

        if len(args) != 1:
            console._print_message("INFO", "Usage: app_pull <package> [--out DIR]")
            return

        package = args[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        if out_dir is None:
            out_dir = os.path.join("pulled-apks", package)
        os.makedirs(out_dir, exist_ok=True)

        console._print_message("INFO", f"Resolving APK paths for {package} ...")
        stdout, stderr, retcode = console._run_shell(["pm", "path", package])
        if retcode != 0 or not stdout:
            console._print_message("ERROR", f"pm path failed: {stderr or 'no output'}")
            return

        paths = [
            line[len("package:"):].strip()
            for line in stdout.splitlines()
            if line.startswith("package:")
        ]
        if not paths:
            console._print_message("ERROR", "pm path returned no APK paths.")
            return

        console._print_message("INFO", f"Found {len(paths)} APK file(s); pulling ...")
        pulled = []
        for remote in paths:
            local = os.path.join(out_dir, os.path.basename(remote))
            bridge_args = console.platform.pull_file_args(
                console.device_id, remote, local
            )
            _, perr, pret = console._run_bridge(bridge_args)
            if pret == 0 and os.path.exists(local):
                pulled.append(local)
                console._print_message(
                    "INFO",
                    f"  {os.path.basename(remote)}  ->  {local}"
                )
            else:
                console._print_message(
                    "WARNING",
                    f"  Failed to pull {remote}: {perr or 'unknown error'}"
                )

        console._print_message(
            "SUCCESS",
            f"Pulled {len(pulled)} / {len(paths)} APK file(s) into {out_dir}/"
        )


def register(registry_func):
    registry_func(AndroidAppPullCommand())
