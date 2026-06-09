# -*- coding: utf-8 -*-
# commands/android/app_decompile.py
"""
app_decompile - pull every APK installed for a package and decompile each
with jadx so the source ends up on disk for static analysis.

Implementation
- Re-uses the app_pull flow (pm path -> adb pull) so we don't depend on
  the user already having APKs locally.
- jadx is shelled out to via subprocess.  We do NOT try to install jadx
  ourselves; if it's missing from PATH the user gets an actionable hint.
"""

import os
import re
import shutil
import subprocess
from typing import List

from commands.base import Command, CommandSource


class AndroidAppDecompileCommand(Command):
    @property
    def name(self) -> str:
        return "app_decompile"

    def help(self) -> str:
        return (
            "app_decompile <package> [--out DIR] [--jadx PATH]\n"
            "  Pull every installed APK for <package> and run jadx on each.\n"
            "  --out   Output directory (default: ./decompiled/<package>/).\n"
            "  --jadx  Path to the jadx CLI (default: 'jadx' on PATH).\n\n"
            "Requires jadx in PATH (download from https://github.com/skylot/jadx).\n\n"
            "Examples:\n"
            "  app_decompile com.example.target\n"
            "  app_decompile com.example.target --out ./src/\n"
            "  app_decompile com.example.target --jadx /opt/jadx/bin/jadx"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        out_dir = None
        jadx_bin = "jadx"
        for opt in ("--out", "--jadx"):
            if opt in args:
                idx = args.index(opt)
                if idx + 1 < len(args):
                    val = args[idx + 1]
                    if opt == "--out":
                        out_dir = val
                    else:
                        jadx_bin = val
                    args = args[:idx] + args[idx + 2:]
                else:
                    args = args[:idx]

        if len(args) != 1:
            console._print_message(
                "INFO", "Usage: app_decompile <package> [--out DIR] [--jadx PATH]"
            )
            return

        package = args[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        if shutil.which(jadx_bin) is None and not os.path.isfile(jadx_bin):
            console._print_message(
                "ERROR",
                f"jadx not found ('{jadx_bin}').  Install from "
                "https://github.com/skylot/jadx/releases and add it to PATH, "
                "or pass --jadx <path> explicitly."
            )
            return

        if out_dir is None:
            out_dir = os.path.join("decompiled", package)
        os.makedirs(out_dir, exist_ok=True)

        # Pull APKs first (write into <out_dir>/_apk/).
        apk_dir = os.path.join(out_dir, "_apk")
        os.makedirs(apk_dir, exist_ok=True)

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

        pulled = []
        for remote in paths:
            local = os.path.join(apk_dir, os.path.basename(remote))
            bridge_args = console.platform.pull_file_args(
                console.device_id, remote, local
            )
            _, perr, pret = console._run_bridge(bridge_args)
            if pret == 0 and os.path.exists(local):
                pulled.append(local)
            else:
                console._print_message(
                    "WARNING",
                    f"Could not pull {remote}: {perr or 'unknown error'}"
                )
        if not pulled:
            console._print_message("ERROR", "No APKs could be pulled.")
            return

        # Decompile each APK with jadx.  Use one output sub-dir per APK so
        # base.apk and any splits don't clobber each other.
        for apk in pulled:
            name = os.path.splitext(os.path.basename(apk))[0]
            target_dir = os.path.join(out_dir, name)
            os.makedirs(target_dir, exist_ok=True)
            console._print_message("INFO", f"jadx {os.path.basename(apk)}  ->  {target_dir}")
            cmd = [jadx_bin, "-d", target_dir, "--no-imports", "--show-bad-code", apk]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            except FileNotFoundError:
                console._print_message("ERROR", f"jadx not found: {jadx_bin}")
                return
            except Exception as e:
                console._print_message("ERROR", f"jadx invocation failed: {e}")
                return
            if proc.returncode != 0:
                # jadx often warns on unrecoverable methods but still produces
                # most of the output; treat non-zero as a soft failure unless
                # the output dir is empty.
                tail = (proc.stderr or proc.stdout or "").splitlines()[-5:]
                if not os.listdir(target_dir):
                    console._print_message(
                        "ERROR",
                        f"jadx failed for {apk}: {' | '.join(tail)}"
                    )
                    continue
                else:
                    console._print_message(
                        "WARNING",
                        f"jadx exited {proc.returncode} for {apk} (partial output): "
                        f"{' | '.join(tail)}"
                    )

        console._print_message(
            "SUCCESS",
            f"Decompiled {len(pulled)} APK(s) into {out_dir}/.  "
            "Run 'app_secrets <dir>' to scan the decompiled tree for secrets."
        )


def register(registry_func):
    registry_func(AndroidAppDecompileCommand())
