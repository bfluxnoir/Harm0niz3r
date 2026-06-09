# -*- coding: utf-8 -*-
# commands/android/app_sandbox_dump.py
"""
app_sandbox_dump - pull the app's private sandbox off the device.

Copies (on the device, as root) the three locations a pentester usually
cares about under /data/data/<package>/ :

  shared_prefs/      -- SharedPreferences XML; classic stash for tokens
                        and feature flags
  databases/         -- SQLite databases used by Room / SQLiteOpenHelper
  files/             -- app-private regular files

The flow:

  1. Confirm root via 'su 0 id' and that the package directory exists.
  2. Stage a copy under /data/local/tmp/h0_dump_<ts>/<package>/.
  3. 'su 0 chmod -R a+rX' the staged tree so the adb shell user can read it.
  4. 'adb pull' the stage onto the host.
  5. 'su 0 rm -rf' the stage to leave the device untouched.

V1 requires root.  run-as for debuggable apps could be added later if
useful; flag --skip-files lets the user skip the (often huge) files/
subtree.
"""

import os
import re
import time
from typing import List, Optional

from commands.base import Command, CommandSource


_SUBDIRS_DEFAULT = ("shared_prefs", "databases", "files")
_SUBDIRS_NO_FILES = ("shared_prefs", "databases")


class AndroidAppSandboxDumpCommand(Command):
    @property
    def name(self) -> str:
        return "app_sandbox_dump"

    def help(self) -> str:
        return (
            "app_sandbox_dump <package> [--out DIR] [--skip-files]\n"
            "  Copy /data/data/<package>/{shared_prefs,databases,files}/ to\n"
            "  the host.  Requires root (uses 'su 0 cp' + a staging dir under\n"
            "  /data/local/tmp).\n"
            "  --out          Output directory (default: ./sandbox/<package>/).\n"
            "  --skip-files   Skip the files/ subtree (it's often large).\n\n"
            "Examples:\n"
            "  app_sandbox_dump com.example.target\n"
            "  app_sandbox_dump com.example.target --out ./analysis --skip-files"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _has_root(self, console) -> bool:
        out, _, ret = console._run_shell(["su", "0", "id"])
        return ret == 0 and "uid=0" in (out or "")

    def _device_dir_exists(self, console, path: str) -> bool:
        # 'su 0 test -d' is portable enough; '[ -d ]' would also work.
        _, _, ret = console._run_shell(["su", "0", "test", "-d", path])
        return ret == 0

    def _su_run(self, console, *cmd):
        """Run 'su 0 ...' on the device; returns the same triple _run_shell does."""
        return console._run_shell(["su", "0"] + list(cmd))

    # ------------------------------------------------------------------

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        # --- args ---
        out_dir: Optional[str] = None
        skip_files = False
        positional: List[str] = []
        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--skip-files":
                skip_files = True; i += 1
            elif tok == "--out" and i + 1 < len(args):
                out_dir = args[i + 1]; i += 2
            else:
                positional.append(tok); i += 1
        if len(positional) != 1:
            console._print_message("INFO", "Usage: app_sandbox_dump <package> [--out DIR] [--skip-files]")
            return
        package = positional[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        # --- preflight ---
        if not self._has_root(console):
            console._print_message(
                "ERROR",
                "Root access via 'su 0' is required for app_sandbox_dump V1.  "
                "Either run on a rooted device or extract the sandbox manually "
                "via 'adb backup' (only when allowBackup=true)."
            )
            return

        data_dir = f"/data/data/{package}"
        if not self._device_dir_exists(console, data_dir):
            console._print_message("ERROR", f"On-device path not found: {data_dir}")
            return

        if out_dir is None:
            out_dir = os.path.join("sandbox", package)
        os.makedirs(out_dir, exist_ok=True)

        ts = time.strftime("%Y%m%d_%H%M%S")
        stage = f"/data/local/tmp/h0_dump_{ts}/{package}"

        subdirs = _SUBDIRS_NO_FILES if skip_files else _SUBDIRS_DEFAULT
        copied_subdirs: List[str] = []

        # --- stage ---
        try:
            _, err, ret = self._su_run(console, "mkdir", "-p", stage)
            if ret != 0:
                console._print_message("ERROR", f"Could not stage on device: {err}")
                return

            for sub in subdirs:
                src = f"{data_dir}/{sub}"
                if not self._device_dir_exists(console, src):
                    console._print_message("INFO", f"  {sub}/ -- absent, skipping")
                    continue
                dst = f"{stage}/"
                _, cerr, cret = self._su_run(console, "cp", "-r", src, dst)
                if cret != 0:
                    console._print_message(
                        "WARNING",
                        f"Could not copy {src} into stage: {cerr or '(no stderr)'}"
                    )
                    continue
                copied_subdirs.append(sub)

            if not copied_subdirs:
                console._print_message("WARNING", "Nothing was copied to the stage.")
                return

            # Make everything readable by the shell uid for adb pull.
            _, ferr, fret = self._su_run(console, "chmod", "-R", "a+rX", stage)
            if fret != 0:
                console._print_message(
                    "WARNING",
                    f"chmod a+rX failed: {ferr or '(no stderr)'}; pull may be partial."
                )

            # --- pull ---
            local_target = out_dir
            os.makedirs(local_target, exist_ok=True)
            console._print_message("INFO", f"Pulling {stage} -> {local_target}")
            bridge_args = console.platform.pull_file_args(
                console.device_id, stage, local_target
            )
            _, perr, pret = console._run_bridge(bridge_args)
            if pret != 0:
                console._print_message("ERROR", f"adb pull failed: {perr or '(no stderr)'}")
                return

            console._print_message(
                "SUCCESS",
                f"Pulled {', '.join(copied_subdirs)} into {local_target}/."
            )
            console._print_message(
                "INFO",
                f"Suggested next steps:\n"
                f"  app_secrets {local_target}\n"
                f"  app_sqlite_inspect {local_target}"
            )

        finally:
            # Best-effort cleanup so we never leave gunk on /data/local/tmp.
            self._su_run(console, "rm", "-rf", f"/data/local/tmp/h0_dump_{ts}")


def register(registry_func):
    registry_func(AndroidAppSandboxDumpCommand())
