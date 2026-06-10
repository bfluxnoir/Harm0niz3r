# -*- coding: utf-8 -*-
# commands/android/tools_status.py
"""
tools_status - print the configured / resolved paths for every external
CLI tool the Harm0nyz3r toolchain knows about.

Resolution order matches Harm0nyz3r_client/tools.py:
  1. tools.local.json     personal override, gitignored
  2. tools.json           shipped defaults
  3. PATH                 shutil.which(name) fallback

The 'source' column shows which of those three actually produced the
resolved path for each tool.  None means the resolver couldn't find a
working binary anywhere -- fix that by adding the path to tools.local.json
or installing the tool to PATH.
"""

import json
from typing import List

from commands.base import Command, CommandSource
from tools import tools_status as _gather


class AndroidToolsStatusCommand(Command):
    @property
    def name(self) -> str:
        return "tools_status"

    def help(self) -> str:
        return (
            "tools_status [--json]\n"
            "  Print the configured / resolved paths for every external CLI\n"
            "  tool the Harm0nyz3r toolchain knows about (jadx, apktool,\n"
            "  openssl, adb, ...).\n"
            "  --json  Emit JSON instead of the console table.\n\n"
            "Edit Harm0nyz3r_client/tools.local.json to pin paths for your\n"
            "machine.  The shipped tools.json is the registry of known tool\n"
            "names; keep its values null so it doesn't shadow your overrides."
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        as_json = "--json" in args
        rows = _gather()
        if as_json:
            print(json.dumps(rows, indent=2))
            return

        # Console table
        if not rows:
            console._print_message(
                "INFO", "No tools listed in tools.json or tools.local.json."
            )
            return
        name_w = max(len(r["name"]) for r in rows)
        src_w = max(len(r["source"] or "-") for r in rows)
        print("")
        print(f"  {'TOOL'.ljust(name_w)}  {'SOURCE'.ljust(src_w)}  RESOLVED PATH")
        print("  " + "-" * (name_w + src_w + 50))
        for r in rows:
            tag = r["source"] or "-"
            resolved = r["resolved"] or "(not found)"
            print(f"  {r['name'].ljust(name_w)}  {tag.ljust(src_w)}  {resolved}")
        print("")


def register(registry_func):
    registry_func(AndroidToolsStatusCommand())
