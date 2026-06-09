# -*- coding: utf-8 -*-
# commands/android/frida_run.py
"""
frida_run - inject a Frida script into an Android app via the on-device
frida-server.

Lazy-imports the 'frida' Python module so this command file loads cleanly
even on hosts where frida-tools isn't installed; the helpful install hint
is printed only when the user actually tries to run frida_run.

Requirements
  pip install frida-tools                            (host)
  frida-server-<version>-android-<abi>  running as root on the device
  adb visible via 'adb devices'

Usage
  frida_run <package> <script.js> [--spawn]
    --spawn   spawn the app fresh and inject early (Frida's
              device.spawn + attach + resume), otherwise attach to a
              currently-running PID
"""

import os
import re
import sys
import time
from typing import List, Optional

from commands.base import Command, CommandSource


# C19: bundled Frida script library lives next to this module.
_PRESETS_DIR = os.path.join(os.path.dirname(__file__), "frida_presets")


def _list_preset_names() -> List[str]:
    """Return all bundled preset script names (without the .js suffix)."""
    if not os.path.isdir(_PRESETS_DIR):
        return []
    return sorted(
        os.path.splitext(f)[0]
        for f in os.listdir(_PRESETS_DIR)
        if f.endswith(".js") and os.path.isfile(os.path.join(_PRESETS_DIR, f))
    )


def _resolve_preset(name: str) -> Optional[str]:
    """Return absolute path to a bundled preset, or None when not found."""
    if not name:
        return None
    candidate = os.path.join(_PRESETS_DIR, name + ".js")
    if os.path.isfile(candidate):
        return candidate
    return None


class AndroidFridaRunCommand(Command):
    @property
    def name(self) -> str:
        return "frida_run"

    def help(self) -> str:
        presets = _list_preset_names()
        preset_block = (
            ("Bundled presets (use --preset <name> instead of the script path):\n  - "
             + "\n  - ".join(presets) + "\n\n")
            if presets else
            ""
        )
        return (
            "frida_run <package> <script.js> [--spawn]\n"
            "frida_run <package> --preset <name>  [--spawn]\n"
            "frida_run --list-presets\n"
            "  Inject a Frida JavaScript file into <package> via frida-server\n"
            "  on the device.  Streams script messages until Ctrl-C, then\n"
            "  detaches cleanly.\n"
            "  --spawn         Spawn the app fresh (Frida spawn+resume) instead\n"
            "                  of attaching to a running PID.  Use when you\n"
            "                  need to hook init paths that run before\n"
            "                  MainActivity.\n"
            "  --preset NAME   Use a script bundled with Harm0niz3r instead of\n"
            "                  a local file path.\n"
            "  --list-presets  Print the bundled preset names and exit.\n\n"
            + preset_block +
            "Requirements:\n"
            "  pip install frida-tools  (host)\n"
            "  frida-server-<ver>-android-<abi> running as root on the device\n"
            "  adb visible via 'adb devices'\n\n"
            "Examples:\n"
            "  frida_run com.example.target ./ssl_unpinning.js\n"
            "  frida_run com.example.target --preset ssl_pinning_bypass --spawn\n"
            "  frida_run --list-presets"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "frida_run is only available from the CLI.")
            return

        # --list-presets is purely informational and does not need frida.
        if "--list-presets" in args:
            presets = _list_preset_names()
            if not presets:
                console._print_message("INFO", "No bundled presets found.")
            else:
                print("Available frida_run presets:")
                for name in presets:
                    print(f"  - {name}")
            return

        # Lazy import: the rest of the Android command set works without frida.
        try:
            import frida
        except ImportError:
            console._print_message(
                "ERROR",
                "The 'frida' Python module is not installed on the host.\n"
                "  Install with:  pip install frida-tools\n"
                "  Then start frida-server on the device (push the matching\n"
                "  frida-server-<version>-android-<abi> binary into\n"
                "  /data/local/tmp/ and run it as root)."
            )
            return

        spawn = "--spawn" in args
        args = [a for a in args if a != "--spawn"]

        # --preset <name> resolution -- replaces the positional script path
        preset_name: Optional[str] = None
        if "--preset" in args:
            idx = args.index("--preset")
            if idx + 1 < len(args):
                preset_name = args[idx + 1]
                args = args[:idx] + args[idx + 2:]
            else:
                console._print_message("ERROR", "--preset requires a name (try --list-presets).")
                return

        if preset_name is not None:
            if len(args) != 1:
                console._print_message(
                    "INFO",
                    "Usage: frida_run <package> --preset <name> [--spawn]"
                )
                return
            resolved = _resolve_preset(preset_name)
            if not resolved:
                avail = _list_preset_names()
                console._print_message(
                    "ERROR",
                    f"Unknown preset '{preset_name}'.  Available: "
                    + (", ".join(avail) if avail else "(none)")
                )
                return
            package = args[0]
            script_path = resolved
            console._print_message("INFO", f"Using bundled preset: {preset_name} ({script_path})")
        else:
            if len(args) != 2:
                console._print_message(
                    "INFO",
                    "Usage: frida_run <package> <script.js> [--spawn]\n"
                    "   or: frida_run <package> --preset <name> [--spawn]\n"
                    "   or: frida_run --list-presets"
                )
                return
            package, script_path = args
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return
        if not os.path.isfile(script_path):
            console._print_message("ERROR", f"Script file not found: {script_path}")
            return

        try:
            with open(script_path, encoding="utf-8") as f:
                script_source = f.read()
        except Exception as e:
            console._print_message("ERROR", f"Could not read script: {e}")
            return

        # ---- get device ----
        try:
            device = frida.get_usb_device(timeout=5)
        except Exception as e:
            console._print_message(
                "ERROR",
                f"Could not reach a USB device via frida: {e}\n"
                "  - Is 'adb devices' showing your device?\n"
                "  - Is frida-server running on the device (as root)?"
            )
            return

        console._print_message(
            "INFO",
            f"Frida device: {getattr(device, 'id', '?')} ({getattr(device, 'name', '?')})"
        )

        # ---- attach or spawn ----
        pid = None
        try:
            if spawn:
                pid = device.spawn([package])
                session = device.attach(pid)
                console._print_message("INFO", f"Spawned {package} (PID {pid})")
            else:
                session = device.attach(package)
                console._print_message("INFO", f"Attached to {package}")
        except Exception as e:
            # frida raises specific exception classes whose names we may not
            # have at import time; fall back to string match for the common
            # ones so the user gets actionable help.
            text = str(e)
            if "ProcessNotFound" in type(e).__name__ or "unable to find process" in text:
                console._print_message(
                    "ERROR",
                    f"{package} is not running.  Add '--spawn' to launch it, "
                    "or start it manually first."
                )
                return
            if "ServerNotRunning" in type(e).__name__ or "frida-server" in text.lower():
                console._print_message(
                    "ERROR",
                    "frida-server is not running on the device.\n"
                    "  - Push the matching frida-server binary into /data/local/tmp/\n"
                    "  - Start it as root, e.g. 'adb shell su -c /data/local/tmp/frida-server &'"
                )
                return
            console._print_message("ERROR", f"Frida attach failed: {e}")
            return

        # ---- create + load script ----
        def _on_message(msg, data):
            try:
                t = msg.get("type")
                if t == "send":
                    print(f"[FRIDA] {msg.get('payload')}")
                elif t == "error":
                    print(f"[FRIDA ERROR] {msg.get('description', msg)}")
                else:
                    print(f"[FRIDA] {msg}")
            except Exception:
                print(f"[FRIDA] (unparsable message: {msg})")

        try:
            script = session.create_script(script_source)
            script.on("message", _on_message)
            script.load()
        except Exception as e:
            console._print_message("ERROR", f"Failed to load script: {e}")
            try:
                session.detach()
            except Exception:
                pass
            return

        if spawn and pid is not None:
            try:
                device.resume(pid)
            except Exception as e:
                console._print_message("WARNING", f"device.resume failed: {e}")

        console._print_message(
            "INFO",
            f"Script loaded.  Streaming messages from {package}.  Press Ctrl-C to detach."
        )

        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            console._print_message("INFO", "Detaching ...")
            try:
                script.unload()
            except Exception:
                pass
            try:
                session.detach()
            except Exception:
                pass
            console._print_message("INFO", "Frida session ended.")


def register(registry_func):
    registry_func(AndroidFridaRunCommand())
