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
from typing import List

from commands.base import Command, CommandSource


class AndroidFridaRunCommand(Command):
    @property
    def name(self) -> str:
        return "frida_run"

    def help(self) -> str:
        return (
            "frida_run <package> <script.js> [--spawn]\n"
            "  Inject a Frida JavaScript file into <package> via frida-server\n"
            "  on the device.  Streams script messages until Ctrl-C, then\n"
            "  detaches cleanly.\n"
            "  --spawn  Spawn the app fresh (Frida spawn+resume) instead of\n"
            "           attaching to a running PID.  Use when you need to\n"
            "           hook init paths that run before MainActivity.\n\n"
            "Requirements:\n"
            "  pip install frida-tools  (host)\n"
            "  frida-server-<ver>-android-<abi> running as root on the device\n"
            "  adb visible via 'adb devices'\n\n"
            "Examples:\n"
            "  frida_run com.example.target ./ssl_unpinning.js\n"
            "  frida_run com.example.target ./trace.js --spawn"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "frida_run is only available from the CLI.")
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

        if len(args) != 2:
            console._print_message(
                "INFO",
                "Usage: frida_run <package> <script.js> [--spawn]"
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
