# -*- coding: utf-8 -*-
# commands/android/frida_server.py
"""
frida_server - manage the on-device frida-server binary via adb.
Pure quality-of-life: pushes the host binary into /data/local/tmp,
starts / stops the daemon, reports status.  No Frida Python module
required.

Subcommands (mutually exclusive)
  --status    Default; print whether frida-server is on disk and
              whether a process is currently running, plus the
              version banner if one is available.
  --start     Try to start the on-device frida-server in the
              background under root.
  --stop      Kill all running frida-server PIDs.
  --install <path>   adb-push <path> to /data/local/tmp/frida-server,
              chmod 755.  --install also accepts a .xz file and
              decompresses it on the host first.
  --remote-path P    Override the on-device binary path
              (default /data/local/tmp/frida-server).
"""

import os
import re
import shutil
import subprocess
from typing import List, Optional

from commands.base import Command, CommandSource


_DEFAULT_REMOTE = "/data/local/tmp/frida-server"


def _decompress_xz_if_needed(host_path: str) -> str:
    """If host_path ends with .xz, decompress in-memory to a sibling file
    without the suffix and return that path.  Otherwise return host_path
    unchanged."""
    if not host_path.lower().endswith(".xz"):
        return host_path
    try:
        import lzma  # stdlib
    except ImportError:
        raise RuntimeError("Python stdlib lacks lzma; cannot decompress .xz")
    out_path = host_path[:-3]
    with lzma.open(host_path, "rb") as src, open(out_path, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return out_path


class AndroidFridaServerCommand(Command):
    @property
    def name(self) -> str:
        return "frida_server"

    def help(self) -> str:
        return (
            "frida_server [--status]                   (default)\n"
            "frida_server --start [--remote-path PATH]\n"
            "frida_server --stop\n"
            "frida_server --install <host_path> [--remote-path PATH]\n"
            "  Manage the on-device frida-server binary via adb.  No Frida\n"
            "  Python module required for any subcommand.\n\n"
            "  --status    Print whether the binary is on disk, whether a\n"
            "              process is running, and the version banner if\n"
            "              one is reachable.\n"
            "  --start     Start frida-server in the background as root.\n"
            "  --stop      Kill all running frida-server PIDs.\n"
            "  --install   Push the host binary (.bin or .xz) to the\n"
            "              device and chmod 755.\n"
            "  --remote-path PATH  Override /data/local/tmp/frida-server.\n\n"
            "Examples:\n"
            "  frida_server\n"
            "  frida_server --start\n"
            "  frida_server --install ./frida-server-17.10.1-android-arm64.xz\n"
            "  frida_server --stop"
        )

    # ------------------------------------------------------------------

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        action = "status"
        remote_path = _DEFAULT_REMOTE
        host_path: Optional[str] = None
        i = 0
        actions_set = 0
        while i < len(args):
            tok = args[i]
            if tok in ("--status", "--start", "--stop"):
                action = tok[2:]
                actions_set += 1
                i += 1
            elif tok == "--install" and i + 1 < len(args):
                action = "install"
                host_path = args[i + 1]
                actions_set += 1
                i += 2
            elif tok == "--remote-path" and i + 1 < len(args):
                remote_path = args[i + 1]
                i += 2
            else:
                console._print_message("WARNING", f"Ignoring unknown argument: {tok}")
                i += 1

        if actions_set > 1:
            console._print_message(
                "ERROR",
                "--status / --start / --stop / --install are mutually exclusive."
            )
            return

        if action == "status":
            self._do_status(console, remote_path)
        elif action == "start":
            self._do_start(console, remote_path)
        elif action == "stop":
            self._do_stop(console, remote_path)
        elif action == "install":
            if not host_path:
                console._print_message("ERROR", "--install requires a host path.")
                return
            self._do_install(console, host_path, remote_path)

    # ------------------------------------------------------------------

    def _do_status(self, console, remote_path: str) -> None:
        # 1. Is the binary on disk?
        _, _, has_binary = console._run_shell(["test", "-f", remote_path])
        if has_binary == 0:
            console._print_message("INFO", f"binary  : present on {remote_path}")
        else:
            console._print_message("WARNING", f"binary  : NOT FOUND at {remote_path}")

        # 2. Is a process running?
        out, _, _ = console._run_shell(["pgrep", "-f", "frida-server"])
        pids = [line.strip() for line in (out or "").splitlines() if line.strip()]
        if pids:
            console._print_message("INFO", f"running : PID(s) {', '.join(pids)}")
        else:
            console._print_message("WARNING", "running : no frida-server PID found")

        # 3. Can the host reach it via frida-tools?
        try:
            import frida
            try:
                dev = frida.get_usb_device(timeout=2)
                ver = getattr(dev, "version", None) or "(unknown version)"
                console._print_message("SUCCESS", f"reach   : {dev.id} {dev.name} {ver}")
            except Exception as e:
                console._print_message("WARNING", f"reach   : frida cannot attach: {e}")
        except ImportError:
            console._print_message(
                "INFO",
                "reach   : frida-tools not installed on host; skip reachability check."
            )

    def _do_start(self, console, remote_path: str) -> None:
        # Background-start under root.  Some shells need 'setsid' to detach
        # cleanly; nohup+& is the broadest fallback.
        cmd = (
            f"su 0 sh -c 'nohup {remote_path} >/dev/null 2>&1 &'"
        )
        out, err, ret = console._run_shell(["sh", "-c", cmd])
        if ret != 0:
            console._print_message(
                "ERROR",
                f"start failed (ret={ret}): {(err or out).strip()}"
            )
            return
        # Confirm a PID actually appeared.
        out, _, _ = console._run_shell(["pgrep", "-f", "frida-server"])
        pids = [line.strip() for line in (out or "").splitlines() if line.strip()]
        if pids:
            console._print_message(
                "SUCCESS",
                f"frida-server started, PID(s) {', '.join(pids)}"
            )
        else:
            console._print_message(
                "WARNING",
                "start returned 0 but no PID surfaced -- check the binary path "
                "and that 'su 0' actually works on this device."
            )

    def _do_stop(self, console, remote_path: str) -> None:
        out, _, _ = console._run_shell(["pgrep", "-f", "frida-server"])
        pids = [line.strip() for line in (out or "").splitlines() if line.strip()]
        if not pids:
            console._print_message("INFO", "frida-server is not running.")
            return
        for pid in pids:
            console._run_shell(["su", "0", "kill", pid])
        # Verify
        out, _, _ = console._run_shell(["pgrep", "-f", "frida-server"])
        leftover = [line.strip() for line in (out or "").splitlines() if line.strip()]
        if leftover:
            # Try harder
            for pid in leftover:
                console._run_shell(["su", "0", "kill", "-9", pid])
            console._print_message(
                "WARNING", f"stop: SIGTERM did not clear {leftover}; sent SIGKILL."
            )
        else:
            console._print_message("SUCCESS", f"stopped: {len(pids)} PID(s).")

    def _do_install(self, console, host_path: str, remote_path: str) -> None:
        if not os.path.isfile(host_path):
            console._print_message("ERROR", f"Host binary not found: {host_path}")
            return
        try:
            staged = _decompress_xz_if_needed(host_path)
        except Exception as e:
            console._print_message("ERROR", f"Could not decompress: {e}")
            return
        # adb push
        push_cmd = ["adb", "-s", console.device_id, "push", staged, remote_path]
        try:
            proc = subprocess.run(push_cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            console._print_message("ERROR", "'adb' not found in PATH.")
            return
        if proc.returncode != 0:
            console._print_message(
                "ERROR",
                f"adb push failed: {(proc.stderr or proc.stdout).strip()}"
            )
            return
        # chmod
        _, err, ret = console._run_shell(["su", "0", "chmod", "755", remote_path])
        if ret != 0:
            console._print_message(
                "WARNING", f"chmod 755 failed: {err.strip() or 'no stderr'}"
            )
            return
        console._print_message("SUCCESS", f"installed: {remote_path}")
        console._print_message(
            "INFO",
            "Start with:  frida_server --start"
        )


def register(registry_func):
    registry_func(AndroidFridaServerCommand())
