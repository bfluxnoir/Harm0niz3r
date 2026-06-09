# -*- coding: utf-8 -*-
"""
 ==========================================================
 HARM0NYZ3R - Multi-Platform Mobile App Security Companion
 ==========================================================
 Author: DEKRA
 Version: 1.2.1
 License: Apache 2.0
 ==========================================================

TODO:
    - Fix invoke with params (design must be done before).
    - Add support to call invoke_with_want functionality from CLI.

Resolved:
    - Buffer-overflow guard on receive — capped at _max_recv_buffer (B3).
    - ' \n\n' framing on the client receive side (B3).
"""

import socket
import threading
import time
import json
import sys
import subprocess
import re
import os
import queue
import argparse

from config import VERSION, SERVER_HOST, PORT, BUFFER_SIZE, DEFAULT_PLATFORM, PLATFORM_CONFIGS, HARMONYZER_ASCII, get_ascii_art, get_level_label, get_theme, _RST, _DIM, _BOLD, _GREY


# B16: tee stdout to a session-log file with ANSI escape codes stripped, so the
# file is plain text but the terminal stays colourised.
_ANSI_STRIP_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class _TeeStdout:
    """Forward every write() to both the original stdout and a sink, stripping
    ANSI escape sequences from the sink copy."""

    def __init__(self, original, sink):
        self._original = original
        self._sink = sink

    def write(self, data):
        self._original.write(data)
        try:
            self._sink.write(_ANSI_STRIP_RE.sub("", data))
        except Exception:
            pass  # never let logging block console output

    def flush(self):
        self._original.flush()
        try:
            self._sink.flush()
        except Exception:
            pass

    def isatty(self):  # input() / readline behaviour expects this
        return getattr(self._original, "isatty", lambda: False)()

    def fileno(self):  # some libs probe this
        return self._original.fileno()
from platforms import get_platform, list_platforms
from commands import register_command, get_command, list_commands
# HarmonyOS command modules (loaded always; registered conditionally below)
from commands import apps_list, app_info, app_surface, apps_visible_abilities, app_udmf, apps_udmf, app_ability, app_ability_want, app_ability_fuzz, app_ability_fuzz_dict, run_script, net_send, shell_exec
# Android command package (registered when --platform android)
from commands import android as android_commands
from commands.base import CommandSource

class Harm0nyz3rConsole:
    """
    A TCP client that connects to the on-device agent and provides a console interface.
    Platform-specific bridge operations (hdc / adb / iproxy) are delegated to
    self.platform so that the rest of this class remains platform-agnostic.
    """
    def __init__(self, host, port, buffer_size=4096, platform_name=DEFAULT_PLATFORM,
                 device_id=None, session_log_path=None):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.platform = get_platform(platform_name)
        # B4: explicit --device override.  None = auto-detect / interactive picker.
        self._explicit_device_id = device_id
        # B16: optional transcript file; opened in start_console, closed on exit.
        self._session_log_path = session_log_path
        self._session_log_file = None
        self._original_stdout = None
        self.socket = None
        self.connected = False
        self.receive_thread = None
        self.running = True
        self._receive_thread_running = False

        self._input_active = False
        self._current_prompt_text = "[You] Enter command: "
        self.device_id = None
        self.device_name = "No Device"
        self.user_name_on_device = "You"
        self.verbose = False
        self._register_builtin_commands()
        self._current_command_log_enabled = False
        self.log_file_path = None
        # --- shell_exec / sandbox shell state ---
        self.exec_result = None
        self._sandbox_shell_active = False
        # --- agent_exec state ---
        # Receive loop renders agent replies itself (B1) and stores the raw
        # decoded payload in last_agent_response after rendering completes.
        # agent_exec polls this to know when the reply has arrived.
        self.last_agent_response = None
        # --- receive-loop framing buffer (B3) ---
        # Both agents frame messages with ' \n\n' (space + LF + LF).  The loop
        # accumulates raw bytes here and splits on the terminator, so large
        # replies (e.g. apps_list on a device with 300+ packages) are no
        # longer chopped up or lost when they exceed buffer_size.
        self._recv_buffer = b""
        # Hard cap to recover from a peer that never sends the terminator.
        self._max_recv_buffer = 1024 * 1024
        
    # ------------------------------------------------------------------
    # Command registration
    # ------------------------------------------------------------------
    def _register_builtin_commands(self):
        """
        Register commands for the active platform.
        Platform-agnostic commands (net_send, run_script) are always registered.
        """
        # Always available regardless of platform
        run_script.register(register_command)
        net_send.register(register_command)

        if self.platform.name == "harmonyos":
            apps_list.register(register_command)
            app_info.register(register_command)
            app_surface.register(register_command)
            apps_visible_abilities.register(register_command)
            app_udmf.register(register_command)
            apps_udmf.register(register_command)
            app_ability.register(register_command)
            app_ability_want.register(register_command)
            app_ability_fuzz.register(register_command)
            app_ability_fuzz_dict.register(register_command)
            shell_exec.register(register_command)

        elif self.platform.name == "android":
            android_commands.apps_list.register(register_command)
            android_commands.app_info.register(register_command)
            android_commands.app_surface.register(register_command)
            android_commands.apps_exported_activities.register(register_command)
            android_commands.app_ability.register(register_command)
            android_commands.app_ability_want.register(register_command)
            android_commands.app_ability_fuzz.register(register_command)
            android_commands.app_broadcast.register(register_command)
            android_commands.app_deeplink.register(register_command)
            android_commands.app_permissions.register(register_command)
            android_commands.app_provider.register(register_command)
            android_commands.shell_exec.register(register_command)
            android_commands.agent_exec.register(register_command)
            android_commands.app_scan.register(register_command)
            android_commands.app_deeplinks.register(register_command)
            android_commands.logcat_tail.register(register_command)
            android_commands.app_provider_probe.register(register_command)
            android_commands.frida_run.register(register_command)
            android_commands.app_pull.register(register_command)
            android_commands.app_decompile.register(register_command)
            android_commands.app_secrets.register(register_command)
            android_commands.mastg_report.register(register_command)
            android_commands.app_nsc_check.register(register_command)
            android_commands.app_pinning_check.register(register_command)
            android_commands.app_webview_scan.register(register_command)
            android_commands.app_crypto_scan.register(register_command)

        elif self.platform.name == "ios":
            # Phase 3 — stub; only platform-agnostic commands available
            self._print_message(
                "WARNING",
                "iOS platform is not yet fully implemented (Phase 3). "
                "Only net_send and run_script are available."
            )
        
    # ------------------------------------------------------------------
    # Device logging lifecycle for commands (stubs for now)
    # ------------------------------------------------------------------

    def _start_device_logging_for_command(self, command_name: str) -> None:
        """
        Start device-side logging for a single command execution using 'hilog'.

        Strategy:
          - Generate a unique log filename on the device.
          - Start 'hilog -r' in the background, redirecting to that file.
          - Store the PID so we can stop it later.
        """
        if not self.device_id:
            # No device → skip logging rather than crash
            self._print_message("WARNING", "No HDC device; skipping device logging.")
            return

        timestamp = int(time.time())
        remote_filename = f"/data/local/tmp/harm0nyz3r_{command_name}_{timestamp}.log"
        local_filename = f"harm0nyz3r_{command_name}_{timestamp}.log"

        self._device_log_remote_path = remote_filename
        self._device_log_local_path = os.path.abspath(local_filename)
        self._device_log_pid = None

        # Build a platform-specific shell command that:
        #  - starts log capture in background
        #  - redirects to our log file
        #  - prints its PID so we can stop it later
        shell_cmd = self.platform.get_log_shell_command(remote_filename)

        self._print_message(
            "INFO",
            f"Starting device logging for '{command_name}' into {remote_filename}"
        )

        # Use your existing _run_shell or _run_bridge:
        stdout, stderr, retcode = self._run_shell(
            [shell_cmd]
        )

        if retcode != 0 or not stdout.strip():
            self._print_message(
                "WARNING",
                f"Failed to start hilog on device: {stderr or 'no output'}"
            )
            # Clear state so stop/fetch knows there is nothing to do
            self._device_log_remote_path = None
            self._device_log_local_path = None
            self._device_log_pid = None
            return

        # stdout should contain the PID printed by 'echo $!'
        pid_str = stdout.strip().splitlines()[-1].strip()
        if not pid_str.isdigit():
            self._print_message(
                "WARNING",
                f"Unexpected PID from hilog start: '{pid_str}'. Logging may not stop cleanly."
            )
            # still keep paths; we might be able to pull file anyway
            return

        self._device_log_pid = int(pid_str)
        if self.verbose:
            self._print_message("DEBUG", f"Device logging PID: {self._device_log_pid}")

    
    def _stop_and_fetch_device_logging_for_command(self, command_name: str) -> None:
        """
        Stop device-side logging (if started) and pull the log file to the host.
        """
        if not self.device_id or not self._device_log_remote_path:
            # Logging never started or failed early
            if self.verbose:
                self._print_message("DEBUG", "No device logging session to stop.")
            return

        remote = self._device_log_remote_path
        local = self._device_log_local_path
        pid = self._device_log_pid

        self._print_message(
            "INFO",
            f"Stopping device logging for '{command_name}' and fetching log file."
        )

        # 1) Try to stop the hilog process cleanly, if we have its PID
        if pid is not None:
            kill_cmd = f"kill {pid}"
            _, stderr_kill, ret_kill = self._run_shell(
                [f"kill -9 {pid}"]
            )
            if ret_kill != 0 and self.verbose:
                self._print_message(
                    "WARNING",
                    f"Failed to kill hilog PID {pid}: {stderr_kill or 'unknown error'}"
                )
            # Give the device a moment to flush the file
            time.sleep(0.5)

        # 2) Pull the log file from device to host (platform-agnostic)
        if local is None:
            local = os.path.abspath(f"harm0nyz3r_{command_name}_log.log")

        recv_cmd = self.platform.pull_file_args(self.device_id, remote, local)
        stdout_recv, stderr_recv, ret_recv = self._run_bridge(recv_cmd)

        if ret_recv != 0:
            self._print_message(
                "WARNING",
                f"Failed to retrieve log file from device: {stderr_recv or stdout_recv or 'no output'}"
            )
        else:
            self._print_message(
                "INFO",
                f"Device log file saved as: {local}"
            )

        # 3) (Optional) Remove remote file to avoid filling /data/local/tmp
        rm_cmd = ["-t", self.device_id, "shell", f"rm -f {remote}"]
        _, stderr_rm, ret_rm = self._run_bridge(rm_cmd)
        if ret_rm != 0 and self.verbose:
            self._print_message(
                "WARNING",
                f"Failed to remove remote log file {remote}: {stderr_rm or 'unknown error'}"
            )

        # 4) Reset state
        self._device_log_remote_path = None
        self._device_log_local_path = None
        self._device_log_pid = None


    @property
    def _agent_label(self) -> str:
        """Human-readable name for the on-device agent, used in console messages."""
        return {
            "harmonyos": "HarmonyOS app",
            "android":   "Android agent",
        }.get(self.platform.name, "agent")

    # ------------------------------------------------------------------
    # B1 — pretty rendering of agent replies in the receive loop
    # (Android only; HarmonyOS keeps the raw [APP MESSAGE] echo so its
    # existing HDC_OUTPUT_* / UDMF_* handling stays bit-for-bit identical)
    # ------------------------------------------------------------------

    def _render_agent_reply(self, raw: str) -> bool:
        """
        Try to render a recognised agent reply nicely.

        Returns True when the message was handled here (and the raw
        '[APP MESSAGE] …' echo should be suppressed); False otherwise.
        """
        if self.platform.name != "android":
            return False
        msg_type, sep, payload = raw.partition(":")
        if not sep:
            return False
        payload = payload.strip()

        renderers = {
            "ERROR_RESULT":               self._render_error,
            "EXEC_RESULT":                self._render_exec,
            "APPS_LIST_RESULT":           self._render_apps_list,
            "APP_INFO_RESULT":            self._render_app_info,
            "APP_SURFACE_RESULT":         self._render_app_surface,
            "EXPORTED_ACTIVITIES_RESULT": self._render_exported_activities,
            "APP_PERMISSIONS_RESULT":     self._render_app_permissions,
            "PROVIDER_QUERY_RESULT":      self._render_provider_query,
        }
        handler = renderers.get(msg_type)
        if handler is None:
            return False
        try:
            handler(payload)
        except Exception as e:
            # Fall back to raw echo on any rendering error rather than dropping the message
            self._print_message("WARNING", f"Failed to render {msg_type}: {e}")
            return False
        return True

    def _try_json(self, payload: str):
        """Parse JSON payload; return decoded value or None on failure."""
        try:
            return json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _pick_permissions(obj: dict) -> list:
        """
        Read the requested-permissions list from an agent JSON reply.

        The field was renamed from 'requiredAppPermissions' to
        'requestedAppPermissions' in commit 339fcd2 (A11).  Accept either
        spelling so a freshly-updated client keeps rendering correctly
        against an on-device APK built before that rename.
        """
        return (
            obj.get("requestedAppPermissions")
            or obj.get("requiredAppPermissions")
            or []
        )

    def _render_error(self, payload: str) -> None:
        self._print_message("ERROR", f"Agent error: {payload}")

    def _render_exec(self, payload: str) -> None:
        # shell_exec.py (HarmonyOS) and any future Android consumer poll
        # self.exec_result.  Don't echo here when the sandbox shell is active.
        if not self._sandbox_shell_active:
            self._print_message("SUCCESS", f"Agent: {payload}")

    def _render_apps_list(self, payload: str) -> None:
        names = self._try_json(payload)
        if not isinstance(names, list):
            self._print_message("INFO", f"[APPS_LIST_RESULT] {payload}")
            return
        print(f"\n--- Installed Packages ({len(names)}) ---")
        for name in sorted(names):
            print(f"  {name}")
        print("--------------------------------------------\n")

    def _render_app_info(self, payload: str) -> None:
        obj = self._try_json(payload)
        if not isinstance(obj, dict):
            self._print_message("INFO", f"[APP_INFO_RESULT] {payload}")
            return
        pkg = obj.get("packageName", "UNKNOWN")
        print(f"\n--- App Info: {pkg} ---")
        print(f"  Version    : {obj.get('versionName')} (code {obj.get('versionCode')})")
        print(f"  Target SDK : {obj.get('targetSdk')}   Min SDK: {obj.get('minSdk')}")
        print(f"  Debug      : {obj.get('debugMode')}")
        print(f"  System App : {obj.get('systemApp')}")
        perms = self._pick_permissions(obj)
        print(f"  Permissions: {len(perms)}")
        for p in perms:
            print(f"    - {p}")
        print("----------------------------\n")

    def _render_app_surface(self, payload: str) -> None:
        obj = self._try_json(payload)
        if not isinstance(obj, dict):
            self._print_message("INFO", f"[APP_SURFACE_RESULT] {payload}")
            return
        pkg = obj.get("packageName", "UNKNOWN")
        comps = obj.get("exposedComponents", [])
        print(f"\n--- App Surface: {pkg} ({len(comps)} exported components) ---")
        for comp in comps:
            ctype = comp.get("type", "?")
            name = comp.get("name", "?")
            visible = comp.get("visible", False)
            perms = comp.get("permissionsRequired", [])
            skills = comp.get("skills", [])
            authority = comp.get("authority")
            print(f"\n  [{ctype}] {name}")
            print(f"    Exported    : {visible}")
            print(f"    Permission  : {', '.join(perms) if perms else '(none)'}")
            if authority:
                print(f"    Authority   : {authority}")
            if skills:
                print("    Intent Filters:")
                for s in skills:
                    kv = " ".join(f"{k}={v}" for k, v in s.items() if v)
                    print(f"      - {kv}")
            else:
                print("    Intent Filters: (none)")
        print("----------------------------------------------\n")

    def _render_exported_activities(self, payload: str) -> None:
        arr = self._try_json(payload)
        if not isinstance(arr, list):
            self._print_message("INFO", f"[EXPORTED_ACTIVITIES_RESULT] {payload}")
            return
        print(f"\n=== Exported Activities (no permission guard) — {len(arr)} ===")
        for item in arr:
            print(f"\n  App     : {item.get('app')}")
            print(f"  Activity: {item.get('activity')}")
            skills = item.get("skills", [])
            if skills:
                print("  Intent Filters:")
                for s in skills:
                    kv = " ".join(f"{k}={v}" for k, v in s.items() if v)
                    print(f"    - {kv}")
        print("======================================================\n")

    def _render_app_permissions(self, payload: str) -> None:
        obj = self._try_json(payload)
        if not isinstance(obj, dict):
            self._print_message("INFO", f"[APP_PERMISSIONS_RESULT] {payload}")
            return
        pkg = obj.get("packageName", "UNKNOWN")
        requested = self._pick_permissions(obj)
        granted = set(obj.get("grantedPermissions", []))
        filt = "dangerous-only" if obj.get("dangerousOnly") else "all"
        print(f"\n--- Permissions: {pkg}  ({filt}) ---")
        print(f"  Debug Mode : {obj.get('debugMode')}")
        print(f"  System App : {obj.get('systemApp')}")
        print(f"\n  Requested ({len(requested)}):")
        for p in sorted(requested):
            tag = " (granted)" if p in granted else ""
            print(f"    {p}{tag}")
        not_granted = [p for p in requested if p not in granted]
        if not_granted:
            print(f"\n  NOT Granted ({len(not_granted)}):")
            for p in sorted(not_granted):
                print(f"    {p}")
        print("------------------------------------\n")

    def _render_provider_query(self, payload: str) -> None:
        obj = self._try_json(payload)
        if not isinstance(obj, dict):
            self._print_message("INFO", f"[PROVIDER_QUERY_RESULT] {payload}")
            return
        uri = obj.get("uri", "N/A")
        rows = obj.get("rows", [])
        print(f"\n--- Provider Query: {uri} ({len(rows)} rows) ---")
        if not rows:
            print("  (no rows returned — provider may require permissions or be empty)")
        else:
            for row in rows:
                print(f"  {row}")
        print("---------------------------------------------\n")

    def _print_message(self, level, message):
        """Print a coloured, platform-aware console message.

        Visible levels (always shown): INFO, ERROR, SUCCESS, FATAL_ERROR, WARNING.
        Debug levels (shown only in verbose mode): DEBUG and any unrecognised level.
        """
        visible = level in ("INFO", "ERROR", "SUCCESS", "FATAL_ERROR", "WARNING")
        if not visible and not self.verbose:
            return

        label, mcol = get_level_label(self.platform.name, level)
        print(f"{label} {mcol}{message}{_RST}")

    def _cleanup_socket(self):
        """Helper to safely close the socket."""
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
                self._print_message("DEBUG", "Socket shutdown and closed successfully.")
            except OSError as e:
                if "Transport endpoint is not connected" not in str(e) and "Socket is not connected" not in str(e):
                    self._print_message("WARNING", f"Warning during socket cleanup: {e}")
            self.socket = None

    def _run_bridge(self, args_list):
        """
        Executes a bridge command (hdc/adb/…) and returns stdout, stderr, returncode.
        Delegates to the active platform adapter.

        Args:
            args_list (list): Arguments for the bridge tool.
        Returns:
            tuple: (stdout_str, stderr_str, return_code)
        """
        self._print_message(
            "DEBUG",
            f"Executing {self.platform.bridge_command} command: "
            f"{self.platform.bridge_command} {' '.join(args_list)}"
        )
        stdout, stderr, retcode = self.platform.execute_bridge_command(args_list)
        if retcode == -1 and not stdout:
            # Surface bridge-not-found errors clearly
            self._print_message("ERROR", stderr)
        return stdout, stderr, retcode

    def _run_shell(self, hdc_shell_cmd_args):
        """
        Executes a device shell command via the active platform bridge.
        This function does NOT handle printing or sending to the agent;
        it just retrieves the raw output.
        """
        if not self.device_id:
            self._print_message(
                "ERROR",
                f"No {self.platform.name} device is connected. "
                f"Cannot execute shell commands."
            )
            return "", f"No {self.platform.name} device found.", -1

        full_hdc_args = self.platform.device_shell_args(self.device_id) + hdc_shell_cmd_args
        self._print_message(
            "INFO",
            f"Executing: '{self.platform.bridge_command} {' '.join(full_hdc_args)}'"
        )
        stdout, stderr, retcode = self._run_bridge(full_hdc_args)
        return stdout, stderr, retcode

    def _pick_device_interactively(self, devices: list) -> tuple:
        """
        Multi-device + no --device override: prompt the user to pick one.

        Returns the chosen (serial, name) tuple, or None if the user aborts.
        Falls back silently to devices[0] when stdin isn't a tty (CI / pipes)
        so non-interactive callers preserve the historical "first device"
        behaviour without surprises.
        """
        if not sys.stdin.isatty():
            self._print_message(
                "WARNING",
                f"Multiple {self.platform.name} devices detected and no "
                f"--device specified; defaulting to the first ({devices[0][0]}). "
                "Pass --device <serial> to pin explicitly."
            )
            return devices[0]

        self._print_message(
            "INFO",
            f"Multiple {self.platform.name} devices detected -- pick one:"
        )
        for i, (serial, name) in enumerate(devices, 1):
            label = f"{name} ({serial})" if name and name != serial else serial
            print(f"  [{i}] {label}")
        while True:
            try:
                choice = input(f"Pick (1-{len(devices)}, empty to abort): ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return None
            if not choice:
                return None
            if choice.isdigit():
                n = int(choice)
                if 1 <= n <= len(devices):
                    return devices[n - 1]
            print(f"  Please enter a number 1-{len(devices)}.")

    def _detect_device(self):
        """
        Detects a connected device via the active platform adapter and
        updates self.device_id / self.device_name / self.user_name_on_device.

        Selection priority (B4):
          1. --device <serial> override -- errors out if not present in the
             current device list.
          2. Single device -> picked automatically.
          3. Multiple devices on Android -> interactive picker (or first when
             stdin isn't a tty).
          4. Multiple devices on HarmonyOS -> first device with a warning
             (HarmonyOS multi-device behaviour preserved).
        """
        self.device_id = None
        self.device_name = "No Device"
        self.user_name_on_device = "You"

        self._print_message(
            "INFO",
            f"Detecting {self.platform.name} device via '{self.platform.bridge_command}'..."
        )

        devices = self.platform.list_devices()
        if not devices:
            self._print_message(
                "INFO",
                f"No {self.platform.name} devices detected via '{self.platform.bridge_command}'."
            )
            return False

        chosen = None
        if self._explicit_device_id:
            for serial, name in devices:
                if serial == self._explicit_device_id:
                    chosen = (serial, name)
                    break
            if not chosen:
                visible = ", ".join(s for s, _ in devices) or "(none)"
                self._print_message(
                    "ERROR",
                    f"Requested device '{self._explicit_device_id}' is not "
                    f"available.  Connected: {visible}"
                )
                return False
        elif len(devices) == 1:
            chosen = devices[0]
        elif self.platform.name == "android":
            chosen = self._pick_device_interactively(devices)
            if chosen is None:
                self._print_message("INFO", "Aborted device selection.")
                return False
        else:
            # Preserve historical HarmonyOS multi-device behaviour: pick first.
            chosen = devices[0]
            self._print_message(
                "WARNING",
                f"Multiple {self.platform.name} devices detected; using the "
                f"first ({chosen[0]}). Pass --device <serial> to pin a specific one."
            )

        self.device_id = chosen[0]
        self.device_name = chosen[1] or chosen[0]
        self._print_message(
            "SUCCESS",
            f"Selected {self.platform.name} device: "
            f"ID='{self.device_id}', Name='{self.device_name}'"
        )

        # Try whoami (generic shell command — works on both HarmonyOS and Android)
        self._print_message("DEBUG", "Attempting 'whoami' on device...")
        whoami_args = self.platform.device_shell_args(self.device_id) + ["whoami"]
        user_stdout, user_stderr, user_retcode = self._run_bridge(whoami_args)
        if user_retcode == 0 and user_stdout:
            self.user_name_on_device = user_stdout.strip()
        else:
            self._print_message(
                "WARNING",
                f"'whoami' failed (retcode: {user_retcode}). Defaulting to 'You'."
            )

        return True

    def _ensure_port_forward(self) -> None:
        """
        F1 — auto-establish the host-to-device port forward at connect time.

        Android only.  HarmonyOS users continue to set up `hdc fport` manually
        as documented (keeps the existing workflow bit-for-bit identical).

        Idempotent: re-running `adb forward` with the same pair is a no-op on
        adb's side, so calling this on every connect is safe.  Always passes
        '-s <device_id>' so the wrong transport (e.g. a stray wireless-adb
        session for the same device) cannot silently steal the request.
        """
        if self.platform.name != "android":
            return
        if not self.device_id:
            return
        try:
            args = self.platform.port_forward_args(self.device_id, self.port, self.port)
        except NotImplementedError:
            return
        self._print_message(
            "INFO",
            f"Setting up {self.platform.bridge_command} forward "
            f"tcp:{self.port} -> tcp:{self.port} on device '{self.device_id}'..."
        )
        stdout, stderr, retcode = self._run_bridge(args)
        if retcode == 0:
            self._print_message("INFO", "Port forward ready.")
        else:
            msg = (stderr or stdout or f"return code {retcode}").strip()
            self._print_message(
                "WARNING",
                f"Auto port-forward failed: {msg}.  "
                "Continuing anyway in case an existing forward is already in place."
            )

    def _diagnose_connection_refused(self) -> None:
        """
        F3 — when the TCP connect is refused, surface actionable detail.

        Android only.  Shows the current `adb forward --list` and prints the
        exact command needed to recreate the forward (with -s <serial> to
        disambiguate when several transports are registered for the same
        device — the most common silent failure mode).
        """
        self._print_message(
            "INFO",
            f"   - Nothing is listening on {self.host}:{self.port}.  "
            "Usually that means the host-to-device port forward is missing."
        )
        if self.platform.name == "android":
            try:
                stdout, _, retcode = self._run_bridge(["forward", "--list"])
            except Exception:
                stdout, retcode = "", -1
            if retcode == 0:
                if stdout.strip():
                    indented = "\n".join(f"       {ln}" for ln in stdout.splitlines())
                    self._print_message("INFO", f"   - Active adb forwards:\n{indented}")
                else:
                    self._print_message("INFO", "   - No active adb forwards.")
            if self.device_id:
                suggested = (
                    f"adb -s {self.device_id} forward "
                    f"tcp:{self.port} tcp:{self.port}"
                )
            else:
                suggested = f"adb forward tcp:{self.port} tcp:{self.port}"
            self._print_message("INFO", f"   - Suggested fix:  {suggested}")
        self._print_message(
            "INFO",
            f"   - Then make sure the {self._agent_label} is running on the device."
        )

    def connect(self):
        """
        Establishes a raw TCP connection, performs a 'MARCO'-'POLO' handshake.
        """
        if self.connected:
            self._print_message("INFO", "Already connected and handshake successful. No need to connect again.")
            return True

        self._print_message(
            "INFO",
            f"Checking for {self.platform.name} device via '{self.platform.bridge_command}'..."
        )
        hdc_device_found = self._detect_device()

        self._update_prompt()

        if not hdc_device_found:
            self._print_message(
                "INFO",
                f"No active {self.platform.name} device detected. "
                "Some commands (e.g., 'apps_list', 'app_info') might not work."
            )
        else:
            # F1: ensure the host-to-device port forward exists before connecting.
            self._ensure_port_forward()

        if self.socket:
            self._print_message("DEBUG", "Disconnecting previous incomplete/failed socket before new attempt.")
            self.disconnect()
            time.sleep(0.1) 

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5) 

            self._print_message("INFO", f"Attempting to establish raw TCP connection to {self.host}:{self.port}...")
            self.socket.connect((self.host, self.port))
            self._print_message("INFO", "Raw TCP connection ESTABLISHED. Now initiating MARCO-POLO handshake.")

            handshake_command = "MARCO \n\n"
            self.socket.sendall(handshake_command.encode('utf-8'))
            self._print_message("DEBUG", f"Sent handshake command: '{handshake_command}' to the {self._agent_label}.")

            self._print_message("DEBUG", "Waiting for handshake response (max 5 seconds) from server...")
            response_data = self.socket.recv(self.buffer_size)
            
            if not response_data:
                self._print_message("ERROR", "Server disconnected during handshake. Received no data after sending MARCO.")
                self._cleanup_socket()
                return False 

            handshake_response = response_data.decode('utf-8').strip()
            self._print_message("DEBUG", f"Received handshake response: '{handshake_response}' from agent.")

            if handshake_response.startswith("POLO"):
                self.connected = True
                if handshake_response == "POLO":
                    self._print_message("SUCCESS", "MARCO-POLO Handshake SUCCESSFUL! Connection fully established. (HarmonyOS agent)")
                else:
                    # e.g. "POLO:android:2.0"
                    agent_info = handshake_response[len("POLO:"):] if ":" in handshake_response else handshake_response
                    self._print_message("SUCCESS", f"MARCO-POLO Handshake SUCCESSFUL! Connection fully established. (Agent: {agent_info})")

                # Switch to a generous receive timeout instead of blocking-forever (None).
                # On Windows, switching to None after a timed socket can cause an immediate
                # empty read in the receive thread.  The receive loop handles socket.timeout
                # with 'pass', so a 60-second poll is transparent to the user.
                self.socket.settimeout(60)

                # Enable TCP keep-alive so the OS probes the connection when idle
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                self._receive_thread_running = True
                self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
                self.receive_thread.start()
                return True
            else:
                self._print_message("ERROR", f"Handshake FAILED: Unexpected response '{handshake_response}'. Expected 'POLO'.")
                self._print_message("INFO", "Connection will NOT be established for further commands.")
                self._cleanup_socket()
                return False

        except socket.timeout:
            self._print_message("ERROR", f"Connection or handshake timed out after 5 seconds to {self.host}:{self.port}.")
            self._print_message("INFO", f"   - Is the {self._agent_label} running?")
            self._print_message("INFO", f"   - Is the {self._agent_label} listening on the correct IP and port?")
            self._print_message("INFO", "   - Are there any firewalls blocking the connection on either side?")
            self._cleanup_socket()
            return False
        except ConnectionRefusedError:
            self._print_message("ERROR", f"Connection refused by {self.host}:{self.port}.")
            # F3: actionable diagnosis (lists active forwards, suggests the exact fix).
            self._diagnose_connection_refused()
            self._cleanup_socket()
            return False
        except Exception as e:
            self._print_message("FATAL_ERROR", f"An unexpected error occurred during connection/handshake: {e}")
            self._cleanup_socket()
            return False

    # Framing terminator both agents emit at the end of every message.
    _FRAME_TERMINATOR = b" \n\n"

    def _extract_frames(self) -> list:
        """
        Pull every complete frame currently in self._recv_buffer.

        Each frame's bytes are everything before the ' \n\n' terminator.  The
        terminator itself is consumed.  Any trailing bytes that don't yet form
        a complete frame stay in the buffer for the next recv().
        """
        frames = []
        term = self._FRAME_TERMINATOR
        while True:
            idx = self._recv_buffer.find(term)
            if idx < 0:
                break
            frames.append(self._recv_buffer[:idx])
            self._recv_buffer = self._recv_buffer[idx + len(term):]
        return frames

    def _process_decoded_frame(self, decoded_data: str) -> None:
        """Handle one fully-framed, decoded message from the agent."""
        if not decoded_data:
            return

        # B1: try to render a recognised agent reply; fall back to the raw
        # '[APP MESSAGE] …' echo when no renderer matches.  Done before
        # updating last_agent_response so synchronous callers (agent_exec)
        # only unblock after the rendered output is on screen — avoids the
        # prompt redrawing in the middle of it.
        if not self._sandbox_shell_active:
            rendered = self._render_agent_reply(decoded_data)
            if not rendered:
                self._print_message("INFO", f"[APP MESSAGE] {decoded_data}")

        # Capture the latest agent message so synchronous commands (e.g.
        # agent_exec) can wait for and consume the reply.
        self.last_agent_response = decoded_data
        if decoded_data.startswith("EXEC_RESULT:"):
            # The shell_exec command is waiting on this
            self.exec_result = decoded_data[len("EXEC_RESULT:"):].strip()

        # --- COMMAND_REQUEST from the on-device agent (HarmonyOS GUI flow) ---
        if decoded_data.startswith('COMMAND_REQUEST:'):
            command_payload = decoded_data[len('COMMAND_REQUEST:'):].strip()
            self._print_message("INFO", f"Received command request from app: '{command_payload}'")
            self._process_app_command_request(command_payload)

        # --- HarmonyOS-only: UDMF_QUERY_RESULT from on-device ArkTS app ---
        # UDMF (Unified Data Management Framework) is a HarmonyOS concept;
        # gated so Android replies of similar shape are not mis-parsed here.
        elif self.platform.name == "harmonyos" and decoded_data.startswith('UDMF_QUERY_RESULT:'):
            result_payload = decoded_data[len('UDMF_QUERY_RESULT:'):].strip()
            try:
                udmf_data = json.loads(result_payload)
                print("\n--- UDMF Query Result ---")
                print(f"  URI: {udmf_data.get('uri', 'N/A')}")
                if udmf_data.get('content'):
                    print("  Content:")
                    for i, item in enumerate(udmf_data['content']):
                        print(f"    {i+1}. {item}")
                else:
                    print("  No content found for this URI.")
                print("-------------------------\n")
            except json.JSONDecodeError:
                print(f"\n--- UDMF Query Result (Raw) ---")
                print(result_payload)
                print("-----------------------------\n")
        # --- HarmonyOS-only: UDMF_APPS_WITH_CONTENT from on-device ArkTS app ---
        elif self.platform.name == "harmonyos" and decoded_data.startswith('UDMF_APPS_WITH_CONTENT:'):
            result_payload = decoded_data[len('UDMF_APPS_WITH_CONTENT:'):].strip()
            try:
                apps_with_content = json.loads(result_payload)
                print("\n--- Apps with UDMF Content ---")
                if apps_with_content:
                    for app_info in apps_with_content:
                        print(f"  - {app_info.get('bundleName', 'N/A')}")
                else:
                    print("  No applications found with UDMF content for the specified group ID.")
                print("------------------------------\n")
            except json.JSONDecodeError:
                print(f"\n--- Apps with UDMF Content (Raw) ---")
                print(result_payload)
                print("----------------------------------\n")
        # --- END HarmonyOS-only handlers ---

        # In case the app sends JSON in the future, keep this simple check.
        try:
            if decoded_data.startswith('[') and decoded_data.endswith(']'):
                parsed_json = json.loads(decoded_data)
                print("--- JSON Response (formatted) ---")
                print(json.dumps(parsed_json, indent=2))
                print("-------------------------------")
        except json.JSONDecodeError:
            pass

    def _receive_loop(self):
        """
        Accumulate raw bytes into self._recv_buffer and dispatch each complete
        ' \n\n'-terminated frame.  Fixes the open TODO: a single recv() of up
        to buffer_size bytes is no longer assumed to be a complete message,
        so large replies (apps_list, app_surface) round-trip intact.
        """
        self._print_message("DEBUG", "Asynchronous receive loop started in background.")
        while self._receive_thread_running and self.connected:
            try:
                chunk = self.socket.recv(self.buffer_size)
                if not chunk:
                    self._print_message("INFO", "Server disconnected gracefully (received no data).")
                    self.connected = False
                    self._receive_thread_running = False
                    self._cleanup_socket()
                    break

                self._recv_buffer += chunk

                # Recover from a peer that never terminates a frame.
                if len(self._recv_buffer) > self._max_recv_buffer:
                    self._print_message(
                        "WARNING",
                        f"Receive buffer exceeded {self._max_recv_buffer} bytes with "
                        "no framing terminator; dropping accumulated data to recover."
                    )
                    self._recv_buffer = b""
                    continue

                frames = self._extract_frames()
                if not frames:
                    continue

                # Clear the prompt once before the batch and redraw once after,
                # so multiple replies arriving in a single recv() don't flicker.
                if self._input_active:
                    sys.stdout.write(
                        '\r' + ' ' * (len(self._current_prompt_text) + self.buffer_size) + '\r'
                    )
                    sys.stdout.flush()

                for raw_frame in frames:
                    try:
                        decoded_data = raw_frame.decode('utf-8').strip()
                    except UnicodeDecodeError as e:
                        self._print_message("WARNING", f"Discarding non-UTF-8 frame: {e}")
                        continue
                    self._process_decoded_frame(decoded_data)

                if self._input_active:
                    sys.stdout.write(self._current_prompt_text)
                    sys.stdout.flush()

            except ConnectionResetError:
                self._print_message("INFO", f"Connection forcibly closed by the {self._agent_label}.")
                self.connected = False
                self._receive_thread_running = False
                self._cleanup_socket()
                break
            except socket.timeout:
                pass  # Timeout on recv is okay, means no data for now
            except Exception as e:
                if self.connected:
                    self._print_message("ERROR", f"Error receiving data in receive loop: {e}")
                self.connected = False
                self._receive_thread_running = False
                self._cleanup_socket()
                break 
        self._print_message("DEBUG", "Receive loop terminated.")

    def _process_app_command_request(self, command_payload: str):
        """
        Processes a command request originating from the on-device agent.

        Instead of duplicating logic for each command, we:
        - parse the command name + args
        - delegate to the same command implementations used by the CLI
        - mark the source as 'app', so commands can behave slightly differently.
        """
        parts = command_payload.split()
        if not parts:
            error_msg = "Empty command from app."
            self._print_message("ERROR", error_msg)
            self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
            return

        cmd_name = parts[0].lower()
        args = parts[1:]

        # If the app accidentally sends '-a', strip it. It is usually implicit.
        if "-a" in args:
            args = [a for a in args if a != "-a"]

        self._print_message("DEBUG", f"Received app command: {cmd_name} {args}")
        self.execute_command(cmd_name, args, source="app")


    def execute_command(self, command_name: str, args: list[str], source: CommandSource):
        """
        Dispatch a command (from CLI or app) using the command registry.

        Behaviour:
        - Handles generic '--log' flag.
        - If '--log' is used and the command supports logging:
                * Start device logging before the command
                * Stop logging + fetch the log file afterwards
        - Provides a per-command logging context via self.is_logging_enabled().
        """
        cmd = get_command(command_name)
        if not cmd:
            self._print_message(
                "INFO",
                f"Unknown command: '{command_name}'. Type 'help' for available commands."
            )
            return

        # B7: '--via-agent' routes the command through the on-device Kotlin agent
        # instead of running it directly via adb.  Only meaningful on Android, and
        # only for commands the agent's CommandHandler actually dispatches.
        if "--via-agent" in args:
            args = [a for a in args if a != "--via-agent"]
            if self.platform.name != "android":
                self._print_message(
                    "WARNING",
                    "'--via-agent' only applies to --platform android; running locally."
                )
            else:
                from commands.android.agent_exec import (
                    AGENT_SUPPORTED_COMMANDS,
                    route_via_agent,
                )
                if command_name not in AGENT_SUPPORTED_COMMANDS:
                    self._print_message(
                        "WARNING",
                        f"Command '{command_name}' is not implemented on the agent; "
                        "running locally."
                    )
                else:
                    payload = " ".join([command_name] + args)
                    route_via_agent(self, payload)
                    return

        # 1) Generic logging flag handling
        log_requested = False
        if "--log" in args:
            if cmd.supports_logging:
                log_requested = True
                args = [a for a in args if a != "--log"]
            else:
                args = [a for a in args if a != "--log"]
                self._print_message(
                    "WARNING",
                    f"Command '{command_name}' does not support logging. Ignoring '--log'."
                )

        # 2) Per-command logging context (for console.log_output / is_logging_enabled)
        prev_log_flag = self._current_command_log_enabled
        self._current_command_log_enabled = log_requested

        # 3) Device logging lifecycle
        device_logging_started = False
        try:
            if log_requested:
                # If anything fails here, we don't want to break the main command completely
                try:
                    self._print_message(
                        "INFO",
                        f"Logging started."
                    )
                    self._start_device_logging_for_command(command_name)
                    device_logging_started = True
                except Exception as e:
                    self._print_message(
                        "WARNING",
                        f"Failed to start device logging for '{command_name}': {e}"
                    )
                    # You might choose to proceed without logging

            # 4) Execute the actual command
            cmd.execute(self, args, source)

        except Exception as e:
            self._print_message("ERROR", f"Unhandled exception in command '{command_name}': {e}")

        finally:
            # 5) Stop logging and fetch file if it was started
            if log_requested and device_logging_started:
                try:
                    self._stop_and_fetch_device_logging_for_command(command_name)
                except Exception as e:
                    self._print_message(
                        "WARNING",
                        f"Failed to stop/fetch device logging for '{command_name}': {e}"
                    )

            # Restore previous logging context
            self._current_command_log_enabled = prev_log_flag

    def send_data_to_app(self, data_str):
        """Sends data string to the on-device agent."""
        if not self.connected or not self.socket:
            self._print_message("INFO", f"Not connected to the {self._agent_label}. Cannot send data.")
            return False
        try:
            data_str += " \n\n"
            encoded_data = data_str.encode('utf-8')
            if len(encoded_data) > self.buffer_size:
                self._print_message("WARNING", f"Data to send ({len(encoded_data)} bytes) exceeds buffer size ({self.buffer_size} bytes). This might cause truncation or errors on the receiving end.")
            
            self.socket.sendall(encoded_data)
            self._print_message("DEBUG", f"Sent to {self._agent_label} (first 100 chars): '{data_str[:100]}...'")
            return True
        except Exception as e:
            self._print_message("ERROR", f"Error sending data to {self._agent_label}: {e}")
            self.connected = False 
            self._receive_thread_running = False
            self._cleanup_socket()
            return False

    def disconnect(self):
        """Closes the client connection."""
        if not self.connected and not self.socket and not self._receive_thread_running:
            self._print_message("INFO", "Already fully disconnected.")
            return

        self._print_message("INFO", "Disconnecting...")
        self.connected = False 
        self._receive_thread_running = False 
        self.device_id = None
        self.device_name = "No Device"
        self.user_name_on_device = "You"
        self._update_prompt()

        if self.receive_thread and self.receive_thread.is_alive():
            self._print_message("DEBUG", "Waiting for receive thread to finish gracefully...")
            self.receive_thread.join(timeout=1) 
            if self.receive_thread.is_alive():
                self._print_message("DEBUG", "Receive thread did not terminate gracefully after 1 sec.")
        self.receive_thread = None

        self._cleanup_socket() 
        self._print_message("INFO", "Disconnected.")

    def _run_shell_and_dispatch(self, hdc_shell_cmd_args, send_to_app_type=None, console_output_prefix="", force_send_to_app=False):
        """
        Executes an hdc shell command, prints to console, and optionally sends to app
        with a specific message type.

        Args:
            hdc_shell_cmd_args (list): List of arguments for the hdc shell command (e.g., ["bm", "dump", "-a"]).
            send_to_app_type (str | None): Specifies the message type prefix for sending
                                            to the app (e.g., "HDC_OUTPUT_ALL_APPS"). If None,
                                            output is not sent to the app.
            console_output_prefix (str): Prefix for the output when printed to console.
            force_send_to_app (bool): If True, output is always sent to the app if connected,
                                      overriding local console printing for success cases.
        """
        if not self.device_id:
            error_msg = (
                f"No {self.platform.name} device is connected via "
                f"'{self.platform.bridge_command}'. Cannot execute shell commands."
            )
            self._print_message("ERROR", error_msg)
            if send_to_app_type and self.connected:
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
            return

        full_hdc_args = self.platform.device_shell_args(self.device_id) + hdc_shell_cmd_args

        self._print_message(
            "INFO",
            f"Executing: '{self.platform.bridge_command} {' '.join(full_hdc_args)}'..."
        )
        stdout, stderr, retcode = self._run_bridge(full_hdc_args)

        if retcode == 0:
            raw_output = stdout
            if not raw_output:
                raw_output = f"Command '{' '.join(hdc_shell_cmd_args)}' executed successfully, but returned no output."
            
            if (send_to_app_type and self.connected) or force_send_to_app: # Send to app if requested OR forced
                if self.connected: # Double-check connection before sending
                    self._print_message("INFO", f"Sending raw bridge command output to {self._agent_label} via socket with type: {send_to_app_type}.")
                    output_to_send = raw_output.strip()
                    self.send_data_to_app(f"{send_to_app_type}:{output_to_send}")
                else: # This case should ideally not happen if force_send_to_app implies connected
                    self._print_message("WARNING", f"Cannot send hdc output of type '{send_to_app_type}' to app: Socket connection not established. Printing to console instead.")
                    print(f"\n{console_output_prefix}\n{raw_output}\n") # Fallback to console print
            else: # Not sending to app, so print to console
                print(f"\n{console_output_prefix}\n{raw_output}\n")
        else:
            error_msg = stderr if stderr else 'No stderr output.'
            self._print_message("ERROR", f"Command '{' '.join(hdc_shell_cmd_args)}' failed with exit code {retcode}.")
            self._print_message("ERROR", f"[HDC STDERR]\n{error_msg}")
            
            # Always send error to app if connection exists and it was meant for app (send_to_app_type provided)
            # or if it was a forced send (meaning the request came from the app)
            if (send_to_app_type and self.connected) or force_send_to_app:
                error_send_type = send_to_app_type.replace("OUTPUT", "ERROR") if send_to_app_type and "OUTPUT" in send_to_app_type else "HDC_OUTPUT_ERROR"
                self._print_message("INFO", f"Sending bridge command error output to {self._agent_label} via socket with type: {error_send_type}...")
                self.send_data_to_app(f"{error_send_type}:{error_msg}") 
            else: # If not sending to app or not connected, always print error to console
                print(f"\n--- HDC Command Error ({' '.join(hdc_shell_cmd_args)}) ---\n{error_msg}\n-----------------------------------\n")

    def _update_prompt(self):
        """Updates the command prompt with platform-themed colours."""
        th  = get_theme(self.platform.name)
        pc  = th.PROMPT_CONN if self.connected else th.PROMPT_DISC
        self._current_prompt_text = (
            f"{pc}[{self.user_name_on_device}@{self.device_name}]{_RST}"
            f" {_DIM}›{_RST} "
        )


                
    def invoke_ability_with_want(self, bundle_name, ability_name, key, value, send_to_app=False):
        """
        Invokes an ability with a Want (key + value) using hdc.
        
        Args:
            app (str): Bundle name of the app.
            ability (str): Name of the ability.
            key (str): Custom Want key.
            value (str): Custom Want value.
            send_to_app (bool): If True, output will be sent back to the app.
        
        Notes:
            Further development needed, there are many parameter types when invoking an ability.
        """
        # Command should be:
        #hdc -t 23E0223C01002818 shell aa start -b com.dekra.dvha -a ExposedCredentialsAbility --ps status already_logged

        cmd = self.platform.device_shell_args(self.device_id) + [
            "aa", "start",
            "-b", bundle_name,
            "-a", ability_name,
            "--params", key, value,
        ]

        stdout, stderr, ret = self._run_bridge(cmd)

        self._print_message("INFO",f"stdout: {stdout}")
        self._print_message("INFO",f"stderr: {stderr}")
        self._print_message("INFO",f"ret: {ret}")


    def _print_help(self):
        """Prints available commands with full platform-themed colouring."""
        th  = get_theme(self.platform.name)
        R   = _RST
        is_android   = self.platform.name == "android"
        is_harmonyos = self.platform.name == "harmonyos"
        W = 54   # column width for rule lines

        # ── Header ────────────────────────────────────────────────────────
        platform_label = self.platform.name.upper()
        print(f"\n{th.HEADER}{'━' * W}{R}")
        print(f"{th.HEADER}  Harm0nyz3r  ›  {platform_label}{R}")
        print(f"{th.HEADER}{'━' * W}{R}")

        # ── Status block ──────────────────────────────────────────────────
        if self.connected:
            conn_str = f"{th.CONNECTED}✅  CONNECTED   (MARCO-POLO handshake OK){R}"
        else:
            conn_str = f"{th.DISCONNECTED}❌  DISCONNECTED  or  HANDSHAKE FAILED{R}"

        verbose_str = (
            f"{th.VERBOSE_ON}ON{R}"  if self.verbose
            else f"{th.VERBOSE_OFF}OFF{R}"
        )
        dev_id = self.device_id if self.device_id else "none"

        print(f"  {th.LABEL}server   {R}  {th.VALUE}{self.host}:{self.port}{R}")
        print(f"  {th.LABEL}status   {R}  {conn_str}")
        print(f"  {th.LABEL}device   {R}  {th.VALUE}{self.device_name}{R}  "
              f"{th.LABEL}id:{R} {th.VALUE}{dev_id}{R}")
        print(f"  {th.LABEL}verbose  {R}  {verbose_str}")
        print(f"{th.SEPARATOR}{'─' * W}{R}")

        # ── Setup (shown only when disconnected) ──────────────────────────
        if not self.connected:
            print(f"\n  {th.SETUP_TAG}[ SETUP ]{R}")
            if is_android:
                steps = [
                    "Install & launch the Harm0niz3r app on the Android device.",
                    f"Tap 'Start Agent' — listens on 127.0.0.1:{self.port}.",
                    f"Type  {th.EX_CMD}connect{R}  — the adb port forward is set up automatically.",
                ]
            elif is_harmonyos:
                steps = [
                    "Install the Harm0niz3r HAP on the HarmonyOS device.",
                    f"Forward the port:  {th.EX_CMD}hdc fport tcp:{self.port} tcp:{self.port}{R}",
                    f"Launch the app, then type  {th.EX_CMD}connect{R}.",
                ]
            else:
                steps = [f"Set up port forwarding and type  {th.EX_CMD}connect{R}."]

            for i, step in enumerate(steps, 1):
                print(f"  {th.STEP_NUM}{i}.{R}  {th.STEP_TEXT}{step}{R}")

        # ── Core commands ─────────────────────────────────────────────────
        bridge = self.platform.bridge_command
        print(f"\n{th.SECTION}  Core Commands{R}")
        print(f"{th.SEPARATOR}  {'─' * (W - 2)}{R}")

        core_cmds = [
            ("help",               "Show this help screen."),
            ("exit / quit",        "Quit Harm0nyz3r."),
            ("connect",            f"TCP session + MARCO-POLO handshake  (bridge: {bridge})."),
            ("disconnect",         "Close the current agent session."),
            ("verbose [on|off]",   f"Toggle verbose output.  Now: {'ON' if self.verbose else 'OFF'}"),
        ]
        for name, desc in core_cmds:
            print(f"  {th.CMD_NAME}{name:<22}{R}  {th.CMD_DESC}{desc}{R}")

        # ── Platform commands ─────────────────────────────────────────────
        if is_android:
            section_title = "Android Commands  (adb + agent on device)"
        elif is_harmonyos:
            section_title = "HarmonyOS Commands  (hdc + agent on device)"
        else:
            section_title = f"Commands  [{self.platform.name}]"

        print(f"\n{th.SECTION}  {section_title}{R}")
        print(f"{th.SEPARATOR}  {'─' * (W - 2)}{R}")
        if is_android:
            print(
                f"  {th.CMD_DESC}Append {th.EX_CMD}--via-agent{R}{th.CMD_DESC} to any "
                f"agent-supported command to route it through the on-device agent "
                f"instead of direct adb.{R}"
            )
            print()

        for cmd in list_commands():
            help_lines = cmd.help().splitlines()
            if not help_lines:
                continue
            # Split signature from description at ' – ' or ' - ' or '  '
            first = help_lines[0]
            sig, desc = first, ""
            for sep in (" \u2013 ", " - ", "   "):
                if sep in first:
                    sig, desc = first.split(sep, 1)
                    break
            sig  = sig.strip()
            desc = desc.strip()
            print(f"  {th.CMD_NAME}{sig:<28}{R}  {th.CMD_DESC}{desc}{R}")
            for line in help_lines[1:]:
                print(f"      {th.CMD_DESC}{line.strip()}{R}")

        # ── Quick examples ────────────────────────────────────────────────
        if is_android:
            examples = [
                ("apps_list",        "-3"),
                ("app_info",         "com.example.target"),
                ("app_surface",      "com.example.target"),
                ("apps_exported_activities", ""),
                ("app_ability",      "com.example.target .MainActivity"),
                ("app_ability_want", "com.example.target .LoginActivity username=admin"),
                ("app_deeplink",     "myapp://admin/panel"),
                ("app_broadcast",    "com.example.REFRESH -n com.example.target/.Receiver"),
                ("app_permissions",  "com.example.target --dangerous"),
                ("app_provider",     "content://com.example.target.provider/users"),
                ("shell_exec",       ""),
            ]
            print(f"\n{th.EX_HDR}  Quick examples  ›  Android{R}")
        elif is_harmonyos:
            examples = [
                ("apps_list",        "-a"),
                ("app_info",         "com.example.bundle"),
                ("app_surface",      "com.example.bundle"),
                ("apps_visible_abilities", ""),
                ("app_ability",      "com.example.bundle ExposedAbility"),
                ("app_ability_want", "com.example.bundle ExposedAbility myKey myValue"),
                ("app_udmf",         "com.example.bundle"),
            ]
            print(f"\n{th.EX_HDR}  Quick examples  ›  HarmonyOS{R}")
        else:
            examples = []

        if examples:
            print(f"{th.SEPARATOR}  {'─' * (W - 2)}{R}")
            for ex_cmd, ex_args in examples:
                if ex_args:
                    print(f"  {th.EX_CMD}{ex_cmd}{R}  {th.EX_ARG}{ex_args}{R}")
                else:
                    print(f"  {th.EX_CMD}{ex_cmd}{R}")

        # ── No-device hint ────────────────────────────────────────────────
        if not self.device_id:
            print(
                f"\n  {th.HINT_TAG}⚠  No {self.platform.name} device detected via "
                f"'{self.platform.bridge_command}'.  "
                f"Run '{self.platform.bridge_command} devices' to verify.{R}"
            )

        # ── Footer ────────────────────────────────────────────────────────
        print(f"{th.FOOTER}{'━' * W}{R}\n")

    def process_command_line(self, command_line: str, source: str = "cli") -> None:
        """
        Parse and execute a single console line, handling:
          - built-in/meta commands (help, connect, verbose, disconnect, exit)
          - registered commands via execute_command()

        'source' can be "cli" for interactive input or "script" for run_script.
        """
        command_line = command_line.strip()
        if not command_line:
            return

        parts = command_line.split()
        if not parts:
            return

        command = parts[0].lower()
        args = parts[1:]

        # -----------------------------
        # Meta / built-in console cmds
        # -----------------------------
        if command in ("exit", "quit"):
            if source == "cli":
                self._print_message("INFO", "Exiting Harm0nyz3r...")
                self.running = False
            else:
                # In scripts, we usually don't want to kill the whole console;
                # you can change this behaviour if you prefer.
                self._print_message(
                    "INFO",
                    "Ignoring 'exit/quit' inside script. Use 'disconnect' instead if needed."
                )
            return

        if command == "help":
            self._print_help()
            return

        if command == "connect":
            # connect [host] [port]
            if len(args) == 0:
                # use default from config
                self.connect()
            elif len(args) == 2:
                try:
                    host = args[0]
                    port = int(args[1])
                except ValueError:
                    self._print_message("ERROR", "Usage: connect [host] [port]")
                    return
                self.connect(host, port)
            else:
                self._print_message("INFO", "Usage: connect [host] [port]")
            return

        if command == "disconnect":
            self.disconnect()
            return

        if command == "verbose":
            if len(args) != 1 or args[0].lower() not in ("on", "off"):
                self._print_message("INFO", "Usage: verbose [on|off]")
                return
            self.verbose = (args[0].lower() == "on")
            self._print_message(
                "INFO",
                f"Verbose mode {'enabled' if self.verbose else 'disabled'}."
            )
            return

        # --------------------------------------
        # All other commands via the registry
        # --------------------------------------
        self.execute_command(command, args, source=source)

    def _open_session_log(self) -> None:
        """B16: open the transcript file (if --session-log was given) and tee stdout."""
        if not self._session_log_path:
            return
        try:
            log_dir = os.path.dirname(self._session_log_path) or "."
            if log_dir and log_dir != ".":
                os.makedirs(log_dir, exist_ok=True)
            self._session_log_file = open(self._session_log_path, "w", encoding="utf-8")
            self._session_log_file.write(
                f"# Harm0nyz3r session log\n"
                f"# platform : {self.platform.name}\n"
                f"# host     : {self.host}:{self.port}\n"
                f"# started  : {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )
            self._session_log_file.flush()
            self._original_stdout = sys.stdout
            sys.stdout = _TeeStdout(self._original_stdout, self._session_log_file)
        except Exception as e:
            # Don't let a logging hiccup take down the console.
            self._print_message("WARNING", f"Could not open session log: {e}")
            self._session_log_file = None

    def _close_session_log(self) -> None:
        """Restore the original stdout and close the transcript file."""
        if self._original_stdout is not None:
            try:
                sys.stdout = self._original_stdout
            except Exception:
                pass
            self._original_stdout = None
        if self._session_log_file is not None:
            try:
                self._session_log_file.write(
                    f"\n# ended    : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
                self._session_log_file.flush()
                self._session_log_file.close()
            except Exception:
                pass
            self._session_log_file = None

    def start_console(self):
        """Starts the interactive console loop."""
        self._open_session_log()
        try:
            print(get_ascii_art(self.platform.name))  # Platform-aware banner
            if self._session_log_path:
                self._print_message(
                    "INFO",
                    f"Session transcript will be written to '{self._session_log_path}'."
                )
            self._detect_device()
            self._update_prompt()

            # Auto-connect on startup so the user doesn't have to type 'connect' manually.
            # If the agent isn't running yet this fails silently; the user can retry with 'connect'.
            self._print_message("INFO", f"Auto-connecting to agent at {self.host}:{self.port}...")
            self.connect()

            self._print_help()

            while self.running:
                try:
                    self._input_active = True
                    command_line = input(self._current_prompt_text).strip()
                    self._input_active = False

                    self.process_command_line(command_line, source="cli")

                except KeyboardInterrupt:
                    print()  # newline
                    self._print_message("INFO", "Use 'exit' or 'quit' to leave Harm0nyz3r.")
                except EOFError:
                    self._print_message("INFO", "EOF received. Exiting console.")
                    break
                except Exception as e:
                    self._print_message("ERROR", f"Unexpected error in console loop: {e}")

            # On exit, cleanup
            self.disconnect()
            self._print_message("INFO", "Goodbye!")
        finally:
            self._close_session_log()

    # ------------------------------------------------------------------
    # Backwards-compatibility shims for the HarmonyOS command layer.
    # The canonical attribute and method names are bridge-neutral
    # (device_id / _detect_device / _run_bridge / _run_shell / ...).
    # The hdc_* names below are retained as aliases so existing HarmonyOS
    # commands keep working without modification.  New code (Android,
    # iOS, shared) should use the canonical names.
    # ------------------------------------------------------------------

    @property
    def hdc_device_id(self):
        return self.device_id

    @hdc_device_id.setter
    def hdc_device_id(self, value):
        self.device_id = value

    @property
    def hdc_device_name(self):
        return self.device_name

    @hdc_device_name.setter
    def hdc_device_name(self, value):
        self.device_name = value

    _get_hdc_device_info = _detect_device
    _execute_hdc_command = _run_bridge
    _get_hdc_shell_output = _run_shell
    _execute_and_handle_hdc_command = _run_shell_and_dispatch


# Backwards-compat alias — older HarmonyOS command docstrings reference the
# previous class name.  New code should use Harm0nyz3rConsole.
HarmonyOSClientConsole = Harm0nyz3rConsole


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Harm0nyz3r — Multi-platform App Security Companion"
    )
    parser.add_argument(
        "--platform",
        choices=list_platforms(),
        default=DEFAULT_PLATFORM,
        help=(
            f"Target device platform (default: {DEFAULT_PLATFORM}). "
            f"Available: {', '.join(list_platforms())}"
        ),
    )
    parser.add_argument(
        "--host",
        default=SERVER_HOST,
        help=f"Agent TCP host (default: {SERVER_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=PORT,
        help=f"Agent TCP port (default: {PORT})",
    )
    parser.add_argument(
        "--device", "-s",
        dest="device",
        default=None,
        help=(
            "Pin to a specific device serial (use the same value 'adb devices' shows). "
            "When omitted, a single device is auto-picked and multiple devices on "
            "--platform android trigger an interactive picker."
        ),
    )
    parser.add_argument(
        "--session-log",
        dest="session_log",
        nargs="?",
        const="__AUTO__",
        default=None,
        help=(
            "Tee all console output to a transcript file (ANSI stripped). "
            "Optional path; default: logs/session-<YYYYmmdd_HHMMSS>.log."
        ),
    )
    args = parser.parse_args()

    session_log_path = args.session_log
    if session_log_path == "__AUTO__":
        session_log_path = os.path.join(
            "logs", f"session-{time.strftime('%Y%m%d_%H%M%S')}.log"
        )

    client_console = Harm0nyz3rConsole(
        host=args.host,
        port=args.port,
        buffer_size=BUFFER_SIZE,
        platform_name=args.platform,
        device_id=args.device,
        session_log_path=session_log_path,
    )
    client_console.start_console()
