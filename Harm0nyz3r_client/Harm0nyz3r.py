# -*- coding: utf-8 -*-
"""
 ==========================================================
 HARM0NYZ3R - HarmonyOS Security Companion
 ==========================================================
 Author: DEKRA
 Version: 1.2.1
 License: Apache 2.0
 ==========================================================

TODO:
    - Stablish a receiving limit in client to avoid buffer overflow flaw when receiving data.
    - Add support for ' \n\n' ending trail when client -> server communication.
    - Fix invoke with params (design must be done before).
    - Add support to call invoke_with_want functionality from CLI.
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

# --- Import the new parser module ---
from harmonyos_parser import parse_app_dump_string

from config import VERSION, SERVER_HOST, PORT, BUFFER_SIZE, DEFAULT_PLATFORM, PLATFORM_CONFIGS, HARMONYZER_ASCII, get_ascii_art, get_level_label, get_theme, _RST, _DIM, _BOLD, _GREY
from platforms import get_platform, list_platforms
from commands import register_command, get_command, list_commands
# HarmonyOS command modules (loaded always; registered conditionally below)
from commands import apps_list, app_info, app_surface, apps_visible_abilities, app_udmf, apps_udmf, app_ability, app_ability_want, app_ability_fuzz, app_ability_fuzz_dict, run_script, net_send, shell_exec
# Android command package (registered when --platform android)
from commands import android as android_commands
from commands.base import CommandSource

class HarmonyOSClientConsole:
    """
    A TCP client that connects to the on-device agent and provides a console interface.
    Platform-specific bridge operations (hdc / adb / iproxy) are delegated to
    self.platform so that the rest of this class remains platform-agnostic.
    """
    def __init__(self, host, port, buffer_size=4096, platform_name=DEFAULT_PLATFORM):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.platform = get_platform(platform_name)
        self.socket = None
        self.connected = False
        self.receive_thread = None
        self.running = True
        self._receive_thread_running = False

        self._input_active = False
        self._current_prompt_text = "[You] Enter command: "
        self.hdc_device_id = None
        self.hdc_device_name = "No Device"
        self.user_name_on_device = "You"
        self.verbose = False
        self._register_builtin_commands()
        self._current_command_log_enabled = False
        self.log_file_path = None
        # --- shell_exec / sandbox shell state ---
        self.exec_result = None
        self._sandbox_shell_active = False
        
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
            android_commands.apps_visible_abilities.register(register_command)
            android_commands.app_ability.register(register_command)
            android_commands.app_ability_want.register(register_command)
            android_commands.app_ability_fuzz.register(register_command)
            android_commands.app_broadcast.register(register_command)
            android_commands.app_deeplink.register(register_command)
            android_commands.app_permissions.register(register_command)
            android_commands.app_provider.register(register_command)
            android_commands.shell_exec.register(register_command)

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
        if not self.hdc_device_id:
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

        # Use your existing _get_hdc_shell_output or _execute_hdc_command:
        stdout, stderr, retcode = self._get_hdc_shell_output(
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
        if not self.hdc_device_id or not self._device_log_remote_path:
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
            _, stderr_kill, ret_kill = self._get_hdc_shell_output(
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

        recv_cmd = self.platform.pull_file_args(self.hdc_device_id, remote, local)
        stdout_recv, stderr_recv, ret_recv = self._execute_hdc_command(recv_cmd)

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
        rm_cmd = ["-t", self.hdc_device_id, "shell", f"rm -f {remote}"]
        _, stderr_rm, ret_rm = self._execute_hdc_command(rm_cmd)
        if ret_rm != 0 and self.verbose:
            self._print_message(
                "WARNING",
                f"Failed to remove remote log file {remote}: {stderr_rm or 'unknown error'}"
            )

        # 4) Reset state
        self._device_log_remote_path = None
        self._device_log_local_path = None
        self._device_log_pid = None


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

    def _execute_hdc_command(self, args_list):
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

    def _get_hdc_shell_output(self, hdc_shell_cmd_args):
        """
        Executes a device shell command via the active platform bridge.
        This function does NOT handle printing or sending to the agent;
        it just retrieves the raw output.
        """
        if not self.hdc_device_id:
            self._print_message(
                "ERROR",
                f"No {self.platform.name} device is connected. "
                f"Cannot execute shell commands."
            )
            return "", f"No {self.platform.name} device found.", -1

        full_hdc_args = self.platform.device_shell_args(self.hdc_device_id) + hdc_shell_cmd_args
        self._print_message(
            "INFO",
            f"Executing: '{self.platform.bridge_command} {' '.join(full_hdc_args)}'"
        )
        stdout, stderr, retcode = self._execute_hdc_command(full_hdc_args)
        return stdout, stderr, retcode

    def _get_hdc_device_info(self):
        """
        Detects a connected device via the active platform adapter and
        updates self.hdc_device_id / hdc_device_name / user_name_on_device.
        """
        self.hdc_device_id = None
        self.hdc_device_name = "No Device"
        self.user_name_on_device = "You"

        self._print_message(
            "INFO",
            f"Detecting {self.platform.name} device via '{self.platform.bridge_command}'..."
        )

        device_id, device_name = self.platform.detect_device()

        if not device_id:
            self._print_message(
                "INFO",
                f"No {self.platform.name} devices detected via '{self.platform.bridge_command}'."
            )
            return False

        self.hdc_device_id = device_id
        self.hdc_device_name = device_name or device_id
        self._print_message(
            "SUCCESS",
            f"Detected {self.platform.name} device: "
            f"ID='{self.hdc_device_id}', Name='{self.hdc_device_name}'"
        )

        # Try whoami (generic shell command — works on both HarmonyOS and Android)
        self._print_message("DEBUG", "Attempting 'whoami' on device...")
        whoami_args = self.platform.device_shell_args(self.hdc_device_id) + ["whoami"]
        user_stdout, user_stderr, user_retcode = self._execute_hdc_command(whoami_args)
        if user_retcode == 0 and user_stdout:
            self.user_name_on_device = user_stdout.strip()
        else:
            self._print_message(
                "WARNING",
                f"'whoami' failed (retcode: {user_retcode}). Defaulting to 'You'."
            )

        return True

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
        hdc_device_found = self._get_hdc_device_info()

        self._update_prompt()

        if not hdc_device_found:
            self._print_message(
                "INFO",
                f"No active {self.platform.name} device detected. "
                "Some commands (e.g., 'apps_list', 'app_info') might not work."
            )

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
            self._print_message("DEBUG", f"Sent handshake command: '{handshake_command}' to the HarmonyOS server.")

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
            self._print_message("INFO", "   - Is the HarmonyOS server app running?")
            self._print_message("INFO", "   - Is the HarmonyOS server listening on the correct IP and port?")
            self._print_message("INFO", "   - Are there any firewalls blocking the connection on either side?")
            self._cleanup_socket()
            return False
        except ConnectionRefusedError:
            self._print_message("ERROR", f"Connection refused by {self.host}:{self.port}.")
            self._print_message("INFO", "   - This usually means no server is actively listening on that address/port.")
            self._print_message("INFO", "   - Please ensure the HarmonyOS server is running and accessible from this machine.")
            self._cleanup_socket()
            return False
        except Exception as e:
            self._print_message("FATAL_ERROR", f"An unexpected error occurred during connection/handshake: {e}")
            self._cleanup_socket()
            return False

    def _receive_loop(self):
        """Internal method to continuously receive data from the server."""
        self._print_message("DEBUG", "Asynchronous receive loop started in background.")
        while self._receive_thread_running and self.connected:
            try:
                data = self.socket.recv(self.buffer_size)
                if not data:
                    self._print_message("INFO", "Server disconnected gracefully (received no data).")
                    self.connected = False
                    self._receive_thread_running = False
                    self._cleanup_socket()
                    break 
                
                decoded_data = data.decode('utf-8').strip()
                
                # If the main input loop is active, clear the line, print, then redraw prompt
                if self._input_active:
                    sys.stdout.write('\r' + ' ' * (len(self._current_prompt_text) + self.buffer_size) + '\r') 
                    sys.stdout.flush()
                if not self._sandbox_shell_active:
                    self._print_message("INFO", f"[APP MESSAGE] {decoded_data}") # Print received data with clear tag
                if decoded_data.startswith("EXEC_RESULT:"):
                    # The shell_exec command is waiting on this
                    self.exec_result = decoded_data[len("EXEC_RESULT:") :].strip()
                # --- NEW: Handle COMMAND_REQUEST from HarmonyOS App ---
                if decoded_data.startswith('COMMAND_REQUEST:'):
                    command_payload = decoded_data[len('COMMAND_REQUEST:'):].strip()
                    self._print_message("INFO", f"Received command request from app: '{command_payload}'")
                    # Parse and execute the command from the app
                    self._process_app_command_request(command_payload)
                
                # --- END NEW ---

                # --- NEW: Handle UDMF_QUERY_RESULT from HarmonyOS App ---
                elif decoded_data.startswith('UDMF_QUERY_RESULT:'):
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
                # --- NEW: Handle UDMF_APPS_WITH_CONTENT from HarmonyOS App ---
                elif decoded_data.startswith('UDMF_APPS_WITH_CONTENT:'):
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
                # --- END NEW ---

                # In case the app sends JSON in the future, keep this simple check.
                try:
                    if decoded_data.startswith('[') and decoded_data.endswith(']'): # Expecting JSON array
                        parsed_json = json.loads(decoded_data)
                        print("--- JSON Response (formatted) ---")
                        print(json.dumps(parsed_json, indent=2))
                        print("-------------------------------")
                except json.JSONDecodeError:
                    pass

                if self._input_active:
                    sys.stdout.write(self._current_prompt_text)
                    sys.stdout.flush()

            except ConnectionResetError:
                self._print_message("INFO", "Connection forcibly closed by the HarmonyOS server.")
                self.connected = False
                self._receive_thread_running = False
                self._cleanup_socket()
                break 
            except socket.timeout:
                pass # Timeout on receive is okay, means no data for now
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
        Processes a command request originating from the HarmonyOS app.

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
        """Sends data string to the HarmonyOS app."""
        if not self.connected or not self.socket:
            self._print_message("INFO", "Not connected to the HarmonyOS app. Cannot send data.")
            return False
        try:
            data_str += " \n\n"
            encoded_data = data_str.encode('utf-8')
            if len(encoded_data) > self.buffer_size:
                self._print_message("WARNING", f"Data to send ({len(encoded_data)} bytes) exceeds buffer size ({self.buffer_size} bytes). This might cause truncation or errors on the receiving end.")
            
            self.socket.sendall(encoded_data)
            self._print_message("DEBUG", f"Sent to HarmonyOS App (first 100 chars): '{data_str[:100]}...'")
            return True
        except Exception as e:
            self._print_message("ERROR", f"Error sending data to HarmonyOS App: {e}")
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
        self.hdc_device_id = None
        self.hdc_device_name = "No Device"
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

    def _execute_and_handle_hdc_command(self, hdc_shell_cmd_args, send_to_app_type=None, console_output_prefix="", force_send_to_app=False):
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
        if not self.hdc_device_id:
            error_msg = (
                f"No {self.platform.name} device is connected via "
                f"'{self.platform.bridge_command}'. Cannot execute shell commands."
            )
            self._print_message("ERROR", error_msg)
            if send_to_app_type and self.connected:
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
            return

        full_hdc_args = self.platform.device_shell_args(self.hdc_device_id) + hdc_shell_cmd_args

        self._print_message(
            "INFO",
            f"Executing: '{self.platform.bridge_command} {' '.join(full_hdc_args)}'..."
        )
        stdout, stderr, retcode = self._execute_hdc_command(full_hdc_args)

        if retcode == 0:
            raw_output = stdout
            if not raw_output:
                raw_output = f"Command '{' '.join(hdc_shell_cmd_args)}' executed successfully, but returned no output."
            
            if (send_to_app_type and self.connected) or force_send_to_app: # Send to app if requested OR forced
                if self.connected: # Double-check connection before sending
                    self._print_message("INFO", f"Sending RAW hdc command output to HarmonyOS app via socket with type: {send_to_app_type}.")
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
                self._print_message("INFO", f"Sending hdc command error output to HarmonyOS app via socket with type: {error_send_type}...")
                self.send_data_to_app(f"{error_send_type}:{error_msg}") 
            else: # If not sending to app or not connected, always print error to console
                print(f"\n--- HDC Command Error ({' '.join(hdc_shell_cmd_args)}) ---\n{error_msg}\n-----------------------------------\n")

    def _update_prompt(self):
        """Updates the command prompt with platform-themed colours."""
        th  = get_theme(self.platform.name)
        pc  = th.PROMPT_CONN if self.connected else th.PROMPT_DISC
        self._current_prompt_text = (
            f"{pc}[{self.user_name_on_device}@{self.hdc_device_name}]{_RST}"
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

        cmd = self.platform.device_shell_args(self.hdc_device_id) + [
            "aa", "start",
            "-b", bundle_name,
            "-a", ability_name,
            "--params", key, value,
        ]

        stdout, stderr, ret = self._execute_hdc_command(cmd)

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
        dev_id = self.hdc_device_id if self.hdc_device_id else "none"

        print(f"  {th.LABEL}server   {R}  {th.VALUE}{self.host}:{self.port}{R}")
        print(f"  {th.LABEL}status   {R}  {conn_str}")
        print(f"  {th.LABEL}device   {R}  {th.VALUE}{self.hdc_device_name}{R}  "
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
                    f"Forward the port:  {th.EX_CMD}adb forward tcp:{self.port} tcp:{self.port}{R}",
                    f"Type  {th.EX_CMD}connect{R}  to establish the session.",
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
                ("apps_visible_abilities", ""),
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
        if not self.hdc_device_id:
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

    def start_console(self):
        """Starts the interactive console loop."""
        print(get_ascii_art(self.platform.name))  # Platform-aware banner
        self._get_hdc_device_info()
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
    args = parser.parse_args()

    client_console = HarmonyOSClientConsole(
        host=args.host,
        port=args.port,
        buffer_size=BUFFER_SIZE,
        platform_name=args.platform,
    )
    client_console.start_console()
