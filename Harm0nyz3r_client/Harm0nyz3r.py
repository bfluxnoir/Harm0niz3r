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
import time
import queue

# --- Import the new parser module ---
from harmonyos_parser import parse_app_dump_string

from config import VERSION, SERVER_HOST, PORT, BUFFER_SIZE, HDC_COMMAND, HARMONYZER_ASCII
from commands import register_command, get_command, list_commands
from commands import apps_list, app_info, app_surface, apps_visible_abilities, app_udmf, apps_udmf, app_ability, app_ability_want, app_ability_fuzz,app_ability_fuzz_dict, run_script,net_send, shell_exec
from commands.base import CommandSource

class HarmonyOSClientConsole:
    """
    A TCP client that connects to the HarmonyOS server and provides a console interface.
    It can execute hdc commands and optionally send results to the HarmonyOS app.
    """
    def __init__(self, host, port, buffer_size=4096):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
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
        Register all built-in commands in the commands/ package.
        You can add more here as you create new command modules.
        """
        # Each command module exposes a `register(registry_func)` helper
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
        run_script.register(register_command)
        shell_exec.register(register_command)
        net_send.register(register_command)
        
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

        # Build a shell command that:
        #  - starts hilog in raw mode (-r)
        #  - redirects stdout to our log file
        #  - runs in background and prints its PID
        shell_cmd = f"hilog > {remote_filename} 2>&1 & echo $!"

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

        # 2) Pull the log file from device to host
        if local is None:
            # Should not happen, but guard anyway
            local = os.path.abspath(f"harm0nyz3r_{command_name}_log.log")

        # hdc file recv <remote> <local>
        recv_cmd = ["-t", self.hdc_device_id, "file", "recv", remote, local]
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
        """Helper to print messages conditionally based on verbose mode."""
        if level in ["INFO", "ERROR", "SUCCESS", "FATAL_ERROR", "WARNING"]:
            print(f"[{level}] {message}")
        elif self.verbose:
            print(f"[{level}] {message}")

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
        Executes an hdc command and returns its stdout and stderr.
        Args:
            args_list (list): Command and its arguments as a list (e.g., ['list', 'targets', '-v']).
        Returns:
            tuple: (stdout_str, stderr_str, return_code)
        """
        full_command = [HDC_COMMAND] + args_list
        
        self._print_message("DEBUG", f"Executing hdc command: {' '.join(full_command)}")
        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                encoding='utf-8',
                check=False, # Important: Do not raise CalledProcessError for non-zero exit codes
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except FileNotFoundError:
            self._print_message("ERROR", f"'{HDC_COMMAND}' command not found. Please ensure hdc is installed and in your system's PATH.")
            return "", "HDC command not found.", -1
        except Exception as e:
            self._print_message("FATAL_ERROR", f"An error occurred while executing hdc command: {e}")
            return "", str(e), -1

    def _get_hdc_shell_output(self, hdc_shell_cmd_args):
        """
        Executes an hdc shell command and returns its stdout, stderr, and return code.
        This function does NOT handle printing or sending to app; it just retrieves the raw output.
        """
        if not self.hdc_device_id:
            self._print_message("ERROR", "No HarmonyOS device is connected via hdc. Cannot execute hdc shell commands.")
            return "", "No HarmonyOS device found via hdc.", -1

        full_hdc_args = ["-t", self.hdc_device_id, "shell"] + hdc_shell_cmd_args
        self._print_message("INFO", f"Executing hdc command: '{HDC_COMMAND} {' '.join(full_hdc_args)}' to get raw output...")
        stdout, stderr, retcode = self._execute_hdc_command(full_hdc_args)
        return stdout, stderr, retcode

    def _get_hdc_device_info(self):
        """
        Attempts to find a connected hdc device and updates self.hdc_device_id/name.
        """
        self.hdc_device_id = None
        self.hdc_device_name = "No Device"
        self.user_name_on_device = "You"

        self._print_message("INFO", f"Running '{HDC_COMMAND} list targets -v' to detect devices...")
        stdout, stderr, retcode = self._execute_hdc_command(["list", "targets", "-v"])
        
        if retcode != 0:
            self._print_message("ERROR", f"Failed to list hdc targets. Error code: {retcode}, Stderr: {stderr}")
            return False

        if "No device found" in stdout or not stdout.strip():
            self._print_message("INFO", "No HarmonyOS devices detected via hdc.")
            return False

        device_line_pattern = re.compile(r"^\s*([\w\d.:-]+)\s+(?:USB|UART|TCP)?\s*(Connected|device|Ready)\s+.*", re.IGNORECASE)
        
        found_id = None
        found_name = None 

        lines = stdout.splitlines()
        for i, line in enumerate(lines):
            match_device_line = device_line_pattern.match(line)
            if match_device_line:
                candidate_id = match_device_line.group(1)
                candidate_status = match_device_line.group(2)

                if candidate_status.lower() in ["connected", "device"]:
                    found_id = candidate_id
                    
                    for j in range(i + 1, min(i + 5, len(lines))): 
                        name_match = re.search(r"^\s+\(Name:\s*(.+)\)", lines[j])
                        if name_match:
                            found_name = name_match.group(1)
                            break
                    break 

        if found_id:
            self.hdc_device_id = found_id
            self.hdc_device_name = found_name if found_name else found_id 
            self._print_message("SUCCESS", f"Detected HarmonyOS device: ID='{self.hdc_device_id}', Name='{self.hdc_device_name}'")
            
            self._print_message("DEBUG", "Attempting to get user name from device using 'whoami'...")
            user_stdout, user_stderr, user_retcode = self._execute_hdc_command(
                ["-t", self.hdc_device_id, "shell", "whoami"]
            )
            if user_retcode == 0 and user_stdout:
                self.user_name_on_device = user_stdout.strip()
            else:
                self.user_name_on_device = "You" # Default if whoami fails
                self._print_message("WARNING", f"Could not get user name from device (retcode: {user_retcode}, stderr: {user_stderr}). Defaulting to 'You'.")

            return True
        else:
            self._print_message("INFO", "No active or parsable HarmonyOS devices found.")
            return False

    def connect(self):
        """
        Establishes a raw TCP connection, performs a 'MARCO'-'POLO' handshake.
        """
        if self.connected:
            self._print_message("INFO", "Already connected and handshake successful. No need to connect again.")
            return True

        self._print_message("INFO", "Checking for HarmonyOS device via hdc...")
        hdc_device_found = self._get_hdc_device_info()
        
        self._update_prompt()

        if not hdc_device_found:
            self._print_message("INFO", "No active hdc device detected. Some commands (e.g., 'apps_list', 'app_info') might not work.")

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
            self._print_message("DEBUG", f"Received handshake response: '{handshake_response}' from HarmonyOS server.")

            if handshake_response == "POLO":
                self.connected = True 
                self._print_message("SUCCESS", "MARCO-POLO Handshake SUCCESSFUL! Connection fully established.")
                self.socket.settimeout(None) # Remove timeout for continuous listening
                
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
            self._print_message("ERROR", "No HarmonyOS device is connected via hdc. Cannot execute hdc shell commands.")
            if send_to_app_type and self.connected: # Still send error to app if it was requested for app
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:No HarmonyOS device found via hdc.")
            return

        full_hdc_args = ["-t", self.hdc_device_id, "shell"] + hdc_shell_cmd_args
        
        self._print_message("INFO", f"Executing hdc command: '{HDC_COMMAND} {' '.join(full_hdc_args)}'...")
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
        """Updates the command prompt text based on current status."""
        self._current_prompt_text = f"[{self.user_name_on_device}@{self.hdc_device_name}] Enter command: "


                
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

        cmd = [ "shell",
                "aa", "start",
                "-b", f"{bundle_name}",
                "-a", f"{ability_name}",
                "--params", f"{key}", f"{value}"
            ]

        stdout, stderr, ret = self._execute_hdc_command(cmd)

        self._print_message("INFO",f"stdout: {stdout}")
        self._print_message("INFO",f"stderr: {stderr}")
        self._print_message("INFO",f"ret: {ret}")


    def _print_help(self):
        """Prints available commands based on connection status."""
        print("\n--- HarmonyOS TCP Client Console ---")
        print(f"Server: {self.host}:{self.port}")
        print(
            "Connection Status: "
            + (
                "✅ ESTABLISHED (MARCO-POLO Handshake OK)"
                if self.connected
                else "❌ DISCONNECTED or HANDSHAKE FAILED"
            )
        )
        print(
            f"HDC Device: {self.hdc_device_name} "
            f"(ID: {self.hdc_device_id if self.hdc_device_id else 'None'})"
        )
        print(f"Verbose Mode: {'ON' if self.verbose else 'OFF'}")

        print("\nCore Console Commands:")
        print("    help                    - Show this help.")
        print("    exit                    - Quit the console.")
        print(
            "    connect                 - Attempt to connect to the server "
            "(includes MARCO-POLO handshake) and check hdc."
        )
        if self.connected:
            print("    disconnect              - Disconnect from the server.")
        print(
            "    verbose [on|off]        - Turn verbose output ON or OFF. "
            f"(Currently: {'ON' if self.verbose else 'OFF'})"
        )

        print("\nRegistered HarmonyOS Commands:")
        # Dynamically list all registered commands from the registry
        for cmd in list_commands():
            help_lines = cmd.help().splitlines()
            if not help_lines:
                continue
            # First line with one level of indentation
            print(f"    {help_lines[0]}")
            # Additional lines further indented
            for line in help_lines[1:]:
                print(f"        {line}")

        if not self.hdc_device_id:
            print(
                "\n[INFO] Hdc-based commands (apps_list, app_info, app_surface, "
                "apps_visible_abilities, app_ability, app_udmf, apps_udmf, "
                "invoke_with_want, ...) require a connected HarmonyOS device."
            )

        print("------------------------------------\n")

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
        print(HARMONYZER_ASCII)  # Print ASCII art at the very beginning
        self._get_hdc_device_info()
        self._update_prompt()
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
    client_console = HarmonyOSClientConsole(SERVER_HOST, PORT, BUFFER_SIZE)
    client_console.start_console()
