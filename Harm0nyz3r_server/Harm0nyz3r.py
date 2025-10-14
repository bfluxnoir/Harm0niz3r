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
import queue

# --- Import the new parser module ---
from harmonyos_parser import parse_app_dump_string

from config import VERSION, SERVER_HOST, PORT, BUFFER_SIZE, HDC_COMMAND, HARMONYZER_ASCII


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

                self._print_message("INFO", f"[APP MESSAGE] {decoded_data}") # Print received data with clear tag

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
        This function will always send the HDC output back to the app.
        """
        parts = command_payload.split(' ')
        cmd = parts[0].lower()
        cmd_args = parts[1:]

        # --- MODIFIED: Handle '-a' flag for app-originated requests ---
        # Remove '-a' if present, as it's implicit for app-originated requests
        if '-a' in cmd_args:
            cmd_args.remove('-a')
        # --- END MODIFIED ---

        if cmd == "app_info":
            # --- MODIFIED: Argument check after removing '-a' ---
            if len(cmd_args) != 1: # Now expecting exactly one argument: namespace
                error_msg = "Invalid app_info command from app: Expected <namespace>. Usage: app_info <namespace>"
                self._print_message("ERROR", error_msg)
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
                return
            # --- END MODIFIED ---
            
            namespace = cmd_args[0]
            hdc_shell_cmd_args = ["bm", "dump", "-n", namespace]
            
            self._execute_and_handle_hdc_command(
                hdc_shell_cmd_args, 
                send_to_app_type="HDC_OUTPUT_APP_DETAILS", # Always send details back to app
                console_output_prefix=f"--- Details for {namespace} (Requested by App) ---",
                force_send_to_app=True # Force sending to app
            )
        # --- NEW: Handle apps_list command from app ---
        elif cmd == "apps_list":
            if len(cmd_args) != 0: # apps_list should have no arguments after removing -a
                error_msg = "Invalid apps_list command from app: No arguments expected. Usage: apps_list"
                self._print_message("ERROR", error_msg)
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
                return
            
            self._execute_and_handle_hdc_command(
                ["bm", "dump", "-a"],
                send_to_app_type="HDC_OUTPUT_ALL_APPS", # Always send all apps back to app
                console_output_prefix="--- Installed Applications List (Requested by App) ---",
                force_send_to_app=True # Force sending to app
            )
        # --- END NEW ---
        elif cmd == "app_surface": # Handle app_surface request from app
            # --- MODIFIED: Argument check after removing '-a' ---
            if len(cmd_args) != 1: # Now expecting exactly one argument: namespace
                error_msg = "Invalid app_surface command from app: Expected <namespace>. Usage: app_surface <namespace>"
                self._print_message("ERROR", error_msg)
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
                return
            # --- END MODIFIED ---

            namespace = cmd_args[0]
            if not re.match(r"^[a-zA-Z0-9\._-]+$", namespace):
                error_msg = f"Invalid namespace format: '{namespace}'."
                self._print_message("ERROR", error_msg)
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
                return

            stdout, stderr, retcode = self._get_hdc_shell_output(["bm", "dump", "-n", namespace])

            if retcode == 0 and stdout:
                try:
                    parsed_data = parse_app_dump_string(stdout)
                    json_output = json.dumps(parsed_data, indent=2)
                    self._print_message("INFO", f"Sending parsed app surface JSON to HarmonyOS app for {namespace}.")
                    self.send_data_to_app(f"HDC_OUTPUT_APP_SURFACE_JSON:{json_output}")
                except ValueError as e:
                    error_msg = f"Error parsing app dump for {namespace}: {e}"
                    self._print_message("ERROR", error_msg)
                    self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
            else:
                error_msg = stderr if stderr else f"HDC command failed or returned no output for {namespace} (exit code: {retcode})."
                self._print_message("ERROR", f"HDC command for app_surface failed: {error_msg}")
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
        # --- NEW: Handle udmf_query_single_app command from app ---
        elif cmd == "udmf_query_single_app":
            if len(cmd_args) < 1 or len(cmd_args) > 2:
                error_msg = "Invalid udmf_query_single_app command from app: Expected <namespace> [groupId]. Usage: udmf_query_single_app <namespace> [groupId]"
                self._print_message("ERROR", error_msg)
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
                return
            
            namespace = cmd_args[0]
            group_id = cmd_args[1] if len(cmd_args) == 2 else "flag" # Default groupId to "flag"
            
            # For UDMF queries, the Python client doesn't execute HDC. It just relays the request.
            # The app will perform the UDMF query and send the result back.
            self._print_message("INFO", f"Relaying UDMF query request for app '{namespace}' (groupId: '{group_id}') to HarmonyOS app.")
            # No HDC command to execute here, just a confirmation of relay
            self.send_data_to_app(f"HDC_OUTPUT_INFO:UDMF query request relayed for {namespace} (groupId: {group_id}). Waiting for app response.")
        # --- END NEW ---
        # --- NEW: Handle udmf_query_all_apps command from app ---
        elif cmd == "udmf_query_all_apps":
            if len(cmd_args) > 1:
                error_msg = "Invalid udmf_query_all_apps command from app: Expected [groupId]. Usage: udmf_query_all_apps [groupId]"
                self._print_message("ERROR", error_msg)
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
                return
            
            group_id = cmd_args[0] if len(cmd_args) == 1 else "flag" # Default groupId to "flag"
            
            self._print_message("INFO", f"Relaying UDMF query for all apps (groupId: '{group_id}') to HarmonyOS app.")
            self.send_data_to_app(f"HDC_OUTPUT_INFO:UDMF query for all apps relayed (groupId: {group_id}). Waiting for app response.")
        # --- END NEW ---
        elif cmd == 'app_visible_abilities':
            send_to_app = '-a' in parts
            if send_to_app:
                parts.remove('-a')
            self.extract_visible_abilities(send_to_app=send_to_app)
        elif cmd == 'invoke_with_want':
            try:
                # Parse key=value pairs de los argumentos
                argmap = dict(arg.split("=", 1) for arg in cmd_args if "=" in arg)
                app = argmap.get("app")
                ability = argmap.get("ability")
                action = argmap.get("action")
                entity = argmap.get("entity")

                # Validar campos requeridos
                if not all([app, ability, action, entity]):
                    raise ValueError("Missing one or more required parameters: app, ability, action, entity")

                self._print_message("INFO", f"Invoking ability {ability} in app {app} with Want action={action} entity={entity}")
                
                # Llamar al método que hace la invocación real
                self.invoke_ability_with_want(app, ability, action, entity, send_to_app=True)

            except Exception as e:
                error_msg = f"Failed to process 'invoke_with_want': {e}"
                self._print_message("ERROR", error_msg)
                self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
        
        else:
            error_msg = f"Unknown command requested by app: '{command_payload}'"
            self._print_message("ERROR", error_msg)
            self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")

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

    # --- NEW HELPER FUNCTION: Format parsed app surface data for console ---
    def _format_app_surface_for_console(self, parsed_data: dict) -> str:
        """
        Formats the parsed app surface data into a human-readable string for console output.
        """
        output_lines = []
        output_lines.append(f"--- App Surface for {parsed_data.get('bundleName', 'Unknown App')} ---")
        output_lines.append(f"  Debug Mode: {'Yes' if parsed_data.get('debugMode', False) else 'No'}")
        output_lines.append(f"  System App: {'Yes' if parsed_data.get('systemApp', False) else 'No'}")
        output_lines.append("\n  Exposed Components:")

        if not parsed_data.get('exposedComponents'):
            output_lines.append("    No exposed abilities or extensions found.")
        else:
            for component in parsed_data['exposedComponents']:
                output_lines.append(f"    - Name: {component.get('name', 'N/A')}")
                output_lines.append(f"      Type: {component.get('type', 'N/A')}")
                output_lines.append(f"      Visible: {'Yes' if component.get('visible', False) else 'No'}")
                if component.get('permissionsRequired'):
                    output_lines.append(f"      Permissions Required: {', '.join(component['permissionsRequired'])}")
                if component.get('skills'):
                    output_lines.append("      Skills (Intent Filters):")
                    for skill in component['skills']:
                        skill_parts = []
                        if 'action' in skill:
                            skill_parts.append(f"Action: {skill['action']}")
                        if 'entity' in skill:
                            skill_parts.append(f"Entity: {skill['entity']}")
                        if 'scheme' in skill:
                            skill_parts.append(f"Scheme: {skill['scheme']}")
                        if 'type' in skill:
                            skill_parts.append(f"Type: {skill['type']}")
                        if 'utd' in skill:
                            skill_parts.append(f"UTD: {', '.join(skill['utd'])}")
                        output_lines.append(f"        - {', '.join(skill_parts)}")
                output_lines.append("") # Add a blank line for readability between components
        
        return "\n".join(output_lines)
    # --- END NEW HELPER FUNCTION ---

    def extract_visible_abilities(self, send_to_app=False):
        """
        Returns all invokable abilities (Visible: Yes, no permissions, skips Entry/MainAbility).
        If send_to_app, data is sent in JSON format to HOS app.
        """
        if not self.hdc_device_id:
            self._print_message("ERROR", "No HarmonyOS device connected via hdc.")
            return

        # 1. Extract app list
        self._print_message("INFO", "Obtaining app list...")
        stdout, stderr, retcode = self._execute_hdc_command(["-t", self.hdc_device_id, "shell", "bm", "dump", "-a"])
        if retcode != 0 or not stdout:
            self._print_message("ERROR", f"Error while executing bm dump -a: {stderr or 'no output'}")
            return

        bundles = [line.strip() for line in stdout.splitlines() if line.strip()]
        self._print_message("INFO", f"Found {len(bundles)} instaled apps.")

        filtered_abilities = []

        for bundle in bundles:
            self._print_message("DEBUG", f"Processing bundle: {bundle}")
            app_stdout, app_stderr, app_retcode = self._get_hdc_shell_output(["bm", "dump", "-n", bundle])

            if app_retcode != 0 or not app_stdout:
                continue

            try:
                parsed = parse_app_dump_string(app_stdout)
                if not isinstance(parsed, dict):
                    continue

                for comp in parsed.get("exposedComponents", []):
                    if not isinstance(comp, dict) or comp.get("type", "").lower() != "ability":
                        continue

                    # Apply filters: Visible: Yes, no Permissions and no EntryAbility nor MainAbility
                    if (comp.get("visible") is True and
                        not comp.get("permissionsRequired", []) and
                        not any(x in comp.get("name", "").lower() 
                                for x in ["entryability", "mainability"])):

                        skills = comp.get("skills", [])
                        if not isinstance(skills, list):
                            skills = []

                        filtered_abilities.append({
                            "app": parsed.get("bundleName", bundle),
                            "ability": comp.get("name", "UNKNOWN"),
                            "skills": skills
                        })

            except Exception as e:
                self._print_message("DEBUG", f"Error processing {bundle}: {str(e)}")
                continue

        # --- Show filtered abilities through CLI ---
        print("\n=== Filtered Abilities ===")
        print(f"Total: {len(filtered_abilities)} (Visible:Yes, No Permissions, No Entry/Main)")
        for ability in filtered_abilities:
            print(f"\nApp: {ability['app']}")
            print(f"Ability: {ability['ability']}")
            if ability['skills']:
                print("Intent Filters (skills):")
                for skill in ability['skills']:
                    if isinstance(skill, dict):
                        print(f" - {' '.join([f'{k}={v}' for k, v in skill.items() if v])}")

        # --- Send filtered ability list to client ---
        if send_to_app and self.connected:
            try:
                payload = f"HDC_OUTPUT_EXPOSED_ABILITIES:{json.dumps(filtered_abilities, ensure_ascii=False)}"
                self.send_data_to_app(payload)
                self._print_message("INFO", f"{len(filtered_abilities)} filtered abilities were sent to the app.")
            except Exception as e:
                self._print_message("ERROR", f"Error al enviar a la app: {e}")
                
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
        print(f"Connection Status: {'✅ ESTABLISHED (MARCO-POLO Handshake OK)' if self.connected else '❌ DISCONNECTED or HANDSHAKE FAILED'}")
        print(f"HDC Device: {self.hdc_device_name} (ID: {self.hdc_device_id if self.hdc_device_id else 'None'})")
        print(f"Verbose Mode: {'ON' if self.verbose else 'OFF'}")
        print("\nAvailable Commands:")
        
        print("    help                    - Show this help.")
        print("    exit                    - Quit the console.")
        print("    connect                 - Attempt to connect to the server (includes MARCO-POLO handshake) and check hdc.")
        print("    verbose [on|off]        - Turn verbose output ON or OFF. (Currently: {})".format("ON" if self.verbose else "OFF"))
        
        # Updated commands with -a flag for conditional sending
        print("    apps_list [-a]          - Run 'hdc shell bm dump -a' to list all app bundle names.")
        print("                              Use '-a' to send results to the HarmonyOS app.")
        print("                              Otherwise, output is printed to this console.")
        print("    app_info <namespace> [-a] - Run 'hdc shell bm dump -n <namespace>' to get detailed info for an app.")
        print("                              Use '-a' to send results to the HarmonyOS app.")
        print("                              Otherwise, output is printed to this console.")
        # --- NEW: app_surface command help ---
        print("    app_surface <namespace> [-a] - Run 'hdc shell bm dump -n <namespace>' and parse output.")
        print("                              If '-a' is used, sends parsed JSON to the HarmonyOS app.")
        print("                              Otherwise, prints human-readable summary to this console.")
        # --- END NEW ---
        # --- NEW: app_visible_abilities command help ---
        print("    app_visible_abilities     - Returns a list with all instaled apps abilities.")
        print("                                     Filters out abilities that are invokable (not require permissions and 'Visible: Yes')")
        print("                                     and skips MainAbility and EntryAbility.")
        # --- END NEW ---
        # --- NEW: app_ability command help ---
        print("    app_ability <namespace> <abilityname> - Run 'hdc shell aa start -a <abilityname> -b <namespace>' to start an ability.")
        print("                                            Output is always printed to this console.")
        # --- END NEW ---
        # --- NEW: app_udmf command help ---
        print("    app_udmf <namespace> [groupId] - Query UDMF for a specific app and optional group ID (default: 'flag').")
        print("                                     Results are returned from the HarmonyOS app and displayed here.")
        # --- END NEW ---
        # --- NEW: apps_udmf command help ---
        print("    apps_udmf [groupId]     - Query UDMF for all installed apps with an optional group ID (default: 'flag').")
        print("                                     Returns a list of apps that have UDMF content for the specified group ID.")
        # --- END NEW ---
        # --- NEW: invoke_with_want command help ---
        print("    invoke_with_want [TODO]     - Invokes an ability using the specified parameters.")
        print("                                     Results are seen on device (if ability is UI).")
        # -- END New ---
        if self.connected: 
            print("    disconnect              - Disconnect from the server.")
        
        if not self.hdc_device_id:
            print("[INFO] Hdc-based commands (apps_list, app_info, app_surface, app_ability, app_visible_abilities...) require a connected HarmonyOS device.")
        
        print("------------------------------------\n")

    def start_console(self):
        """Starts the interactive console loop."""
        print(HARMONYZER_ASCII) # Print ASCII art at the very beginning
        self._get_hdc_device_info()
        self._update_prompt()
        self._print_help()

        while self.running:
            try:
                self._input_active = True 
                command_line = input(self._current_prompt_text).strip()
                self._input_active = False 

                parts = command_line.split()
                if not parts:
                    continue

                command = parts[0].lower()
                
                if command == 'exit':
                    self.running = False
                    break
                elif command == 'help':
                    self._print_help() 
                elif command == 'connect':
                    connection_successful = self.connect()
                    self._update_prompt()
                    self._print_help()
                    self._print_message("INFO", f"'connect' command finished. Final handshake status: {'SUCCESS' if connection_successful else 'FAILED'}")
                elif command == 'disconnect':
                    self.disconnect()
                    self._print_help() 
                elif command == 'verbose':
                    if len(parts) < 2:
                        print(f"[INFO] Usage: verbose [on|off]. Current: {'ON' if self.verbose else 'OFF'}")
                    else:
                        toggle_arg = parts[1].lower()
                        if toggle_arg == 'on':
                            self.verbose = True
                            self._print_message("INFO", "Verbose mode ON.")
                        elif toggle_arg == 'off':
                            self.verbose = False
                            print("[INFO] Verbose mode OFF.")
                        else:
                            print(f"[INFO] Invalid verbose option: '{toggle_arg}'. Use 'on' or 'off'.")
                    self._print_help()
                
                elif command == 'apps_list':
                    send_to_app = '-a' in parts
                    if send_to_app:
                        parts.remove('-a')
                    if len(parts) > 1: # After potentially removing -a, there should be no other arguments
                        print("[INFO] Usage: apps_list [-a] (no other arguments expected).")
                        continue
                    
                    if not send_to_app:
                         self._print_message("INFO", "Output will be printed to this console.")
                    elif not self.connected:
                        self._print_message("WARNING", "Not connected to the HarmonyOS app. Output of 'apps_list' cannot be sent to the device. Printing to console instead.")
                        send_to_app = False # Force console output if not connected

                    self._execute_and_handle_hdc_command(
                        ["bm", "dump", "-a"], 
                        send_to_app_type="HDC_OUTPUT_ALL_APPS" if send_to_app else None,
                        console_output_prefix="--- Installed Applications List ---"
                    )

                elif command == 'app_info': # Renamed from 'get_app_details'
                    send_to_app = '-a' in parts
                    if send_to_app:
                        parts.remove('-a')
                    
                    if len(parts) < 2: # After removing -a, we expect at least one more part (namespace)
                        print("[INFO] Usage: app_info <namespace> [-a] (missing namespace).")
                        continue
                    if len(parts) > 2: # More than just 'app_info' and 'namespace'
                        print("[INFO] Usage: app_info <namespace> [-a] (too many arguments).")
                        continue

                    namespace = parts[1]
                    if not re.match(r"^[a-zA-Z0-9\._-]+$", namespace):
                        print(f"[ERROR] Invalid namespace format: '{namespace}'.")
                        continue
                    
                    if not send_to_app:
                         self._print_message("INFO", "Output will be printed to this console.")
                    elif not self.connected:
                        self._print_message("WARNING", "Not connected to the HarmonyOS app. Output of 'app_info' cannot be sent to the device. Printing to console instead.")
                        send_to_app = False # Force console output if not connected
                    
                    self._execute_and_handle_hdc_command(
                        ["bm", "dump", "-n", namespace], 
                        send_to_app_type="HDC_OUTPUT_APP_DETAILS" if send_to_app else None,
                        console_output_prefix=f"--- Details for {namespace} ---"
                    )
                
                # --- NEW COMMAND: app_surface ---
                elif command == 'app_surface':
                    send_to_app = '-a' in parts
                    if send_to_app:
                        parts.remove('-a')
                    
                    if len(parts) < 2: # Expect at least 'app_surface' and '<namespace>'
                        print("[INFO] Usage: app_surface <namespace> [-a] (missing namespace).")
                        continue
                    if len(parts) > 2: # More than 'app_surface' and 'namespace'
                        print("[INFO] Usage: app_surface <namespace> [-a] (too many arguments).")
                        continue

                    namespace = parts[1]
                    if not re.match(r"^[a-zA-Z0-9\._-]+$", namespace):
                        print(f"[ERROR] Invalid namespace format: '{namespace}'.")
                        continue
                    
                    stdout, stderr, retcode = self._get_hdc_shell_output(["bm", "dump", "-n", namespace])

                    if retcode == 0 and stdout:
                        try:
                            parsed_data = parse_app_dump_string(stdout)
                            
                            if send_to_app:
                                if self.connected:
                                    json_output = json.dumps(parsed_data, indent=2)
                                    self._print_message("INFO", f"Sending parsed app surface JSON to HarmonyOS app for {namespace}.")
                                    self.send_data_to_app(f"HDC_OUTPUT_APP_SURFACE_JSON:{json_output}")
                                else:
                                    self._print_message("WARNING", "Not connected to the HarmonyOS app. Parsed app surface JSON cannot be sent to the device. Printing human-readable output to console instead.")
                                    human_readable_output = self._format_app_surface_for_console(parsed_data)
                                    print(f"\n{human_readable_output}\n-----------------------------------\n")
                            else:
                                self._print_message("INFO", "Output will be printed to this console (human-readable format).")
                                human_readable_output = self._format_app_surface_for_console(parsed_data)
                                print(f"\n{human_readable_output}\n-----------------------------------\n")
                        except ValueError as e:
                            self._print_message("ERROR", f"Error parsing app dump for {namespace}: {e}")
                            if send_to_app and self.connected:
                                self.send_data_to_app(f"HDC_OUTPUT_ERROR:Error parsing app dump for {namespace}: {e}")
                            else:
                                print(f"\n--- Error Parsing App Dump for {namespace} ---\n{e}\n-----------------------------------\n")
                    else:
                        error_msg = stderr if stderr else f"HDC command failed or returned no output for {namespace} (exit code: {retcode})."
                        self._print_message("ERROR", f"HDC command for app_surface failed: {error_msg}")
                        if send_to_app and self.connected:
                            self.send_data_to_app(f"HDC_OUTPUT_ERROR:{error_msg}")
                        else:
                            print(f"\n--- HDC Command Error for App Surface ({namespace}) ---\n{error_msg}\n-----------------------------------\n")
                # --- END NEW COMMAND: app_surface ---
                
                # --- NEW COMMAND: app_ability ---
                elif command == 'app_ability':
                    if len(parts) < 3: # Expect 'app_ability', '<namespace>', '<abilityname>'
                        print("[INFO] Usage: app_ability <namespace> <abilityname> (missing arguments).")
                        continue
                    if len(parts) > 3: # Too many arguments
                        print("[INFO] Usage: app_ability <namespace> <abilityname> (too many arguments).")
                        continue

                    namespace = parts[1]
                    ability_name = parts[2]

                    if not re.match(r"^[a-zA-Z0-9\._-]+$", namespace):
                        print(f"[ERROR] Invalid namespace format: '{namespace}'.")
                        continue
                    if not re.match(r"^[a-zA-Z0-9\._-]+$", ability_name):
                        print(f"[ERROR] Invalid ability name format: '{ability_name}'.")
                        continue
                    
                    self._print_message("INFO", f"Attempting to start ability '{ability_name}' in bundle '{namespace}'...")
                    
                    # Execute 'aa start' command
                    self._execute_and_handle_hdc_command(
                        ["aa", "start", "-a", ability_name, "-b", namespace],
                        send_to_app_type=None, # Never send this output to the app
                        console_output_prefix=f"--- Result of starting Ability {ability_name} in {namespace} ---"
                    )
                # --- END NEW COMMAND: app_ability ---
                # --- NEW COMMAND: app_udmf ---
                elif command == 'app_udmf':
                    if not self.connected:
                        self._print_message("ERROR", "Not connected to the HarmonyOS app. Cannot query UDMF.")
                        continue

                    if len(parts) < 2 or len(parts) > 3:
                        print("[INFO] Usage: app_udmf <namespace> [groupId] (groupId defaults to 'flag').")
                        continue

                    namespace = parts[1]
                    group_id = parts[2] if len(parts) == 3 else "flag"

                    if not re.match(r"^[a-zA-Z0-9\._-]+$", namespace):
                        print(f"[ERROR] Invalid namespace format: '{namespace}'.")
                        continue
                    if not re.match(r"^[a-zA-Z0-9\._-]+$", group_id):
                        print(f"[ERROR] Invalid group ID format: '{group_id}'.")
                        continue

                    self._print_message("INFO", f"Requesting UDMF content for app '{namespace}' with group ID '{group_id}' from HarmonyOS app.")
                    self.send_data_to_app(f"COMMAND_REQUEST:udmf_query_single_app {namespace} {group_id}")
                # --- END NEW ---
                # --- NEW COMMAND: apps_udmf ---
                elif command == 'apps_udmf':
                    if not self.connected:
                        self._print_message("ERROR", "Not connected to the HarmonyOS app. Cannot query UDMF for all apps.")
                        continue

                    if len(parts) > 2:
                        print("[INFO] Usage: apps_udmf [groupId] (groupId defaults to 'flag').")
                        continue

                    group_id = parts[1] if len(parts) == 2 else "flag"

                    if not re.match(r"^[a-zA-Z0-9\._-]+$", group_id):
                        print(f"[ERROR] Invalid group ID format: '{group_id}'.")
                        continue

                    self._print_message("INFO", f"Requesting UDMF content for all apps with group ID '{group_id}' from HarmonyOS app.")
                    self.send_data_to_app(f"COMMAND_REQUEST:udmf_query_all_apps {group_id}")
                # --- END NEW ---
                
                elif command == 'app_visible_abilities':
                    send_to_app = '-a' in parts
                    if send_to_app:
                        parts.remove('-a')
                    self.extract_visible_abilities(send_to_app=send_to_app)
                
                elif command == 'invoke_with_want':
                    self._print_message("ERROR", "Invoking with wants not available yet from CLI. Please use app client.")
                    #self.invoke_ability_with_want()

                else: 
                    print(f"[INFO] Unknown command: '{command_line}'. Type 'help' for available commands.")
            except EOFError: 
                self._print_message("INFO", "EOF detected (Ctrl+D). Exiting.")
                self.running = False
            except Exception as e:
                self._print_message("FATAL_ERROR", f"An unexpected error occurred in console loop: {e}")

        self.disconnect() 

if __name__ == "__main__":
    client_console = HarmonyOSClientConsole(SERVER_HOST, PORT, BUFFER_SIZE)
    client_console.start_console()
