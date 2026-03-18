"""
platforms/android.py
---------------------
Android platform adapter — wraps the 'adb' (Android Debug Bridge) tool.

Phase 2 will add Android-specific commands on top of this adapter.
The adapter itself is already fully functional for device detection,
shell execution, file transfer, logging, and port forwarding.
"""

import re
import subprocess
from typing import Optional, Tuple

from .base_platform import BasePlatform


class AndroidPlatform(BasePlatform):

    @property
    def name(self) -> str:
        return "android"

    @property
    def bridge_command(self) -> str:
        return "adb"

    # ------------------------------------------------------------------
    # Device detection
    # ------------------------------------------------------------------

    def detect_device(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Runs 'adb devices -l' and returns (device_id, device_name).
        Both are None if no device is found.

        Example 'adb devices -l' output:
            List of devices attached
            emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 ...
            R58M73XXXXX            device product:dreamlte model:SM-G950F ...
        """
        stdout, stderr, retcode = self.execute_bridge_command(["devices", "-l"])

        if retcode != 0 or not stdout.strip():
            return None, None

        lines = stdout.splitlines()
        for line in lines:
            # Skip header and empty lines
            if not line.strip() or line.startswith("List of devices"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            device_id = parts[0]
            status = parts[1]

            if status == "device":
                # Try to extract friendly model name from 'model:XYZ'
                model_match = re.search(r"model:(\S+)", line)
                device_name = model_match.group(1) if model_match else device_id
                return device_id, device_name

        return None, None

    # ------------------------------------------------------------------
    # Raw bridge execution
    # ------------------------------------------------------------------

    def execute_bridge_command(self, args: list) -> Tuple[str, str, int]:
        full_command = [self.bridge_command] + args
        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except FileNotFoundError:
            return "", f"'{self.bridge_command}' not found. Ensure adb is installed and in PATH.", -1
        except Exception as e:
            return "", str(e), -1

    # ------------------------------------------------------------------
    # Shell execution helpers
    # ------------------------------------------------------------------

    def device_shell_args(self, device_id: str) -> list:
        return ["-s", device_id, "shell"]

    # ------------------------------------------------------------------
    # File transfer
    # ------------------------------------------------------------------

    def pull_file_args(self, device_id: str, remote: str, local: str) -> list:
        return ["-s", device_id, "pull", remote, local]

    # ------------------------------------------------------------------
    # Device logging
    # ------------------------------------------------------------------

    def get_log_shell_command(self, remote_path: str) -> str:
        # logcat writes continuously; redirect to file in background
        return f"logcat > {remote_path} 2>&1 & echo $!"

    # ------------------------------------------------------------------
    # Port forwarding
    # ------------------------------------------------------------------

    def port_forward_args(self, device_id: str, local_port: int, remote_port: int) -> list:
        return ["-s", device_id, "forward", f"tcp:{local_port}", f"tcp:{remote_port}"]
