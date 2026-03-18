"""
platforms/harmonyos.py
-----------------------
HarmonyOS platform adapter — wraps the 'hdc' (Harmony Device Connector) tool.
"""

import re
import subprocess
from typing import Optional, Tuple

from .base_platform import BasePlatform


class HarmonyOSPlatform(BasePlatform):

    @property
    def name(self) -> str:
        return "harmonyos"

    @property
    def bridge_command(self) -> str:
        return "hdc"

    # ------------------------------------------------------------------
    # Device detection
    # ------------------------------------------------------------------

    def detect_device(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Runs 'hdc list targets -v' and returns (device_id, device_name).
        Both are None if no device is found.
        """
        stdout, stderr, retcode = self.execute_bridge_command(["list", "targets", "-v"])

        if retcode != 0 or not stdout.strip() or "No device found" in stdout:
            return None, None

        device_line_pattern = re.compile(
            r"^\s*([\w\d.:-]+)\s+(?:USB|UART|TCP)?\s*(Connected|device|Ready)\s+.*",
            re.IGNORECASE,
        )

        lines = stdout.splitlines()
        for i, line in enumerate(lines):
            match = device_line_pattern.match(line)
            if match and match.group(2).lower() in ("connected", "device"):
                device_id = match.group(1)
                device_name = None
                for j in range(i + 1, min(i + 5, len(lines))):
                    name_match = re.search(r"^\s+\(Name:\s*(.+)\)", lines[j])
                    if name_match:
                        device_name = name_match.group(1)
                        break
                return device_id, device_name or device_id

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
            return "", f"'{self.bridge_command}' not found. Ensure hdc is installed and in PATH.", -1
        except Exception as e:
            return "", str(e), -1

    # ------------------------------------------------------------------
    # Shell execution helpers
    # ------------------------------------------------------------------

    def device_shell_args(self, device_id: str) -> list:
        return ["-t", device_id, "shell"]

    # ------------------------------------------------------------------
    # File transfer
    # ------------------------------------------------------------------

    def pull_file_args(self, device_id: str, remote: str, local: str) -> list:
        return ["-t", device_id, "file", "recv", remote, local]

    # ------------------------------------------------------------------
    # Device logging
    # ------------------------------------------------------------------

    def get_log_shell_command(self, remote_path: str) -> str:
        return f"hilog > {remote_path} 2>&1 & echo $!"

    # ------------------------------------------------------------------
    # Port forwarding
    # ------------------------------------------------------------------

    def port_forward_args(self, device_id: str, local_port: int, remote_port: int) -> list:
        return ["-t", device_id, "fport", f"tcp:{local_port}", f"tcp:{remote_port}"]
