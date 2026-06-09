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
from typing import List, Optional, Tuple

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
        Runs 'adb devices -l' and returns (device_id, device_name) for the
        first ready entry.  Both None when nothing is found.
        """
        all_devices = self.list_devices()
        return all_devices[0] if all_devices else (None, None)

    def list_devices(self) -> List[Tuple[str, Optional[str]]]:
        """
        Enumerate every adb transport currently in the 'device' state.

        Note: 'adb devices -l' lists each transport separately, so a single
        phone connected via both USB and wireless adb will appear twice (the
        wireless serial starts with 'adb-...').  Callers that want one entry
        per physical device should de-duplicate by model / by user choice.

        Example 'adb devices -l' output:
            List of devices attached
            emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 ...
            5B181FDDW00016         device product:grizzly model:Grizzly ...
            adb-5B181FDDW00016-... device product:grizzly model:Grizzly ...
        """
        stdout, _, retcode = self.execute_bridge_command(["devices", "-l"])
        if retcode != 0 or not stdout.strip():
            return []

        results: List[Tuple[str, Optional[str]]] = []
        for line in stdout.splitlines():
            if not line.strip() or line.startswith("List of devices"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            device_id, status = parts[0], parts[1]
            if status != "device":
                continue
            model_match = re.search(r"model:(\S+)", line)
            device_name = model_match.group(1) if model_match else None
            results.append((device_id, device_name))
        return results

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
