"""
platforms/base_platform.py
---------------------------
Abstract interface that every platform adapter must implement.

A "platform" encapsulates all knowledge about a specific device bridge
tool (hdc, adb, iproxy …) so that the rest of Harm0nyz3r can remain
platform-agnostic.
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple


class BasePlatform(ABC):
    """Abstract device-bridge adapter."""

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable platform name: 'harmonyos', 'android', 'ios'."""

    @property
    @abstractmethod
    def bridge_command(self) -> str:
        """CLI bridge tool name, e.g. 'hdc', 'adb', 'iproxy'."""

    # ------------------------------------------------------------------
    # Device detection
    # ------------------------------------------------------------------

    @abstractmethod
    def detect_device(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect the first connected / ready device.

        Returns:
            (device_id, device_name)  – both are None when nothing is found.
        """

    # ------------------------------------------------------------------
    # Raw bridge execution
    # ------------------------------------------------------------------

    @abstractmethod
    def execute_bridge_command(self, args: list) -> Tuple[str, str, int]:
        """
        Run `bridge_command <args>` in a subprocess.

        Returns:
            (stdout, stderr, returncode)
        """

    # ------------------------------------------------------------------
    # Shell execution helpers
    # ------------------------------------------------------------------

    @abstractmethod
    def device_shell_args(self, device_id: str) -> list:
        """
        Returns the bridge-command argument prefix that opens a shell on a
        specific device.

        Examples:
            hdc  →  ["-t", device_id, "shell"]
            adb  →  ["-s", device_id, "shell"]
        """

    # ------------------------------------------------------------------
    # File transfer
    # ------------------------------------------------------------------

    @abstractmethod
    def pull_file_args(self, device_id: str, remote: str, local: str) -> list:
        """
        Returns the bridge-command argument list to pull a file from the device.

        Examples:
            hdc  →  ["-t", device_id, "file", "recv", remote, local]
            adb  →  ["-s", device_id, "pull", remote, local]
        """

    # ------------------------------------------------------------------
    # Device logging
    # ------------------------------------------------------------------

    @abstractmethod
    def get_log_shell_command(self, remote_path: str) -> str:
        """
        Returns a *shell command string* (run on the device) that:
          - starts background log capture writing to `remote_path`
          - prints the background PID so the caller can later kill it

        Examples:
            HarmonyOS  →  "hilog > {remote_path} 2>&1 & echo $!"
            Android    →  "logcat > {remote_path} 2>&1 & echo $!"
        """

    # ------------------------------------------------------------------
    # Port forwarding  (optional – default raises NotImplementedError)
    # ------------------------------------------------------------------

    def port_forward_args(self, device_id: str, local_port: int, remote_port: int) -> list:
        """
        Returns the bridge-command argument list to set up TCP port forwarding.

        Examples:
            hdc  →  ["-t", device_id, "fport", f"tcp:{local_port}", f"tcp:{remote_port}"]
            adb  →  ["-s", device_id, "forward", f"tcp:{local_port}", f"tcp:{remote_port}"]

        Raises:
            NotImplementedError if the platform does not support port forwarding.
        """
        raise NotImplementedError(f"Port forwarding not implemented for platform '{self.name}'.")
