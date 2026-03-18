"""
platforms/ios.py
-----------------
iOS platform adapter stub.

Phase 3 will flesh this out.  The two supported scenarios are:
  - Jailbroken device  →  pymobiledevice3 + iproxy USB tunnel + Frida
  - Simulator          →  xcrun simctl

For now every method returns a sensible "not yet implemented" response so
the rest of the tool loads cleanly with '--platform ios'.
"""

from typing import Optional, Tuple

from .base_platform import BasePlatform


class iOSPlatform(BasePlatform):

    @property
    def name(self) -> str:
        return "ios"

    @property
    def bridge_command(self) -> str:
        # iproxy from libimobiledevice is the primary USB tunnel tool.
        # Full device management is done via pymobiledevice3 (Python library).
        return "iproxy"

    # ------------------------------------------------------------------
    # Device detection  (Phase 3)
    # ------------------------------------------------------------------

    def detect_device(self) -> Tuple[Optional[str], Optional[str]]:
        """
        TODO (Phase 3): Use pymobiledevice3 to detect connected iOS devices.

        Planned implementation:
            from pymobiledevice3.usbmux import UsbmuxdClient
            devices = UsbmuxdClient().devices()
            if devices:
                dev = devices[0]
                return dev.serial, dev.label or dev.serial
        """
        print("[WARNING] iOS platform support is not yet implemented (Phase 3).")
        return None, None

    # ------------------------------------------------------------------
    # Raw bridge execution  (Phase 3)
    # ------------------------------------------------------------------

    def execute_bridge_command(self, args: list) -> Tuple[str, str, int]:
        """
        TODO (Phase 3): Run iproxy or pymobiledevice3 CLI commands.
        """
        return "", "iOS bridge execution not yet implemented (Phase 3).", -1

    # ------------------------------------------------------------------
    # Shell execution helpers  (Phase 3)
    # ------------------------------------------------------------------

    def device_shell_args(self, device_id: str) -> list:
        """
        TODO (Phase 3): SSH over USB via iproxy 2222 22, then ssh root@localhost -p 2222.
        """
        return []

    # ------------------------------------------------------------------
    # File transfer  (Phase 3)
    # ------------------------------------------------------------------

    def pull_file_args(self, device_id: str, remote: str, local: str) -> list:
        """
        TODO (Phase 3): Use AFC (Apple File Conduit) via pymobiledevice3.
        Example: pymobiledevice3 afc pull <remote> <local>
        """
        return []

    # ------------------------------------------------------------------
    # Device logging  (Phase 3)
    # ------------------------------------------------------------------

    def get_log_shell_command(self, remote_path: str) -> str:
        """
        TODO (Phase 3): Use 'oslog' stream on device over SSH.
        Example: oslog stream > {remote_path} 2>&1 & echo $!
        """
        return f"echo 'iOS logging not yet implemented' > {remote_path} & echo $!"

    # ------------------------------------------------------------------
    # Port forwarding  (Phase 3)
    # ------------------------------------------------------------------

    def port_forward_args(self, device_id: str, local_port: int, remote_port: int) -> list:
        """
        TODO (Phase 3): iproxy <local_port> <remote_port> --udid <device_id>
        """
        return ["--udid", device_id, str(local_port), str(remote_port)]
