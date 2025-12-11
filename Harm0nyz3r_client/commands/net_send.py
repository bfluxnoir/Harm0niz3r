# commands/net_send.py

import os
import socket
from typing import List

from .base import Command, CommandSource


class NetSendCommand(Command):
    @property
    def name(self) -> str:
        return "net_send"

    def help(self) -> str:
        return (
            "net_send <tcp|udp> <port> [--hex] [--file <path>] <data...>\n"
            "net_send <tcp|udp> <host> <port> [--hex] [--file <path>] <data...>\n"
            "\n"
            "Send text, hex, or file content to a TCP/UDP port.\n"
            "\n"
            "Device mode (via hdc fport, TCP only):\n"
            "  net_send tcp 51337 --hex deadbeef00\n"
            "    → runs: hdc -t <id> fport tcp:51337 tcp:51337, then sends from host to 127.0.0.1:51337\n"
            "\n"
            "Host mode (no port forwarding):\n"
            "  net_send tcp 127.0.0.1 9000 hello world\n"
            "  net_send udp 192.168.0.10 5000 --hex deadbeef00\n"
            "\n"
            "File mode (raw bytes):\n"
            "  net_send tcp 51337 --file /tmp/payload.bin\n"
            "  net_send tcp 127.0.0.1 9000 --file /tmp/payload.bin\n"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Send data from the host to a TCP/UDP port.

        Modes:
          - <tcp|udp> <port> ...        → TCP: uses `hdc fport` to the device, then connects to 127.0.0.1:<port>
          - <tcp|udp> <host> <port> ... → Direct host connection, no hdc involvement
        """
        if source != "cli":
            console._print_message(
                "WARNING",
                "net_send is only intended to be used from the CLI."
            )
            return

        if len(args) < 2:
            console._print_message("INFO", self.help())
            return

        proto = args[0].lower()
        if proto not in ("tcp", "udp"):
            console._print_message("ERROR", "Protocol must be 'tcp' or 'udp'.")
            return

        # Decide: device mode (<port>) vs host mode (<host> <port>)
        use_fport = False
        host: str
        port: int
        data_args: List[str]

        # Device mode: net_send <proto> <port> ...
        if len(args) >= 2 and args[1].isdigit():
            if proto != "tcp":
                console._print_message(
                    "ERROR",
                    "Device-mode net_send (via hdc fport) currently supports only TCP."
                )
                return
            try:
                port = int(args[1])
            except ValueError:
                console._print_message("ERROR", f"Invalid port: {args[1]}")
                return

            host = "127.0.0.1"
            data_args = args[2:]
            use_fport = True

        # Host mode: net_send <proto> <host> <port> ...
        else:
            if len(args) < 3:
                console._print_message("INFO", self.help())
                return
            host = args[1]
            try:
                port = int(args[2])
            except ValueError:
                console._print_message("ERROR", f"Invalid port: {args[2]}")
                return
            data_args = args[3:]

        if not data_args:
            console._print_message("ERROR", "No data or options provided to send.")
            return

        # Flags
        hex_mode = False
        file_mode = False
        file_path: str = ""

        i = 0
        while i < len(data_args):
            token = data_args[i]
            if token == "--file":
                if file_mode:
                    console._print_message("ERROR", "Duplicate --file option.")
                    return
                if hex_mode:
                    console._print_message(
                        "ERROR",
                        "Cannot combine --file and --hex in the same command."
                    )
                    return
                if i + 1 >= len(data_args):
                    console._print_message("ERROR", "--file requires a file path.")
                    return
                file_mode = True
                file_path = data_args[i + 1]
                i += 2
                if i < len(data_args):
                    console._print_message(
                        "WARN",
                        "Extra arguments after --file path are ignored."
                    )
                break
            elif token == "--hex":
                if file_mode:
                    console._print_message(
                        "ERROR",
                        "Cannot combine --file and --hex in the same command."
                    )
                    return
                hex_mode = True
                i += 1
                break
            else:
                break

        # Build payload
        if file_mode:
            if not os.path.isfile(file_path):
                console._print_message("ERROR", f"File not found: {file_path}")
                return
            try:
                with open(file_path, "rb") as f:
                    payload = f.read()
            except Exception as e:
                console._print_message("ERROR", f"Failed to read file '{file_path}': {e}")
                return
        else:
            inline_args = data_args[i:]
            if not inline_args:
                console._print_message("ERROR", "No data provided to send.")
                return
            try:
                if hex_mode:
                    hex_str = "".join(inline_args).replace(" ", "")
                    if len(hex_str) % 2 != 0:
                        console._print_message(
                            "WARN",
                            "Odd-length hex string; padding with trailing '0'."
                        )
                        hex_str += "0"
                    payload = bytes.fromhex(hex_str)
                else:
                    text = " ".join(inline_args)
                    payload = text.encode("utf-8")
            except ValueError as e:
                console._print_message("ERROR", f"Invalid hex data: {e}")
                return

        # Device mode: configure hdc fport so the socket is effectively inside the phone
        if use_fport:
            if not console.hdc_device_id:
                console._print_message(
                    "ERROR",
                    "No HarmonyOS device is connected via hdc. Cannot configure fport."
                )
                return

            fport_args = [
                "-t",
                console.hdc_device_id,
                "fport",
                f"tcp:{port}",
                f"tcp:{port}",
            ]
            console._print_message(
                "INFO",
                f"Configuring hdc port forwarding: fport tcp:{port} tcp:{port}"
            )
            stdout, stderr, retcode = console._execute_hdc_command(fport_args)
            if retcode != 0:
                console._print_message(
                    "WARNING",
                    f"hdc fport failed with code {retcode}. stderr: {stderr or 'no stderr'}"
                )
                # fport may already be active; still attempt to send.

        # Send payload over TCP/UDP
        try:
            if proto == "tcp":
                with socket.create_connection((host, port), timeout=5.0) as s:
                    s.sendall(payload)
                console._print_message(
                    "INFO",
                    f"Sent {len(payload)} bytes over TCP to {host}:{port}"
                )
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(payload, (host, port))
                console._print_message(
                    "INFO",
                    f"Sent {len(payload)} bytes over UDP to {host}:{port}"
                )
        except Exception as e:
            console._print_message("ERROR", f"Failed to send data: {e}")


def register(register_func) -> None:
    register_func(NetSendCommand())

