# -*- coding: utf-8 -*-
# commands/android/agent_exec.py
import json
import time
from typing import List

from commands.base import Command, CommandSource

_DEFAULT_TIMEOUT = 15.0


class AndroidAgentExecCommand(Command):
    """
    Route a command to the on-device Kotlin agent over the socket.

    Most Android CLI commands talk to the device directly via 'adb'.  agent_exec
    instead sends a 'COMMAND_REQUEST:' to the agent, so the agent executes the
    command inside its own app process (framework APIs, app-granted permissions).
    Useful for exercising the agent and for commands that behave differently
    in-process than they do through 'adb'.

    Agent-supported commands: apps_list, app_info, app_surface,
    apps_visible_abilities, app_ability, app_ability_want, app_ability_fuzz,
    app_broadcast, app_deeplink, app_permissions, app_provider, shell_exec.
    """

    @property
    def name(self) -> str:
        return "agent_exec"

    def help(self) -> str:
        return (
            "agent_exec <command> [args ...] [--timeout S]\n"
            "  Send a command to the on-device agent and print its reply.\n"
            "  --timeout S  Seconds to wait for the reply (default 15).\n\n"
            "Examples:\n"
            "  agent_exec apps_list\n"
            "  agent_exec app_permissions com.example.app --dangerous\n"
            "  agent_exec app_deeplink myapp://admin/panel\n"
            "  agent_exec app_broadcast com.example.REFRESH -n com.example.app/.Receiver"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "agent_exec is only available from the CLI.")
            return

        if not console.connected:
            console._print_message("ERROR", "Not connected to the agent. Run 'connect' first.")
            return

        timeout = _DEFAULT_TIMEOUT
        if "--timeout" in args:
            idx = args.index("--timeout")
            if idx + 1 < len(args):
                try:
                    timeout = float(args[idx + 1])
                except ValueError:
                    console._print_message("WARNING", f"Invalid --timeout value; using {timeout}s.")
                args = args[:idx] + args[idx + 2:]
            else:
                args = args[:idx]

        if not args:
            console._print_message("INFO", self.help())
            return

        request = " ".join(args)
        console.last_agent_response = None
        console._awaiting_agent_reply = True
        console._print_message("INFO", f"Sending to agent: {request}")

        try:
            if not console.send_data_to_app(f"COMMAND_REQUEST:{request}"):
                console._print_message("ERROR", "Failed to send command to the agent.")
                return

            waited = 0.0
            while (
                console.last_agent_response is None
                and waited < timeout
                and console.connected
            ):
                time.sleep(0.1)
                waited += 0.1
            reply = console.last_agent_response
        finally:
            console._awaiting_agent_reply = False

        if reply is None:
            console._print_message(
                "WARNING",
                f"No reply from agent within {timeout:.0f}s. Long-running commands "
                "(e.g. app_ability_fuzz) may still be running; the reply will appear "
                "as an [APP MESSAGE] when it arrives."
            )
            return

        self._print_reply(console, reply)
        console.last_agent_response = None

    @staticmethod
    def _print_reply(console, raw: str) -> None:
        """Replies are 'TYPE:payload'; pretty-print JSON payloads when possible."""
        msg_type, sep, payload = raw.partition(":")
        if not sep:
            console._print_message("INFO", f"Agent reply: {raw}")
            return

        payload = payload.strip()
        if msg_type == "HDC_OUTPUT_ERROR":
            console._print_message("ERROR", f"Agent error: {payload}")
            return

        rendered = payload
        try:
            rendered = json.dumps(json.loads(payload), indent=2)
        except (json.JSONDecodeError, ValueError):
            pass

        console._print_message("SUCCESS", f"Agent reply [{msg_type}]:")
        print(rendered)


def register(registry_func):
    registry_func(AndroidAgentExecCommand())
