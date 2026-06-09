# -*- coding: utf-8 -*-
# commands/android/agent_exec.py
import time
from typing import List

from commands.base import Command, CommandSource

_DEFAULT_TIMEOUT = 15.0


# ---------------------------------------------------------------------------
# Shared helper: route any command line through the on-device agent.
#
# Used by:
#   - AndroidAgentExecCommand (explicit 'agent_exec ...' verb)
#   - Harm0nyz3rConsole.execute_command (the generic '--via-agent' flag)
# ---------------------------------------------------------------------------

def route_via_agent(console, command_line: str, timeout: float = _DEFAULT_TIMEOUT) -> None:
    """
    Send 'COMMAND_REQUEST:<command_line>' over the socket and wait for the
    reply (rendered by the receive loop) or a timeout.

    The receive loop is the one rendering output; this helper just owns the
    send + synchronous wait so callers don't need to duplicate the polling
    loop on console.last_agent_response.
    """
    if not console.connected:
        console._print_message("ERROR", "Not connected to the agent (run 'connect' first).")
        return

    console.last_agent_response = None
    console._print_message("INFO", f"Routing via agent: {command_line}")
    if not console.send_data_to_app(f"COMMAND_REQUEST:{command_line}"):
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

    if console.last_agent_response is None:
        console._print_message(
            "WARNING",
            f"No reply from agent within {timeout:.0f}s. Long-running commands "
            "(e.g. app_activity_fuzz) may still be running; the reply will appear "
            "in the console as soon as it arrives."
        )
        return

    # Reply has already been rendered by the receive loop -- just free the slot.
    console.last_agent_response = None


# The set of commands the Kotlin agent's CommandHandler currently dispatches.
# Used by Harm0nyz3rConsole.execute_command to decide whether '--via-agent' is
# meaningful for a given command.
AGENT_SUPPORTED_COMMANDS = frozenset({
    "apps_list",
    "app_info",
    "app_surface",
    "apps_exported_activities",
    "apps_visible_abilities",   # CLI alias of apps_exported_activities
    "app_activity_start",
    "app_activity_intent",
    "app_activity_fuzz",
    "app_ability",              # D-bucket alias of app_activity_start
    "app_ability_want",         # D-bucket alias of app_activity_intent
    "app_ability_fuzz",         # D-bucket alias of app_activity_fuzz
    "app_broadcast",
    "app_deeplink",
    "app_permissions",
    "app_provider",
    "shell_exec",
})


class AndroidAgentExecCommand(Command):
    """
    Route a command to the on-device Kotlin agent over the socket.

    Most Android CLI commands talk to the device directly via 'adb'.  agent_exec
    instead sends a 'COMMAND_REQUEST:' to the agent, so the agent executes the
    command inside its own app process (framework APIs, app-granted permissions).
    Useful for exercising the agent and for commands that behave differently
    in-process than they do through 'adb'.

    Agent-supported commands: apps_list, app_info, app_surface,
    apps_exported_activities (alias: apps_visible_abilities),
    app_activity_start (alias: app_ability), app_activity_intent
    (alias: app_ability_want), app_activity_fuzz (alias: app_ability_fuzz),
    app_broadcast, app_deeplink, app_permissions, app_provider, shell_exec.

    The reply is rendered by the console's receive loop (see Harm0nyz3rConsole
    ._render_agent_reply); this command just waits until the reply has arrived
    and surfaces a timeout warning when nothing comes back in time.
    """

    @property
    def name(self) -> str:
        return "agent_exec"

    def help(self) -> str:
        return (
            "agent_exec <command> [args ...] [--timeout S]\n"
            "  Send a command to the on-device agent.  The reply is rendered\n"
            "  by the console as soon as it arrives.\n"
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

        route_via_agent(console, " ".join(args), timeout=timeout)


def register(registry_func):
    registry_func(AndroidAgentExecCommand())
