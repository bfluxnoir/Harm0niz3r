from abc import ABC, abstractmethod
from typing import List, Literal

CommandSource = Literal["cli", "app"]

class Command(ABC):
    """
    Base interface for all commands.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Primary command name, e.g. 'apps_list'."""

    @property
    def aliases(self) -> List[str]:
        """Optional alternative names."""
        return []

    @property
    def supports_logging(self) -> bool:
        """
        Whether this command supports the --log flag.

        If True, the console will:
          - accept '--log' as a generic flag
          - set a per-command "log enabled" context that the command can query.
        """
        return False

    @abstractmethod
    def help(self) -> str:
        """Short help line for 'help' output."""

    @abstractmethod
    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Execute the command.

        console: HarmonyOSClientConsole instance (for logging, HDC, socket,…)
        args:    list of string args (no command name, '--log' already stripped)
        source:  'cli' or 'app'
        """