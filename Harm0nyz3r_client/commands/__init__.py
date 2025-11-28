# commands/__init__.py

from typing import Dict, List
from .base import Command

# Internal registry: maps command names and aliases to Command instances
_command_registry: Dict[str, Command] = {}


def register_command(cmd: Command) -> None:
    """
    Register a command and its aliases in the global registry.
    """
    # Primary name
    _command_registry[cmd.name] = cmd

    # Optional aliases
    for alias in cmd.aliases:
        _command_registry[alias] = cmd


def get_command(name: str) -> Command | None:
    """
    Look up a command by name (or alias).
    """
    return _command_registry.get(name)


def list_commands() -> List[Command]:
    """
    Return a deduplicated list of all registered Command instances,
    sorted by their primary name.
    """
    seen = set()
    unique_cmds: List[Command] = []
    for cmd in _command_registry.values():
        if id(cmd) not in seen:
            seen.add(id(cmd))
            unique_cmds.append(cmd)

    # Sort by primary name for nicer 'help' output
    return sorted(unique_cmds, key=lambda c: c.name)
