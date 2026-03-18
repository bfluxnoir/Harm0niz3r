# commands/android package — Android-specific command implementations.
# Imported and registered by Harm0nyz3r.py when --platform android is used.
from . import (
    apps_list,
    app_info,
    app_surface,
    apps_visible_abilities,
    app_ability,
    app_ability_want,
    app_ability_fuzz,
    app_broadcast,
    app_deeplink,
    app_permissions,
    app_provider,
    shell_exec,
)

__all__ = [
    "apps_list",
    "app_info",
    "app_surface",
    "apps_visible_abilities",
    "app_ability",
    "app_ability_want",
    "app_ability_fuzz",
    "app_broadcast",
    "app_deeplink",
    "app_permissions",
    "app_provider",
    "shell_exec",
]
