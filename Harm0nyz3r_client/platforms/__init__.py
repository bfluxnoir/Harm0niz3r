"""
platforms/__init__.py
----------------------
Factory function to instantiate the correct platform adapter by name.
"""

from .base_platform import BasePlatform
from .harmonyos import HarmonyOSPlatform
from .android import AndroidPlatform
from .ios import iOSPlatform

_REGISTRY = {
    "harmonyos": HarmonyOSPlatform,
    "android": AndroidPlatform,
    "ios": iOSPlatform,
}


def get_platform(name: str) -> BasePlatform:
    """
    Return a platform adapter instance for the given name.

    Args:
        name: One of 'harmonyos', 'android', 'ios'.

    Raises:
        ValueError: If the platform name is unknown.
    """
    name = name.lower().strip()
    cls = _REGISTRY.get(name)
    if cls is None:
        available = ", ".join(sorted(_REGISTRY))
        raise ValueError(
            f"Unknown platform '{name}'. Available platforms: {available}"
        )
    return cls()


def list_platforms() -> list:
    """Return sorted list of supported platform names."""
    return sorted(_REGISTRY.keys())
