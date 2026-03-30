# config.py

VERSION = "v1.2.1"

SERVER_HOST = '127.0.0.1'
PORT = 51337
BUFFER_SIZE = 8192 * 2  # Max size for single message. Keep in mind for very long lists.
SHELL_EXEC_PROMPT = "[shell] $ "

# ---------------------------------------------------------------------------
# Platform configuration
# ---------------------------------------------------------------------------
# Legacy constant kept for any direct references outside the PAL.
HDC_COMMAND = 'hdc'

DEFAULT_PLATFORM = "harmonyos"

# Per-platform defaults.  The PAL (platforms/) is authoritative at runtime;
# these entries are used to display help text and validate CLI input.
PLATFORM_CONFIGS = {
    "harmonyos": {
        "bridge_command": "hdc",
        "port_forward_hint": "hdc -t <device_id> fport tcp:51337 tcp:51337",
    },
    "android": {
        "bridge_command": "adb",
        "port_forward_hint": "adb -s <device_id> forward tcp:51337 tcp:51337",
    },
    "ios": {
        "bridge_command": "iproxy",
        "port_forward_hint": "iproxy 51337 51337 --udid <device_udid>",
    },
}
# ---------------------------------------------------------------------------
# ANSI colour primitives
# ---------------------------------------------------------------------------
_RST    = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_ITALIC = "\033[3m"

# Foreground colours
_GREY   = "\033[90m"   # dark / dim grey
_WHITE  = "\033[97m"   # bright white
_AMB    = "\033[33m"   # amber / yellow
_AMBER  = "\033[33m"   # alias
_CYAN   = "\033[36m"

# HarmonyOS palette – reds / amber
_R1     = "\033[31m"   # dark red
_R2     = "\033[91m"   # bright red

# Android palette – greens
_G1     = "\033[32m"   # dark green
_G2     = "\033[92m"   # bright green

# Universal semantic colours
_GREEN  = "\033[32m"
_BGREEN = "\033[92m"
_RED    = "\033[31m"
_BRED   = "\033[91m"

# Background colours (for FATAL)
_BG_RED = "\033[41m"

# ---------------------------------------------------------------------------
# HarmonyOS banner  (red / amber theme)
# ---------------------------------------------------------------------------
_HARMONY_BANNER = (
    f"\n"
    f"{_R1}            .-----.\n"
    f"{_R1}           /       \\\n"
    f"{_R1}          /_________\\\n"
    f"{_R1}         / /\\  /\\  /\\ \\\n"
    f"{_R1}        / /  \\/  \\/  \\ \\\n"
    f"{_R1}       /_/____\\____\\___\\\n"
    f"{_AMB}      ^^^^^^^^^^^^^^^^^^^\n"
    f"{_R1}   |\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/|\n"
    f"{_R1}   |{_BOLD}{_R2}  H A R M 0 N Y Z 3 R {_RST}{_R1}|\n"
    f"{_R1}   |______________________|\n"
    f"{_RST}\n"
    f"    App Security Companion Script\n\n"
    f"    {VERSION}\n"
)

# ---------------------------------------------------------------------------
# Android banner  (green theme)
# ---------------------------------------------------------------------------
_ANDROID_BANNER = (
    f"\n"
    f"{_G1}           __         __\n"
    f"{_G1}          /  \\       /  \\\n"
    f"{_G2}    .----'    '-------'    '----.\n"
    f"{_G2}   /   {_G1}(o){_G2}                 {_G1}(o){_G2}   \\\n"
    f"{_G2}  |          _________          |\n"
    f"{_G2}  |         |         |         |\n"
    f"{_G2}  |         |_________|         |\n"
    f"{_G2}   \\    ___________________    /\n"
    f"{_G2}    '---[___________________]---'\n"
    f"{_G2}        |    |       |    |\n"
    f"{_G1}     .--'    |       |    '--.\n"
    f"{_G1}     '--'    |       |    '--'\n"
    f"{_G2}\n"
    f"   |\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/|\n"
    f"   |{_BOLD}{_G2}     A N D R 0 I D        {_RST}{_G2}|\n"
    f"   |__________________________|\n"
    f"{_RST}\n"
    f"    App Security Companion Script\n\n"
    f"    {VERSION}\n"
)


def get_ascii_art(platform_name: str) -> str:
    """Return the coloured ASCII banner for the given platform."""
    if platform_name == "android":
        return _ANDROID_BANNER
    return _HARMONY_BANNER          # harmonyos / ios / unknown → HarmonyOS banner


# Legacy alias kept so any existing direct reference to HARMONYZER_ASCII
# still works (it defaults to the HarmonyOS banner).
HARMONYZER_ASCII = _HARMONY_BANNER


# ---------------------------------------------------------------------------
# Console message theme
# ---------------------------------------------------------------------------
#
# Each entry maps a log level to (label_style, label_text, message_style).
#   label_style  – ANSI codes applied to the "[LEVEL]" tag
#   label_text   – text inside the brackets (can differ from the key)
#   message_style – ANSI codes applied to the message body (subtle tint)
#
# INFO is intentionally absent here – it is platform-specific (see below).
#
_LEVEL_THEME: dict[str, tuple[str, str, str]] = {
    #              label_style                label_text    message_style
    "SUCCESS":    (f"{_BOLD}{_BGREEN}",       "SUCCESS",    _BGREEN),
    "WARNING":    (f"{_BOLD}{_AMB}",          "WARNING",    _AMB),
    "ERROR":      (f"{_BOLD}{_BRED}",         "ERROR",      _BRED),
    "FATAL_ERROR":(f"{_BOLD}{_WHITE}{_BG_RED}","FATAL",     f"{_BOLD}{_BRED}"),
    "DEBUG":      (f"{_DIM}{_GREY}",          "DEBUG",      _GREY),
}

# Platform-specific INFO style
_INFO_THEME: dict[str, tuple[str, str, str]] = {
    "harmonyos": (f"{_BOLD}{_R2}",  "INFO", _R1),       # bold bright-red label, dark-red text
    "android":   (f"{_BOLD}{_G2}",  "INFO", _G1),       # bold bright-green label, dark-green text
    "ios":       (f"{_BOLD}{_CYAN}", "INFO", _CYAN),     # cyan (future)
}
_INFO_THEME_DEFAULT = (f"{_BOLD}{_WHITE}", "INFO", "")   # fallback


def get_level_label(platform_name: str, level: str) -> tuple[str, str]:
    """
    Return (coloured_label, message_colour_prefix) for the given platform and level.

    coloured_label       – ready-to-print "[LEVEL]" string with ANSI codes + reset
    message_colour_prefix – ANSI code to apply to the message body (caller appends _RST)

    Usage::
        label, mcol = get_level_label("android", "ERROR")
        print(f"{label} {mcol}{message}{_RST}")
    """
    if level == "INFO":
        ls, lt, ms = _INFO_THEME.get(platform_name, _INFO_THEME_DEFAULT)
    else:
        ls, lt, ms = _LEVEL_THEME.get(level, (f"{_BOLD}{_WHITE}", level, ""))

    coloured_label = f"{ls}[{lt}]{_RST}"
    return coloured_label, ms