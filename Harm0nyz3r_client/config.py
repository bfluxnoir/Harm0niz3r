# -*- coding: utf-8 -*-
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


# ---------------------------------------------------------------------------
# Console UI theme  –  semantic colour roles per platform
# ---------------------------------------------------------------------------
#
# Each role is a raw ANSI open-code string (no reset).  Callers must append
# _RST themselves.  Use get_theme() to obtain the correct set for a platform.
#
# Roles:
#   HEADER        – bold title bar
#   SECTION       – section heading
#   SEPARATOR     – ─ / ━ divider lines
#   FOOTER        – closing rule
#   LABEL         – field name in status block  ("Server:", "Device:")
#   VALUE         – field value  (host, device name)
#   CONNECTED     – ✅ connected state indicator
#   DISCONNECTED  – ❌ disconnected state indicator
#   VERBOSE_ON    – verbose enabled indicator
#   VERBOSE_OFF   – verbose disabled indicator
#   SETUP_TAG     – [ SETUP ] attention marker
#   STEP_NUM      – numbered step prefix
#   STEP_TEXT     – step body text
#   HINT_TAG      – ⚠ soft warning / tip
#   CMD_NAME      – command keyword in listings
#   CMD_DESC      – description text after the dash
#   EX_HDR        – "Quick examples" heading
#   EX_CMD        – command part of an example line
#   EX_ARG        – argument(s) part of an example line
#   PROMPT_CONN   – prompt colour when connected
#   PROMPT_DISC   – prompt colour when disconnected

try:
    from types import SimpleNamespace as _NS
except ImportError:
    class _NS:                         # type: ignore[no-redef]
        def __init__(self, **kw): self.__dict__.update(kw)

def get_theme(platform_name: str) -> "_NS":
    """Return a namespace of ANSI open-codes for every console UI role."""

    # ── shared universals ──────────────────────────────────────────────
    _CONN  = f"{_BOLD}\033[92m"        # bold bright-green (connected – always)
    _DISC  = f"{_BOLD}\033[91m"        # bold bright-red   (disconnected – always)
    _V_OFF = f"{_DIM}{_GREY}"
    _HINT  = f"{_ITALIC}{_AMB}"
    _LBL   = f"{_DIM}{_WHITE}"
    _VAL   = _WHITE
    _VOFF  = f"{_DIM}{_GREY}"
    _FOT   = f"{_DIM}{_GREY}"

    if platform_name == "android":
        return _NS(
            RST          = _RST,
            HEADER       = f"{_BOLD}{_G2}",
            SECTION      = f"{_BOLD}{_G1}",
            SEPARATOR    = f"{_DIM}{_G1}",
            FOOTER       = _FOT,
            LABEL        = _LBL,
            VALUE        = _VAL,
            CONNECTED    = _CONN,
            DISCONNECTED = _DISC,
            VERBOSE_ON   = f"{_BOLD}{_G2}",
            VERBOSE_OFF  = _VOFF,
            SETUP_TAG    = f"{_BOLD}{_G2}",
            STEP_NUM     = f"{_BOLD}{_G2}",
            STEP_TEXT    = _VAL,
            HINT_TAG     = _HINT,
            CMD_NAME     = f"{_BOLD}{_G2}",
            CMD_DESC     = f"{_DIM}{_WHITE}",
            EX_HDR       = f"{_BOLD}{_G2}",
            EX_CMD       = _G2,
            EX_ARG       = _G1,
            PROMPT_CONN  = _G2,
            PROMPT_DISC  = _GREY,
        )
    else:   # harmonyos / ios / fallback  →  red / amber palette
        return _NS(
            RST          = _RST,
            HEADER       = f"{_BOLD}{_R2}",
            SECTION      = f"{_BOLD}{_AMB}",
            SEPARATOR    = f"{_DIM}{_R1}",
            FOOTER       = _FOT,
            LABEL        = _LBL,
            VALUE        = _VAL,
            CONNECTED    = _CONN,
            DISCONNECTED = _DISC,
            VERBOSE_ON   = f"{_BOLD}{_R2}",
            VERBOSE_OFF  = _VOFF,
            SETUP_TAG    = f"{_BOLD}{_AMB}",
            STEP_NUM     = f"{_BOLD}{_AMB}",
            STEP_TEXT    = _VAL,
            HINT_TAG     = _HINT,
            CMD_NAME     = f"{_BOLD}{_R2}",
            CMD_DESC     = f"{_DIM}{_WHITE}",
            EX_HDR       = f"{_BOLD}{_AMB}",
            EX_CMD       = _R2,
            EX_ARG       = _AMB,
            PROMPT_CONN  = _R2,
            PROMPT_DISC  = _GREY,
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