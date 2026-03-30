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
# ANSI colour helpers (used only in ASCII banners)
# ---------------------------------------------------------------------------
_RST  = "\033[0m"
_BOLD = "\033[1m"
# HarmonyOS palette – reds / amber
_R1   = "\033[31m"    # dark red
_R2   = "\033[91m"    # bright red
_AMB  = "\033[33m"    # amber / yellow
# Android palette – greens
_G1   = "\033[32m"    # dark green
_G2   = "\033[92m"    # bright green

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