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
# ASCII Art for initial run: Rising sun between mountains with "Harm0nyz3r"
HARMONYZER_ASCII = f"""
            .-----.
           /       \\
          /_________\\
         / /\\  /\\  /\\ \\
        / /  \\/  \\/  \\ \\
       /_/____\\____\\___\\
      ^^^^^^^^^^^^^^^^^^^
   |\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/|
   |  H A R M 0 N Y Z 3 R |
   |______________________|

    App Security Companion Script

    {VERSION}
"""