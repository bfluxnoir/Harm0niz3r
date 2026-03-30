# Harm0niz3r

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![HarmonyOS](https://img.shields.io/badge/HarmonyOS-Next%205.0%2B-lightgrey.svg)
![Android](https://img.shields.io/badge/Android-8.0%2B-green.svg)
![iOS](https://img.shields.io/badge/iOS-coming%20soon-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

A powerful security assessment and application interaction framework originally built for HarmonyOS Next (5.0+), now a multi-platform tool with full Android support and iOS support in progress.

Harm0niz3r enables researchers to interact with and analyze applications from a controlled rogue app, allowing enumeration of internal components and permissions in a simple and extensible way.

# Quickstart

## Setup

Download or clone this Github repo:

```bash
git clone https://github.com/DEKRA-Cybersecurity/Harm0niz3r/
```

### Agent Setup

An on-device agent must be installed on the target device before using most features.

**HarmonyOS** — install the `.hap` package via DevEco Studio or `hdc`:

```bash
hdc app install harm0niz3r.hap
```

**Android** — build the Kotlin agent with Android Studio (open `Harm0nyz3r_android/`) or
install a pre-built APK:

```bash
adb install harm0niz3r.apk
```

Then launch the **Harm0niz3r** app on the device and tap **Start Agent**. The agent runs as a
foreground service and listens on `127.0.0.1:51337`.

> The Android agent requires **Android 8.0+ (API 26+)** and grants itself
> `QUERY_ALL_PACKAGES` at install time for full package enumeration.

### Server Setup

Run the server, specifying the target platform with `--platform` (defaults to `harmonyos`):

```bash
# HarmonyOS (default)
python3 Harm0nyz3r.py

# Android
python3 Harm0nyz3r.py --platform android

# Custom host / port
python3 Harm0nyz3r.py --platform android --host 127.0.0.1 --port 51337
```

Available options:

```
usage: Harm0nyz3r.py [-h] [--platform {android,harmonyos,ios}] [--host HOST] [--port PORT]
```

The bridge tool (`hdc` for HarmonyOS, `adb` for Android) must be installed and available in `PATH`.

## Connection

Client and server must be connected to have full functionality available. First, set up port
forwarding on the host depending on the platform:

**HarmonyOS**
```bash
hdc fport tcp:51337 tcp:51337
```

**Android**
```bash
adb forward tcp:51337 tcp:51337
```

Then from the Harm0niz3r CLI run the `connect` command (ensure the on-device agent is running
and listening on port 51337). The *MARCO-POLO* handshake will be performed and the connection
established.

> If the connection fails, make sure port forwarding is active and re-run both the agent and the server.

# Usage

Both client GUI and server CLI can be used to perform many operations. With `help` command in CLI all possibilities are shown.

## App List

Touching *Get App List from PC* in client UI will display a list of all installed apps, allowing the user to query relevant information for each one.

This same functionality is possible through CLI using the `apps_list -a` command.

## Get Exposed Abilities / Activities

Exposed abilities (HarmonyOS) or exported Activities (Android) may contain sensitive information,
so checking all of them may be interesting. In the client UI it is possible to list and invoke
each one with the *Get Abilities from PC* option.

To perform the same operation in the CLI:

```
apps_visible_abilities
```

## Android Commands

When running with `--platform android` the following commands are available:

| Command | Description |
|---------|-------------|
| `apps_list [-a] [-3]` | List installed packages (`-a` all, `-3` third-party only) |
| `app_info <package>` | Version, SDK, flags, permissions for a package |
| `app_surface <package>` | All exported components with permissions and intent filters |
| `apps_visible_abilities` | All exported Activities with no permission guard |
| `app_ability <pkg> <activity>` | Launch an Activity via `am start` |
| `app_ability_want <pkg> <activity> [extras]` | Launch with structured Intent extras |
| `app_ability_fuzz <pkg> <activity>` | Fuzz-launch an Activity with randomised extras |
| `app_broadcast <action> [-n component] [extras]` | Send a broadcast via `am broadcast` |
| `app_deeplink <uri>` | Trigger a deep-link via `am start VIEW` |
| `app_permissions <package> [--dangerous]` | Show requested / granted permissions |
| `app_provider <authority> [columns]` | Query a Content Provider by URI |
| `shell_exec <cmd>` | Execute a shell command on the device |

# Architecture

## Multi-Platform Design (v1.3+)

Starting from v1.3, Harm0niz3r introduces a **Platform Abstraction Layer (PAL)** that decouples
the Python server from any specific device bridge tool. This makes it straightforward to add
support for new mobile platforms without touching the core console logic or any existing commands.

```
                  ┌──────────────────────────────────────────┐
                  │           Python CLI Server               │
                  │  ┌──────────────┐  ┌──────────────────┐  │
                  │  │  Console /   │  │ Command Registry │  │
                  │  │  Core Logic  │  │  (unchanged)     │  │
                  │  └──────┬───────┘  └──────────────────┘  │
                  │         │ self.platform                   │
                  │  ┌──────▼───────────────────────────┐    │
                  │  │     Platform Abstraction Layer    │    │
                  │  │  harmonyos.py | android.py | ios  │    │
                  │  └──────┬──────────────┬─────────────┘   │
                  └─────────┼──────────────┼─────────────────┘
                            │              │
                  hdc fport │              │ adb forward
                            ▼              ▼
                      [HarmonyOS]      [Android]
                       ArkTS Agent    Kotlin Agent
```

### Platform status

| Platform   | Bridge tool | Agent        | Status          |
|------------|-------------|--------------|-----------------|
| HarmonyOS  | `hdc`       | ArkTS app    | ✅ Full support  |
| Android    | `adb`       | Kotlin app   | ✅ Full support  |
| iOS        | `iproxy`    | Swift binary | 📋 Phase 3       |

## Android Agent Architecture

The Android agent (`Harm0nyz3r_android/`) is a standard Android application written in Kotlin
that mirrors the HarmonyOS ArkTS agent in functionality.

```
Harm0nyz3r_android/
├── app/
│   ├── build.gradle
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/com/dekra/harm0niz3r/
│       │   ├── MainActivity.kt        # Toggle UI (Start / Stop Agent)
│       │   ├── Harm0nizerService.kt   # Foreground service managing TcpServer
│       │   ├── TcpServer.kt           # TCP socket server + MARCO-POLO handshake
│       │   └── CommandHandler.kt      # Command dispatcher (PackageManager / ContentResolver)
│       └── res/
│           ├── layout/activity_main.xml
│           ├── values/strings.xml
│           └── drawable/ic_launcher.xml
├── build.gradle
└── settings.gradle
```

**Key implementation notes:**

- Runs as a `START_STICKY` foreground service to survive background restrictions.
- Binds only to `127.0.0.1:51337` (loopback) — traffic never leaves the device.
- MARCO-POLO handshake extended: Android agent replies `POLO:android:2.0` so the server can
  detect the platform version.
- `CommandHandler` dispatches the same command set as the HarmonyOS agent:
  `apps_list`, `app_surface`, `app_info`, `apps_visible_abilities`, `app_ability`,
  `shell_exec`, `app_provider`.
- Requires `QUERY_ALL_PACKAGES` permission (declared in `AndroidManifest.xml`).

## Project Structure

```
Harm0niz3r/
├── Harm0nyz3r/                    # HarmonyOS on-device agent (ArkTS)
│   ├── AppScope/
│   └── entry/
│
├── Harm0nyz3r_android/            # Android on-device agent (Kotlin)
│   ├── app/
│   │   ├── build.gradle
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       └── java/com/dekra/harm0niz3r/
│   ├── build.gradle
│   └── settings.gradle
│
└── Harm0nyz3r_client/             # Python server / CLI
    ├── Harm0nyz3r.py              # Entry point and console loop
    ├── config.py                  # Global configuration + platform defaults
    │
    ├── platforms/                 # Platform Abstraction Layer (PAL)
    │   ├── base_platform.py       # Abstract interface (BasePlatform)
    │   ├── harmonyos.py           # HarmonyOS / hdc adapter
    │   ├── android.py             # Android / adb adapter
    │   └── ios.py                 # iOS stub (Phase 3)
    │
    ├── parsers/                   # Output parsers, one per platform
    │   ├── harmonyos_parser.py    # bm dump -n <namespace> parser
    │   ├── android_parser.py      # pm list packages / pm dump parser
    │   └── ios_parser.py          # Info.plist / URL scheme parser stub
    │
    └── commands/                  # Modular command registry
        ├── base.py                # Command abstract class
        ├── android/               # Android-specific commands (12 total)
        │   ├── apps_list.py
        │   ├── app_info.py
        │   ├── app_surface.py
        │   ├── apps_visible_abilities.py
        │   ├── app_ability.py
        │   ├── app_ability_want.py
        │   ├── app_ability_fuzz.py
        │   ├── app_broadcast.py
        │   ├── app_deeplink.py
        │   ├── app_permissions.py
        │   ├── app_provider.py
        │   └── shell_exec.py
        ├── apps_list.py           # HarmonyOS commands
        ├── app_info.py
        ├── app_surface.py
        └── ...                    # (13 HarmonyOS commands total)
```

# Development

This section is meant to be a development guide for anyone contributing.

## Server

The server is written in Python 3.10+ and provides direct interaction with the device via a
configurable bridge tool. It offers a CLI but requires the target device to be connected to the PC.

## Client (App)

Apart from the server, a native application is provided. This application must be installed on
the target device, enabling operations in a simpler way.

The HarmonyOS (ArkTS) and Android (Kotlin) agents are both fully functional.
The iOS agent is planned for Phase 3.

## Connection and Communication

When `connect` is sent from the CLI, a TCP socket is opened (default port `51337`). If successful,
the *MARCO-POLO* handshake is performed:

1. Server sends `MARCO \n\n` to the agent.
2. If the agent responds with `POLO` (HarmonyOS) or `POLO:android:2.0` (Android), the session is established.

```ts
// Handshake side in HarmonyOS client
if (txt === 'MARCO') {
    await cli.send({ data: 'POLO' });
    this.status = `Console connected on ${this.port}`;
    hilog.info(0x0000, 'AppLog', 'Responded with POLO for MARCO handshake.');
    return;
}
```

```kotlin
// Handshake side in Android agent (TcpServer.kt)
if (message == "MARCO") {
    sendMessage(writer, "POLO:android:2.0")
}
```

Once connected, a thread continuously reads from the socket so the agent can send requests to
the server or vice versa.

### Client to server communication

Usually the client will request the server to perform operations or provide some information.
For this purpose the client implements `sendToPcClient`, which sends a message string.

Messages have the following structure: `COMMAND_REQUEST:<command>`, where the first part is
the type and the second is the payload, separated by a colon.

The server processes those messages in `_receive_loop`:

```python
if decoded_data.startswith('COMMAND_REQUEST:'):
    command_payload = decoded_data[len('COMMAND_REQUEST:'):].strip()
    self._print_message("INFO", f"Received command request from app: '{command_payload}'")
    self._process_app_command_request(command_payload)
```

### Server to client communication

The server sends data with `send_data_to_app`. Messages share the same structure and include
` \n\n` as an ending trail.

The ending trail is necessary because responses can span multiple TCP packets. The client
implements buffered reception (in `handlePacket`) which waits for ` \n\n` before calling
`processFullMessage` to interpret the complete message.

## Adding New Commands

Commands are implemented as modular classes under `commands/` and registered through a central
registry. Adding a new command involves three steps:

### 1. Create a new Command module

```python
# commands/example_feature.py
from typing import List
from .base import Command, CommandSource


class ExampleFeatureCommand(Command):
    @property
    def name(self) -> str:
        return "example_feature"

    @property
    def supports_logging(self) -> bool:
        return False  # Set to True to enable --log support

    def help(self) -> str:
        return (
            "example_feature [args]\n"
            "  A new example feature in the Harm0nyz3r console.\n"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        console._print_message("INFO", "Executing example_feature...")
        # stdout, stderr, ret = console._get_hdc_shell_output(["bm", "dump", "-a"])
        # console.send_data_to_app("COMMAND_REQUEST:new_feature")
        console._print_message("INFO", "Done.")


def register(registry_func):
    registry_func(ExampleFeatureCommand())
```

### 2. Register it in `Harm0nyz3r.py`

```python
from commands import (
    ...,
    example_feature,   # <-- new command
)

# Inside _register_builtin_commands():
example_feature.register(register_command)
```

### 3. (Optional) Add an app-side handler

If the feature needs to interact with the on-device agent, send a command from the console:

```python
console.send_data_to_app("COMMAND_REQUEST:new_feature some arguments")
```

## Adding a New Platform

Implement `BasePlatform` from `platforms/base_platform.py` and register it in `platforms/__init__.py`:

```python
# platforms/my_platform.py
from .base_platform import BasePlatform

class MyPlatform(BasePlatform):
    @property
    def name(self) -> str:
        return "myplatform"

    @property
    def bridge_command(self) -> str:
        return "mybridge"

    def detect_device(self):
        # Run bridge detection command, return (device_id, device_name)
        ...

    def execute_bridge_command(self, args):
        # subprocess.run([self.bridge_command] + args, ...)
        ...

    def device_shell_args(self, device_id):
        return ["--device", device_id, "shell"]

    def pull_file_args(self, device_id, remote, local):
        return ["--device", device_id, "pull", remote, local]

    def get_log_shell_command(self, remote_path):
        return f"mylog > {remote_path} 2>&1 & echo $!"
```

Then register it:

```python
# platforms/__init__.py
from .my_platform import MyPlatform

_REGISTRY = {
    ...
    "myplatform": MyPlatform,
}
```

It will be automatically available as `python3 Harm0nyz3r.py --platform myplatform`.

# Authors

- Jorge Wallace Ruiz
- Pablo Cáceres Gaitán

As part of DEKRA's cybersecurity team.

## License

Harm0niz3r is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.
