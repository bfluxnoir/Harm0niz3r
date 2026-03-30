# Harm0niz3r

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![HarmonyOS](https://img.shields.io/badge/HarmonyOS-Next%205.0%2B-lightgrey.svg)
![Android](https://img.shields.io/badge/Android-8.0%2B-green.svg)
![iOS](https://img.shields.io/badge/iOS-coming%20soon-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

A powerful security assessment and application interaction framework originally built for HarmonyOS Next (5.0+), now a multi-platform tool with full Android support and iOS support in progress.

Harm0niz3r enables researchers to interact with and analyze applications from a controlled rogue app, allowing enumeration of internal components and permissions in a simple and extensible way.

---

# Quickstart

## Setup

Download or clone this repository:

```bash
git clone https://github.com/bfluxnoir/Harm0niz3r/
```

### Agent Setup

An on-device agent must be installed on the target device before using most features.

**HarmonyOS** — install the `.hap` package via DevEco Studio or `hdc`:

```bash
hdc app install harm0niz3r.hap
```

**Android** — open `Harm0nyz3r_android/` in Android Studio, build and install, or sideload a pre-built APK:

```bash
adb install harm0niz3r.apk
```

Then launch the **Harm0niz3r** app on the device and tap **Start Agent**. The agent runs as a
foreground service and listens on `127.0.0.1:51337`.

> The Android agent requires **Android 8.0+ (API 26+)** and grants itself
> `QUERY_ALL_PACKAGES` at install time for full package enumeration.

### Python Client Setup

Install dependencies (stdlib-only for HarmonyOS and Android; iOS requires an extra package):

```bash
pip install -r requirements.txt
```

Run the client, specifying the target platform with `--platform` (defaults to `harmonyos`):

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

---

## Connection

Client and agent must be connected to have full functionality available. First, set up port
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

> If the connection fails, make sure port forwarding is active and re-run both the agent and the client.

---

# Usage

Both client GUI (on-device app) and the Python CLI can be used to perform operations. Run `help` inside the CLI to see all available commands.

## Platform-aware console

The CLI banner, colour scheme and command set all adapt automatically based on the `--platform` flag:

| Aspect | HarmonyOS | Android |
|--------|-----------|---------|
| Banner | Red / amber mountain art | Green Android-bot art |
| `[INFO]` colour | Bold bright-red | Bold bright-green |
| Bridge command | `hdc` | `adb` |
| Port-forward hint | `hdc fport tcp:51337 tcp:51337` | `adb forward tcp:51337 tcp:51337` |

## App List

Tapping *Get App List from PC* in the on-device UI displays all installed apps. From the CLI:

```
apps_list -a          # HarmonyOS — all bundles
apps_list -3          # Android  — third-party packages only
```

## Get Exposed Abilities / Activities

Exported abilities (HarmonyOS) or exported Activities (Android) may contain sensitive information.
List and invoke each one from the CLI:

```
apps_visible_abilities
```

## Android Commands

When running with `--platform android` the following commands are available:

| Command | Description |
|---------|-------------|
| `apps_list [-a] [-3]` | List installed packages (`-a` all, `-3` third-party only) |
| `app_info <package>` | Version, SDK, flags and permissions for a package |
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

## HarmonyOS Commands

When running with `--platform harmonyos` (default):

| Command | Description |
|---------|-------------|
| `apps_list [-a]` | List all installed bundles |
| `app_info <bundleName>` | Bundle metadata, permissions and abilities |
| `app_surface <bundleName>` | Exported UIAbilities and ExtensionAbilities |
| `apps_visible_abilities` | All exported abilities with no permission guard |
| `app_ability <bundle> <ability>` | Start a UIAbility via Want |
| `app_ability_want <bundle> <ability> [params]` | Start ability with structured Want parameters |
| `app_ability_fuzz <bundle> <ability>` | Fuzz-launch ability with random Want parameters |
| `app_udmf <uri>` | Trigger a UDMF data-sharing intent |
| `apps_udmf` | List all UDMF-registered data providers |
| `shell_exec <cmd>` | Execute a shell command on the device |

---

# Android ↔ HarmonyOS Concept Map

Researchers familiar with Android will encounter different terminology on HarmonyOS. The table
below maps the core building blocks between the two platforms.

| Android | HarmonyOS Equivalent | Notes |
|---------|----------------------|-------|
| `Activity` | `UIAbility` | Full-screen UI component; managed by AbilityStage |
| `Fragment` | `Page` / `NavDestination` | Sub-screen component inside a UIAbility |
| `Service` | `ServiceExtensionAbility` | Long-running background component |
| `ContentProvider` | `DataShareExtensionAbility` | Structured data sharing between apps |
| `BroadcastReceiver` (static) | `StaticSubscriberExtensionAbility` | Declared in `module.json5`, receives system events |
| `BroadcastReceiver` (dynamic) | `CommonEventSubscriber` | Registered at runtime via `commonEventManager` |
| `Intent` | `Want` | Message object used to start components or carry data |
| `IntentFilter` | `skills` block in `module.json5` | Declares what Wants a component can handle |
| `Bundle` (Intent extras) | `Want.parameters` | Key-value map attached to a Want |
| `PackageManager` | `bundleManager` | Queries installed bundles, abilities and permissions |
| `ActivityManager` | `abilityManager` | Starts, stops and queries running abilities |
| `AndroidManifest.xml` | `module.json5` + `app.json5` | App and module declarations in JSON5 format |
| `build.gradle` | `build-profile.json5` + `hvigorfile.ts` | Build configuration via hvigor (Huawei's Gradle equivalent) |
| `APK` | `HAP` (HarmonyOS Ability Package) | Installable module package |
| `AAB` (App Bundle) | `.app` pack | Multi-HAP distribution bundle |
| `adb` | `hdc` (HarmonyOS Device Connector) | CLI bridge tool for device interaction |
| `pm list packages` | `bm dump -a` | List installed packages/bundles |
| `am start` | `aa start` | Launch a component from the CLI |
| `am broadcast` | `cem publish` | Send a common event (broadcast) from the CLI |
| `logcat` | `hilog` | On-device logging system |
| `Gradle` / `Maven` | `ohpm` (OpenHarmony Package Manager) | Dependency management |
| `ViewModel` + `LiveData` | `@State` / `@Observed` / `@Link` | Reactive state management in ArkUI |
| `Room` / `SQLite` | `relationalStore` | Structured local data persistence |
| `SharedPreferences` | `preferences` | Lightweight key-value storage |
| `Notification` | `notificationManager` | System notification delivery |
| `Permission` | `ohos.permission.*` | Different namespace; similar grant model |

---

# Architecture

## Multi-Platform Design

Harm0niz3r uses a **Platform Abstraction Layer (PAL)** that decouples the Python client from any
specific device bridge tool. Adding support for a new mobile platform requires only a new adapter
under `platforms/` — the core console, command registry and communication layer stay untouched.

```
                  ┌──────────────────────────────────────────┐
                  │           Python CLI Client               │
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

| Platform   | Bridge tool | Agent        | UI colours   | Status          |
|------------|-------------|--------------|--------------|-----------------|
| HarmonyOS  | `hdc`       | ArkTS app    | Red / amber  | ✅ Full support  |
| Android    | `adb`       | Kotlin app   | Green        | ✅ Full support  |
| iOS        | `iproxy`    | Swift binary | Cyan (TBD)   | 📋 Phase 3       |

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
│       │   ├── MainActivity.kt        # Toggle UI (Start / Stop Agent) — green theme
│       │   ├── Harm0nizerService.kt   # Foreground service managing TcpServer
│       │   ├── TcpServer.kt           # TCP socket server + MARCO-POLO handshake
│       │   └── CommandHandler.kt      # Command dispatcher (PackageManager / ContentResolver)
│       └── res/
│           ├── layout/activity_main.xml   # Dark background + Material Green (#4CAF50) accents
│           ├── values/strings.xml
│           ├── values/themes.xml          # AppTheme — colorPrimary/Accent = #4CAF50
│           └── drawable/ic_launcher.xml   # "H" glyph in Material Green
├── build.gradle
└── settings.gradle
```

**Key implementation notes:**

- Runs as a `START_STICKY` foreground service to survive background restrictions.
- Binds only to `127.0.0.1:51337` (loopback) — traffic never leaves the device.
- MARCO-POLO handshake extended: Android agent replies `POLO:android:2.0` so the client can detect the platform version.
- `CommandHandler` dispatches the same command set as the HarmonyOS agent: `apps_list`, `app_surface`, `app_info`, `apps_visible_abilities`, `app_ability`, `shell_exec`, `app_provider`.
- Requires `QUERY_ALL_PACKAGES` permission (declared in `AndroidManifest.xml`).
- UI palette: dark background `#1A1A2E` with Material Green `#4CAF50` accents, replacing the red HarmonyOS palette.

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
└── Harm0nyz3r_client/             # Python client / CLI
    ├── Harm0nyz3r.py              # Entry point and console loop
    ├── config.py                  # Global config, colour themes, ASCII banners
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

---

# Development

## Server / Client

The Python client is written in Python 3.10+ and provides direct interaction with the device via
a configurable bridge tool. It offers a CLI but requires the target device to be connected to the PC.

## Agent (On-device App)

A native application must be installed on the target device to enable most operations. Both the
HarmonyOS (ArkTS) and Android (Kotlin) agents are fully functional. The iOS agent is planned for Phase 3.

## Connection and Communication

When `connect` is run from the CLI, a TCP socket is opened (default port `51337`). If successful,
the *MARCO-POLO* handshake is performed:

1. Client sends `MARCO \n\n` to the agent.
2. If the agent responds with `POLO` (HarmonyOS) or `POLO:android:2.0` (Android), the session is established.

```ts
// Handshake — HarmonyOS agent (ArkTS)
if (txt === 'MARCO') {
    await cli.send({ data: 'POLO' });
    this.status = `Console connected on ${this.port}`;
    hilog.info(0x0000, 'AppLog', 'Responded with POLO for MARCO handshake.');
    return;
}
```

```kotlin
// Handshake — Android agent (TcpServer.kt)
if (message == "MARCO") {
    sendMessage(writer, "POLO:android:2.0")
}
```

Once connected, a background thread continuously reads from the socket so either side can
initiate communication.

### Client → Agent

The client requests operations by sending `COMMAND_REQUEST:<command>` messages. The agent
processes these and replies with structured data.

### Agent → Client

The agent sends data with ` \n\n` as a framing trailer. The client's receive loop waits for
this trailer before interpreting the complete message, handling TCP fragmentation transparently.

---

## Adding New Commands

Commands are modular classes under `commands/` registered through a central registry.

### 1. Create a command module

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
        return False

    def help(self) -> str:
        return (
            "example_feature [args]\n"
            "  A new example feature in the Harm0nyz3r console.\n"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        console._print_message("INFO", "Executing example_feature...")
        console._print_message("SUCCESS", "Done.")

def register(registry_func):
    registry_func(ExampleFeatureCommand())
```

### 2. Register it in `Harm0nyz3r.py`

```python
from commands import ..., example_feature

# Inside _register_builtin_commands():
example_feature.register(register_command)
```

### 3. (Optional) Add an agent-side handler

```python
console.send_data_to_app("COMMAND_REQUEST:new_feature some arguments")
```

---

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
        ...

    def execute_bridge_command(self, args):
        ...

    def device_shell_args(self, device_id):
        return ["--device", device_id, "shell"]

    def pull_file_args(self, device_id, remote, local):
        return ["--device", device_id, "pull", remote, local]

    def get_log_shell_command(self, remote_path):
        return f"mylog > {remote_path} 2>&1 & echo $!"
```

```python
# platforms/__init__.py
from .my_platform import MyPlatform

_REGISTRY = {
    ...
    "myplatform": MyPlatform,
}
```

It will be automatically available as `python3 Harm0nyz3r.py --platform myplatform`.

---

# Authors

- Jorge Wallace Ruiz
- Pablo Cáceres Gaitán

As part of DEKRA's cybersecurity team.

## License

Harm0niz3r is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.
