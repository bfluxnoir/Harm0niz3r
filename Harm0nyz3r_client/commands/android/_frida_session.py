# -*- coding: utf-8 -*-
# commands/android/_frida_session.py
"""
Tiny shared helper for the Frida-orchestrated commands in this package
(app_dex_dump, app_memory_dump, ...).  Wraps the get-device / spawn-or-
attach / load-script / wait-for-ready / detach lifecycle so each
caller can focus on its own message handler and post-processing.
"""

import time
from typing import Callable, Optional, Tuple


def attach_or_spawn(console, package: str, spawn: bool):
    """
    Returns (frida_module, device, session, pid_or_None).  Returns
    (None, None, None, None) and prints an actionable ERROR if any
    step fails -- the caller should check and bail out.
    """
    try:
        import frida
    except ImportError:
        console._print_message(
            "ERROR",
            "The 'frida' Python module is not installed on the host.\n"
            "  pip install frida-tools\n"
            "  Then start frida-server on the device (push the matching\n"
            "  frida-server-<version>-android-<abi> into /data/local/tmp/\n"
            "  and run it as root)."
        )
        return None, None, None, None

    try:
        device = frida.get_usb_device(timeout=5)
    except Exception as e:
        console._print_message(
            "ERROR",
            f"Could not reach a USB device via frida: {e}\n"
            "  - Is 'adb devices' showing your device?\n"
            "  - Is frida-server running on the device (as root)?"
        )
        return None, None, None, None

    console._print_message(
        "INFO",
        f"Frida device: {getattr(device, 'id', '?')} "
        f"({getattr(device, 'name', '?')})"
    )

    pid: Optional[int] = None
    try:
        if spawn:
            pid = device.spawn([package])
            session = device.attach(pid)
            console._print_message("INFO", f"Spawned {package} (PID {pid})")
        else:
            session = device.attach(package)
            console._print_message("INFO", f"Attached to {package}")
    except Exception as e:
        text = str(e)
        if "ProcessNotFound" in type(e).__name__ or "unable to find process" in text:
            console._print_message(
                "ERROR",
                f"{package} is not running.  Add '--spawn' to launch it, or "
                "start it manually first."
            )
            return None, None, None, None
        if "ServerNotRunning" in type(e).__name__ or "frida-server" in text.lower():
            console._print_message(
                "ERROR",
                "frida-server is not running on the device.\n"
                "  - Push the matching frida-server binary into /data/local/tmp/\n"
                "  - Start it as root, e.g.\n"
                "      adb shell su -c /data/local/tmp/frida-server &"
            )
            return None, None, None, None
        console._print_message("ERROR", f"Frida attach failed: {e}")
        return None, None, None, None

    return frida, device, session, pid


def load_and_wait(
    console,
    session,
    device,
    pid: Optional[int],
    script_source: str,
    on_message: Callable,
    sentinel_check: Callable,
    seconds: int,
) -> bool:
    """
    Load script_source into the given session, register on_message as the
    Frida message callback, resume the spawned process if pid is set, then
    poll sentinel_check() every 0.2s until it returns True or the
    'seconds' timeout elapses.  Detaches cleanly at the end.  Returns
    True if sentinel_check fired before the timeout, False otherwise.
    """
    try:
        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()
    except Exception as e:
        console._print_message("ERROR", f"Failed to load script: {e}")
        try:
            session.detach()
        except Exception:
            pass
        return False

    if pid is not None:
        try:
            device.resume(pid)
            console._print_message("INFO", f"Resumed PID {pid}")
        except Exception as e:
            console._print_message("WARNING", f"resume() failed: {e}")

    deadline = time.time() + max(1, seconds)
    sentinel_fired = False
    try:
        while time.time() < deadline:
            if sentinel_check():
                sentinel_fired = True
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        console._print_message("INFO", "Capture interrupted by Ctrl-C.")
    finally:
        try:
            session.detach()
        except Exception:
            pass

    return sentinel_fired
