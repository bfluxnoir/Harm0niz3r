# commands/android/app_permissions.py
import re
from typing import List

from commands.base import Command, CommandSource
from parsers.android_parser import parse_pm_dump

_DANGEROUS_PERMS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.MANAGE_ACCOUNTS",
    "android.permission.AUTHENTICATE_ACCOUNTS",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.PROCESS_OUTGOING_CALLS",
}


class AndroidAppPermissionsCommand(Command):
    """
    Android-specific: show requested, granted, and dangerous permissions for a package.
    """

    @property
    def name(self) -> str:
        return "app_permissions"

    def help(self) -> str:
        return (
            "app_permissions <package> [--dangerous]\n"
            "  List all permissions for a package from 'pm dump'.\n"
            "  --dangerous  Only show dangerous permissions.\n\n"
            "Examples:\n"
            "  app_permissions com.example.app\n"
            "  app_permissions com.example.app --dangerous"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.hdc_device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        dangerous_only = "--dangerous" in args
        args = [a for a in args if a != "--dangerous"]

        if len(args) != 1:
            console._print_message("INFO", "Usage: app_permissions <package> [--dangerous]")
            return

        package = args[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: '{package}'")
            return

        stdout, stderr, ret = console._get_hdc_shell_output(["pm", "dump", package])
        if ret != 0 or not stdout:
            console._print_message("ERROR", f"pm dump failed: {stderr or 'no output'}")
            return

        parsed = parse_pm_dump(stdout, package)
        requested = parsed.get("requiredAppPermissions", [])
        granted = parsed.get("grantedPermissions", [])

        if dangerous_only:
            requested = [p for p in requested if p in _DANGEROUS_PERMS]
            granted = [p for p in granted if p in _DANGEROUS_PERMS]

        print(f"\n--- Permissions: {package} ---")
        print(f"  Debug Mode : {parsed.get('debugMode')}")
        print(f"  System App : {parsed.get('systemApp')}")

        print(f"\n  Requested ({len(requested)}):")
        for p in sorted(requested):
            tag = " ⚠ DANGEROUS" if p in _DANGEROUS_PERMS else ""
            print(f"    {p}{tag}")

        print(f"\n  Granted ({len(granted)}):")
        for p in sorted(granted):
            tag = " ⚠ DANGEROUS" if p in _DANGEROUS_PERMS else ""
            print(f"    {p}{tag}")

        not_granted = [p for p in requested if p not in granted]
        if not_granted:
            print(f"\n  NOT Granted ({len(not_granted)}):")
            for p in sorted(not_granted):
                print(f"    {p}")

        print("------------------------------------\n")


def register(registry_func):
    registry_func(AndroidAppPermissionsCommand())
