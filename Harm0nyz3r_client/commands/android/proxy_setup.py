# -*- coding: utf-8 -*-
# commands/android/proxy_setup.py
"""
proxy_setup - flip an Android device into 'intercept me with Burp /
mitmproxy' mode without having to remember the magic adb commands.

Three independent jobs the command can do in a single invocation:

  1. Read or set the device's global HTTP proxy via
     'settings put global http_proxy <ip:port>'.
  2. Clear the proxy back to ':0' (Android's "no proxy" sentinel).
  3. Push a PEM-encoded CA certificate into /system/etc/security/cacerts/
     under its OpenSSL subject_hash_old name (e.g. '9a5ba575.0') so all
     apps trust it without an NSC override.  Requires root and a /system
     that can be remounted r/w.  On AVB-locked devices we surface a
     hint pointing at Magisk's MagiskTrustUserCerts module.

Examples
--------
  proxy_setup --status
  proxy_setup --proxy 192.168.1.10:8080
  proxy_setup --ca burp.pem --system
  proxy_setup --clear
"""

import os
import re
import shutil
import subprocess
from typing import List, Optional, Tuple

from commands.base import Command, CommandSource


_PROXY_RE = re.compile(r"^[A-Za-z0-9.\-]+:\d{1,5}$")
_SYSTEM_CA_DIR = "/system/etc/security/cacerts"


class AndroidProxySetupCommand(Command):
    @property
    def name(self) -> str:
        return "proxy_setup"

    def help(self) -> str:
        return (
            "proxy_setup [--status] [--proxy IP:PORT | --clear]\n"
            "            [--ca cert.pem [--system] [--hash-name <hex>]]\n"
            "  Manage the device's global HTTP proxy and (optionally) install\n"
            "  a CA certificate so HTTPS traffic decrypts cleanly through\n"
            "  Burp / mitmproxy.\n"
            "  With no flags, prints current proxy + CA setup hints.\n\n"
            "Proxy management:\n"
            "  --proxy IP:PORT  Set global HTTP proxy.\n"
            "  --clear          Clear the proxy (back to Android's ':0').\n"
            "  --status         Print current proxy state.  Default.\n\n"
            "CA installation (system store):\n"
            "  --ca cert.pem    PEM-encoded CA certificate path.\n"
            "  --system         Push to /system store (root required).\n"
            "  --hash-name HEX  Override the computed subject_hash_old name\n"
            "                   (useful when openssl isn't in PATH).\n\n"
            "Examples:\n"
            "  proxy_setup --status\n"
            "  proxy_setup --proxy 192.168.1.10:8080\n"
            "  proxy_setup --ca burp.pem --system\n"
            "  proxy_setup --clear"
        )

    # ------------------------------------------------------------------
    # Arg parsing
    # ------------------------------------------------------------------

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        proxy: Optional[str] = None
        clear = False
        status = False
        ca_path: Optional[str] = None
        to_system = False
        hash_override: Optional[str] = None
        unknown: List[str] = []

        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--status":
                status = True; i += 1
            elif tok == "--clear":
                clear = True; i += 1
            elif tok == "--system":
                to_system = True; i += 1
            elif tok == "--proxy" and i + 1 < len(args):
                proxy = args[i + 1]; i += 2
            elif tok == "--ca" and i + 1 < len(args):
                ca_path = args[i + 1]; i += 2
            elif tok == "--hash-name" and i + 1 < len(args):
                hash_override = args[i + 1]; i += 2
            else:
                unknown.append(tok); i += 1

        if unknown:
            console._print_message(
                "WARNING",
                f"Ignoring unknown argument(s): {' '.join(unknown)}"
            )

        # Default to --status when no action flag is supplied.
        if not (proxy or clear or status or ca_path):
            status = True

        if status:
            self._print_status(console)
        if clear and proxy:
            console._print_message(
                "WARNING",
                "Both --clear and --proxy were given; --proxy wins."
            )
            clear = False
        if clear:
            self._clear_proxy(console)
        if proxy:
            self._set_proxy(console, proxy)
        if ca_path:
            self._install_ca(console, ca_path, to_system, hash_override)

    # ------------------------------------------------------------------
    # Proxy management
    # ------------------------------------------------------------------

    def _print_status(self, console) -> None:
        out, _, _ = console._run_shell(["settings", "get", "global", "http_proxy"])
        current = (out or "").strip()
        if not current or current.lower() in ("null", ":0"):
            console._print_message("INFO", "Current http_proxy: (not set)")
        else:
            console._print_message("INFO", f"Current http_proxy: {current}")

    def _set_proxy(self, console, proxy: str) -> None:
        if not _PROXY_RE.match(proxy):
            console._print_message(
                "ERROR",
                f"Invalid proxy format '{proxy}'.  Expected IP:PORT or HOST:PORT."
            )
            return
        out, err, ret = console._run_shell(
            ["settings", "put", "global", "http_proxy", proxy]
        )
        if ret != 0:
            console._print_message("ERROR", f"settings put failed: {err or 'unknown'}")
            return
        console._print_message("SUCCESS", f"http_proxy set to {proxy}")
        # Verify
        self._print_status(console)

    def _clear_proxy(self, console) -> None:
        out, err, ret = console._run_shell(
            ["settings", "put", "global", "http_proxy", ":0"]
        )
        if ret != 0:
            console._print_message("ERROR", f"settings put failed: {err or 'unknown'}")
            return
        console._print_message("SUCCESS", "http_proxy cleared (reset to :0)")
        self._print_status(console)

    # ------------------------------------------------------------------
    # CA installation
    # ------------------------------------------------------------------

    def _has_root(self, console) -> bool:
        out, _, ret = console._run_shell(["su", "0", "id"])
        return ret == 0 and "uid=0" in (out or "")

    def _compute_subject_hash(self, ca_path: str) -> Optional[str]:
        """
        Compute OpenSSL's subject_hash_old (the legacy 8-char hex name
        Android's CA store uses).  Shells out to 'openssl' because doing
        it by hand requires ASN.1 parsing.
        """
        # Resolve openssl through the F bucket central resolver so a user
        # can pin the path in tools.local.json instead of relying on PATH.
        from tools import resolve_tool
        openssl_bin = resolve_tool("openssl")
        if not openssl_bin:
            return None
        try:
            proc = subprocess.run(
                [openssl_bin, "x509", "-inform", "PEM", "-subject_hash_old",
                 "-in", ca_path, "-noout"],
                capture_output=True, text=True, check=False,
            )
        except Exception:
            return None
        if proc.returncode != 0:
            return None
        head = (proc.stdout or "").splitlines()[0].strip()
        # openssl prints multiple hashes on one line sometimes; first token wins
        return head.split()[0] if head else None

    def _install_ca(
        self,
        console,
        ca_path: str,
        to_system: bool,
        hash_override: Optional[str],
    ) -> None:
        if not os.path.isfile(ca_path):
            console._print_message("ERROR", f"CA file not found: {ca_path}")
            return
        if not to_system:
            console._print_message(
                "INFO",
                "CA install requested without --system.  V1 only supports the\n"
                "system store path; for a user-store install, push the PEM to\n"
                "/sdcard/Download/ and open it from Settings -> Security ->\n"
                "Install from storage."
            )
            return
        if not self._has_root(console):
            console._print_message(
                "ERROR",
                "--system requires root.  Either rerun on a rooted device or\n"
                "install Magisk's 'MagiskTrustUserCerts' module which folds\n"
                "the user store into the system store automatically."
            )
            return

        # 1) Compute / accept the hash name.
        hash_name = hash_override or self._compute_subject_hash(ca_path)
        if not hash_name:
            console._print_message(
                "ERROR",
                "Could not compute subject_hash_old.  Install openssl and rerun, or\n"
                "supply --hash-name <hex> with the value 'openssl x509 -inform PEM\n"
                "-subject_hash_old -in <ca.pem> -noout' would print."
            )
            return
        if not re.match(r"^[0-9a-fA-F]{8}$", hash_name):
            console._print_message(
                "ERROR",
                f"Computed/supplied hash '{hash_name}' isn't 8 hex chars.  Refusing."
            )
            return

        target = f"{_SYSTEM_CA_DIR}/{hash_name}.0"
        tmp_remote = f"/data/local/tmp/{hash_name}.0"

        # 2) Remount /system rw.
        console._print_message("INFO", "Attempting 'mount -o rw,remount /system' ...")
        _, mr_err, mr_ret = console._run_shell(
            ["su", "0", "mount", "-o", "rw,remount", "/system"]
        )
        if mr_ret != 0:
            console._print_message(
                "ERROR",
                f"Could not remount /system rw: {mr_err or '(no stderr)'}\n"
                "  Android 10+ devices with verified boot will refuse this.\n"
                "  Install Magisk + the 'MagiskTrustUserCerts' module and rerun\n"
                "  this command without --system to push to the user store."
            )
            return

        # 3) Push the cert to a writable staging path with normal adb push.
        push_cmd = ["adb", "-s", console.device_id, "push", ca_path, tmp_remote]
        try:
            proc = subprocess.run(push_cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            console._print_message("ERROR", "'adb' not found in PATH.")
            return
        if proc.returncode != 0:
            console._print_message(
                "ERROR",
                f"adb push failed: {(proc.stderr or proc.stdout).strip()}"
            )
            return

        # 4) Move into the CA dir with su, then chmod 644.
        for cmd_label, cmd in (
            ("mkdir", ["su", "0", "mkdir", "-p", _SYSTEM_CA_DIR]),
            ("cp",    ["su", "0", "cp", tmp_remote, target]),
            ("chmod", ["su", "0", "chmod", "644", target]),
            ("rm",    ["su", "0", "rm", "-f", tmp_remote]),
        ):
            _, e, r = console._run_shell(cmd)
            if r != 0:
                console._print_message(
                    "WARNING",
                    f"step '{cmd_label}' returned {r}: {e or '(no stderr)'}"
                )

        # 5) Remount ro for hygiene (best-effort).
        console._run_shell(["su", "0", "mount", "-o", "ro,remount", "/system"])

        console._print_message(
            "SUCCESS",
            f"Installed {os.path.basename(ca_path)} as {target}."
        )
        console._print_message(
            "INFO",
            "A reboot may be required before all running apps pick up the new "
            "system CA."
        )


def register(registry_func):
    registry_func(AndroidProxySetupCommand())
