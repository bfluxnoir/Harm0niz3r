# -*- coding: utf-8 -*-
# commands/android/app_backup.py
"""
app_backup - run 'adb backup' against a package and optionally extract the
resulting .ab file straight to a tar / unpacked directory.

The .ab format
--------------
  ANDROID BACKUP\n     14-byte fixed header
  <version>\n          1..5 (stdlib only supports v1-5 here)
  <compressed>\n       '0' = stored, '1' = deflate-zlib
  <encryption>\n       'none' = plaintext.  Any other value (e.g.
                       'AES-256') triggers a clear error with a
                       pointer to abe.jar; V1 does not implement
                       the PBKDF2 + AES-256-CBC dance.
  [body]               the (possibly deflated) tar stream

allowBackup gating
------------------
Apps that set 'android:allowBackup="false"' in their manifest will
produce a header-only .ab.  The tool reports that explicitly so the
operator isn't left guessing.

Why this command exists
-----------------------
The 'adb backup' route is a legitimate (if old) MASTG-STORAGE check:
when allowBackup is true and the device is unencrypted, any user with
USB-debugging access can walk away with the app's sandbox.  This
command makes that part of an engagement a single line instead of the
usual adb + abe.jar + tar dance.
"""

import os
import re
import shutil
import subprocess
import tarfile
import zlib
from typing import List, Optional

from commands.base import Command, CommandSource


_AB_MAGIC = b"ANDROID BACKUP\n"


def ab_to_tar(ab_bytes: bytes) -> bytes:
    """
    Convert the bytes of a .ab file into the raw .tar payload.

    Raises ValueError on:
      - missing 'ANDROID BACKUP' header
      - truncated header
      - unsupported encryption (anything other than 'none')
      - zlib failure when the body is marked compressed
    """
    if not ab_bytes.startswith(_AB_MAGIC):
        raise ValueError("Missing 'ANDROID BACKUP' header")

    cursor = len(_AB_MAGIC)
    headers: List[str] = []
    for _ in range(3):  # version, compressed, encryption
        nl = ab_bytes.find(b"\n", cursor)
        if nl < 0:
            raise ValueError("Truncated .ab header")
        headers.append(ab_bytes[cursor:nl].decode("ascii", errors="replace"))
        cursor = nl + 1

    version_str, compressed_str, encryption_str = headers
    try:
        version = int(version_str)
    except ValueError:
        raise ValueError(f"Bad .ab version: {version_str!r}")
    if version < 1 or version > 5:
        raise ValueError(f"Unsupported .ab version {version}")
    compressed = (compressed_str == "1")
    enc = encryption_str.strip().lower()
    if enc and enc != "none":
        raise ValueError(
            f"Encrypted backup (algorithm: {encryption_str!r}); V1 supports "
            "plaintext .ab only.  Decrypt with abe.jar "
            "(https://github.com/nelenkov/android-backup-extractor) and rerun "
            "with --tar-only or extract the resulting tar by hand."
        )

    body = ab_bytes[cursor:]
    if not compressed:
        return body
    try:
        return zlib.decompress(body)
    except zlib.error as e:
        raise ValueError(f"Could not inflate .ab body: {e}")


class AndroidAppBackupCommand(Command):
    @property
    def name(self) -> str:
        return "app_backup"

    def help(self) -> str:
        return (
            "app_backup <package> [--out FILE] [--apk] [--obb] [--shared]\n"
            "          [--extract DIR | --tar-only]\n"
            "  Run 'adb backup -f <file> [-noapk ...] <package>' and optionally\n"
            "  convert the resulting plain .ab file into a tar archive (and an\n"
            "  unpacked directory).\n\n"
            "  --out FILE     Output .ab path (default: ./backups/<package>.ab).\n"
            "  --apk          Include the APK itself (default: excluded).\n"
            "  --obb          Include OBB expansion files (default: excluded).\n"
            "  --shared       Include /sdcard shared storage (default: excluded).\n"
            "  --extract DIR  After backup, convert .ab -> .tar -> unpacked tree\n"
            "                 under DIR.\n"
            "  --tar-only     After backup, convert .ab -> .tar next to --out; do\n"
            "                 not unpack into a directory.\n\n"
            "The target app must declare android:allowBackup=\"true\" in its\n"
            "manifest.  You'll need to tap 'Back up my data' on the device's\n"
            "confirmation dialog when prompted.  Encrypted backups need abe.jar.\n\n"
            "Examples:\n"
            "  app_backup com.example.target\n"
            "  app_backup com.example.target --out /tmp/target.ab --extract /tmp/target/\n"
            "  app_backup com.example.target --apk --obb --shared --extract ./dump/"
        )

    # ------------------------------------------------------------------

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "app_backup is only available from the CLI.")
            return
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        # --- arg parsing ---
        out_file: Optional[str] = None
        with_apk = False
        with_obb = False
        with_shared = False
        extract_dir: Optional[str] = None
        tar_only = False
        positional: List[str] = []

        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--apk":
                with_apk = True; i += 1
            elif tok == "--obb":
                with_obb = True; i += 1
            elif tok == "--shared":
                with_shared = True; i += 1
            elif tok == "--tar-only":
                tar_only = True; i += 1
            elif tok == "--out" and i + 1 < len(args):
                out_file = args[i + 1]; i += 2
            elif tok == "--extract" and i + 1 < len(args):
                extract_dir = args[i + 1]; i += 2
            else:
                positional.append(tok); i += 1

        if len(positional) != 1:
            console._print_message(
                "INFO",
                "Usage: app_backup <package> [--out FILE] [--apk] [--obb] "
                "[--shared] [--extract DIR | --tar-only]"
            )
            return
        package = positional[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        # --- defaults / setup ---
        if out_file is None:
            out_dir = os.path.abspath("backups")
            os.makedirs(out_dir, exist_ok=True)
            out_file = os.path.join(out_dir, f"{package}.ab")
        else:
            out_dir = os.path.dirname(os.path.abspath(out_file)) or "."
            os.makedirs(out_dir, exist_ok=True)

        # adb backup flags.  The defaults exclude everything beyond app data
        # because that's the common pentest case; APKs, OBBs, shared storage
        # are opt-in.
        adb_args = ["adb", "-s", console.device_id, "backup", "-f", out_file]
        adb_args.append("-apk" if with_apk else "-noapk")
        adb_args.append("-obb" if with_obb else "-noobb")
        adb_args.append("-shared" if with_shared else "-noshared")
        adb_args.append(package)

        console._print_message(
            "INFO",
            "Running 'adb backup'.  Confirm the dialog on the device "
            "('Back up my data').  Leave the password empty for a plain backup."
        )
        try:
            proc = subprocess.run(adb_args, capture_output=False, check=False)
        except FileNotFoundError:
            console._print_message("ERROR", "'adb' not found in PATH.")
            return
        if proc.returncode != 0:
            console._print_message("ERROR", f"adb backup exited {proc.returncode}.")
            return
        if not os.path.isfile(out_file):
            console._print_message("ERROR", f"adb backup produced no file at {out_file}.")
            return

        size = os.path.getsize(out_file)
        console._print_message("SUCCESS", f"Wrote .ab to {out_file} ({size} bytes).")

        # Read the header at minimum; a truly empty file means the user cancelled
        # or allowBackup=false.
        try:
            with open(out_file, "rb") as f:
                ab_bytes = f.read()
        except OSError as e:
            console._print_message("ERROR", f"Could not read back .ab file: {e}")
            return

        if size <= len(_AB_MAGIC) + 8:
            console._print_message(
                "WARNING",
                "The .ab file is suspiciously small.  Likely causes: the user "
                "cancelled the dialog, the package set allowBackup=\"false\", "
                "or 'adb backup' is no longer permitted on this device "
                "(Android 12+ defaults).  No tar conversion will be attempted."
            )
            return

        # If neither --extract nor --tar-only was requested, we're done.
        if not extract_dir and not tar_only:
            console._print_message(
                "INFO",
                "Tip: rerun with --extract <DIR> to unpack the backup, or with "
                "--tar-only to just convert to .tar next to the .ab."
            )
            return

        # Convert .ab -> .tar.
        try:
            tar_bytes = ab_to_tar(ab_bytes)
        except ValueError as e:
            console._print_message("ERROR", f"Could not parse .ab: {e}")
            return

        tar_path = out_file.rsplit(".ab", 1)[0] + ".tar"
        try:
            with open(tar_path, "wb") as f:
                f.write(tar_bytes)
        except OSError as e:
            console._print_message("ERROR", f"Could not write {tar_path}: {e}")
            return
        console._print_message(
            "SUCCESS",
            f"Wrote tar payload to {tar_path} ({len(tar_bytes)} bytes)."
        )

        if extract_dir:
            os.makedirs(extract_dir, exist_ok=True)
            try:
                with tarfile.open(tar_path, "r:") as tf:
                    # 'data' filter is safer than the default 'fully_trusted'
                    # filter -- see PEP 706 / CVE-2024-...; available since
                    # Python 3.12.  Fall back to default when the param isn't
                    # accepted by older interpreters.
                    try:
                        tf.extractall(extract_dir, filter="data")
                    except TypeError:
                        tf.extractall(extract_dir)
            except (tarfile.TarError, OSError) as e:
                console._print_message("ERROR", f"Could not extract tar: {e}")
                return
            console._print_message(
                "SUCCESS",
                f"Extracted backup tree into {extract_dir}/.  "
                f"Suggested follow-ups:\n"
                f"  app_secrets {extract_dir}\n"
                f"  app_sqlite_inspect {extract_dir}"
            )


def register(registry_func):
    registry_func(AndroidAppBackupCommand())
