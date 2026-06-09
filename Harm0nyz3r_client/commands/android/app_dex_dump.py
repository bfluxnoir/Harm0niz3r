# -*- coding: utf-8 -*-
# commands/android/app_dex_dump.py
"""
app_dex_dump - dump every loaded DEX from the target's memory using
Frida.  Catches the cases where a runtime unpacker (Bangcle, Tencent
Legu, generic in-memory decrypt-on-class-load) hands the VM real
bytecode that never landed on disk in plaintext.

How it works
------------
A small Frida script walks Process.enumerateRanges('r--'), inspects
the first eight bytes of each readable range, and considers any
range that starts with the DEX magic ('dex\\n', followed by '035'..
'039' and a null byte) a candidate.  When the candidate's header
file_size (uint32 LE at offset 32) is plausible (between 100 bytes
and the range size), the matching bytes are sent back to the host
which writes them to disk as 'dex_<base>_<size>.dex'.

The Python side waits for either the 'dex_dump' sentinel (the script
emits {kind:'dex_dump', ready:true} after the scan finishes) or the
--seconds timeout, whichever comes first, then detaches.
"""

import os
import re
import time
from typing import List, Optional

from commands.base import Command, CommandSource
from commands.android._frida_session import attach_or_spawn, load_and_wait


_DEX_DUMP_SCRIPT = r"""
(function () {
  function looksLikeDex(magicBytes) {
    var v = new Uint8Array(magicBytes);
    if (v.length < 8) return false;
    // 'dex\n' = 0x64 0x65 0x78 0x0a
    if (v[0] !== 0x64 || v[1] !== 0x65 || v[2] !== 0x78 || v[3] !== 0x0a) return false;
    // version: '035', '036', '037', '038' or '039' (0x30 0x33 [0x35..0x39])
    if (v[4] !== 0x30) return false;
    if (v[5] !== 0x33) return false;
    if (v[6] < 0x35 || v[6] > 0x39) return false;
    if (v[7] !== 0x00) return false;
    return true;
  }
  function readUint32LE(bytes) {
    var v = new Uint8Array(bytes);
    return (v[0]) | (v[1] << 8) | (v[2] << 16) | (v[3] << 24);
  }

  Java.perform(function () {
    var ranges;
    try {
      ranges = Process.enumerateRanges({protection: 'r--', coalesce: false});
    } catch (e) {
      send({kind: 'dex_dump', error: 'enumerateRanges failed: ' + e});
      return;
    }
    var scanned = 0;
    var found = 0;
    for (var i = 0; i < ranges.length; i++) {
      var r = ranges[i];
      if (r.size < 100) continue;
      scanned++;
      try {
        var magic = Memory.readByteArray(r.base, 8);
        if (!looksLikeDex(magic)) continue;
        // File size is uint32 LE at offset 32 in the DEX header.
        var sizeBytes = Memory.readByteArray(r.base.add(32), 4);
        var size = readUint32LE(sizeBytes);
        if (size < 100 || size > r.size) continue;
        var dex = Memory.readByteArray(r.base, size);
        send({kind: 'dex', base: '' + r.base, size: size}, dex);
        found++;
      } catch (e) {
        send({kind: 'dex_range_error', base: '' + r.base, error: '' + e});
      }
    }
    send({kind: 'dex_dump', scanned: scanned, found: found, ready: true});
  });
})();
"""


class AndroidAppDexDumpCommand(Command):
    @property
    def name(self) -> str:
        return "app_dex_dump"

    def help(self) -> str:
        return (
            "app_dex_dump <package> [--out DIR] [--spawn] [--seconds N]\n"
            "  Dump every loaded DEX from <package>'s memory via Frida.\n"
            "  Useful when the app uses a runtime unpacker (Bangcle, Tencent\n"
            "  Legu, generic decrypt-on-class-load) that hands the VM real\n"
            "  bytecode the static app_decompile path never sees.\n"
            "  --out DIR     Output directory (default: ./dex_dumps/<pkg>/).\n"
            "  --spawn       Spawn the app fresh (use when the unpacker\n"
            "                runs only during the cold start).\n"
            "  --seconds N   How long to wait after the script loads for\n"
            "                the sentinel (default: 20).\n\n"
            "Requires frida-tools on the host and frida-server running on\n"
            "the device.\n\n"
            "Examples:\n"
            "  app_dex_dump com.example.target\n"
            "  app_dex_dump com.example.target --spawn --out ./dumps/\n"
            "  app_dex_dump com.example.target --seconds 60"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "app_dex_dump is CLI-only.")
            return
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        spawn = False
        seconds = 20
        out_dir: Optional[str] = None
        positional: List[str] = []

        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--spawn":
                spawn = True; i += 1
            elif tok == "--seconds" and i + 1 < len(args):
                try: seconds = max(1, int(args[i + 1]))
                except ValueError: pass
                i += 2
            elif tok == "--out" and i + 1 < len(args):
                out_dir = args[i + 1]; i += 2
            else:
                positional.append(tok); i += 1

        if len(positional) != 1:
            console._print_message(
                "INFO",
                "Usage: app_dex_dump <package> [--out DIR] [--spawn] [--seconds N]"
            )
            return
        package = positional[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        if out_dir is None:
            out_dir = os.path.join("dex_dumps", package)
        os.makedirs(out_dir, exist_ok=True)

        frida_mod, device, session, pid = attach_or_spawn(console, package, spawn)
        if session is None:
            return

        state = {
            "ready":      False,
            "dex_count":  0,
            "errors":     0,
            "scanned":    0,
        }

        def _on_message(msg, data):
            try:
                if msg.get("type") != "send":
                    return
                payload = msg.get("payload")
                if isinstance(payload, dict):
                    kind = payload.get("kind")
                    if kind == "dex" and data:
                        base = payload.get("base", "0x0").replace("0x", "")
                        size = payload.get("size", len(data))
                        fname = f"dex_{base}_{size}.dex"
                        out_path = os.path.join(out_dir, fname)
                        with open(out_path, "wb") as f:
                            f.write(data)
                        state["dex_count"] += 1
                        console._print_message(
                            "SUCCESS",
                            f"  wrote {len(data)} bytes -> {out_path}"
                        )
                    elif kind == "dex_dump":
                        state["scanned"] = payload.get("scanned", 0)
                        state["ready"] = True
                    elif kind == "dex_range_error":
                        state["errors"] += 1
            except Exception as e:
                console._print_message("WARNING", f"on_message: {e}")

        console._print_message(
            "INFO",
            f"Scanning {package} memory for DEX magic (max {seconds}s) ..."
        )
        fired = load_and_wait(
            console, session, device, pid,
            _DEX_DUMP_SCRIPT, _on_message,
            sentinel_check=lambda: state["ready"],
            seconds=seconds,
        )

        if fired:
            console._print_message(
                "SUCCESS",
                f"app_dex_dump done.  Scanned {state['scanned']} ranges, "
                f"dumped {state['dex_count']} DEX file(s), "
                f"{state['errors']} read error(s).  Output: {out_dir}/"
            )
        else:
            console._print_message(
                "WARNING",
                f"Timed out after {seconds}s before the dex_dump sentinel.  "
                f"Got {state['dex_count']} DEX file(s) so far in {out_dir}/."
            )


def register(registry_func):
    registry_func(AndroidAppDexDumpCommand())
