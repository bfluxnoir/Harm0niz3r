# -*- coding: utf-8 -*-
# commands/android/app_memory_dump.py
"""
app_memory_dump - dump strings (or raw bytes) from the target's
writeable memory ranges using Frida.  Catches the in-RAM-only data
that doesn't survive on disk: decrypted tokens, derived keys, OAuth
authorization headers, PII the app fetched but never persisted.

Default mode: --strings (printable-string extraction)
  Each rw- range >= --min-range bytes is scanned for runs of >=
  --min-strlen printable ASCII characters.  Each run is written
  one-per-line to <out>/strings.txt with a header line giving the
  range base.  Result is typically a few hundred KB even on a
  large app -- fast to scan and grep through.

Optional mode: --raw
  Each qualifying range is written as <out>/range_<base>_<size>.bin
  exactly as it lives in memory.  Result can be hundreds of MB
  depending on heap shape; use --max-range to cap.

Python waits for the {kind:'memory_dump', ready:true} sentinel or
the --seconds timeout, then detaches.
"""

import json
import os
import re
import time
from typing import List, Optional

from commands.base import Command, CommandSource
from commands.android._frida_session import attach_or_spawn, load_and_wait


# The script reads _args.* (frida_run-style) so we can reuse the same
# prelude shape we shipped in E batch 1.  Defaults are picked so the
# common case (--strings only) runs without any --arg fiddling.
_MEM_DUMP_SCRIPT = r"""
(function () {
  var A = (typeof _args === 'object' && _args !== null) ? _args : {};
  var mode      = A.mode      || 'strings';                    // 'strings' or 'raw'
  var minStrLen = parseInt(A.minStrLen || '6', 10);
  var minRange  = parseInt(A.minRange  || '4096', 10);
  var maxRange  = parseInt(A.maxRange  || '52428800', 10);     // 50 MB ceiling
  var protection = A.protection || 'rw-';

  function extractPrintable(bytes, minRun) {
    var arr = new Uint8Array(bytes);
    var out = [];
    var current = '';
    for (var i = 0; i < arr.length; i++) {
      var b = arr[i];
      if (b >= 0x20 && b <= 0x7e) {
        current += String.fromCharCode(b);
      } else {
        if (current.length >= minRun) out.push(current);
        current = '';
      }
    }
    if (current.length >= minRun) out.push(current);
    return out;
  }

  Java.perform(function () {
    var ranges;
    try {
      ranges = Process.enumerateRanges({protection: protection, coalesce: false});
    } catch (e) {
      send({kind: 'memory_dump', error: 'enumerateRanges failed: ' + e});
      return;
    }

    var scanned = 0;
    var dumped = 0;
    var stringsTotal = 0;
    var errors = 0;

    for (var i = 0; i < ranges.length; i++) {
      var r = ranges[i];
      if (r.size < minRange) continue;
      if (r.size > maxRange) {
        send({kind: 'mem_skip', base: '' + r.base, size: r.size, reason: 'too_large'});
        continue;
      }
      scanned++;

      try {
        var bytes = Memory.readByteArray(r.base, r.size);
        if (mode === 'raw') {
          send({kind: 'mem_raw', base: '' + r.base, size: r.size}, bytes);
          dumped++;
        } else {
          var strs = extractPrintable(bytes, minStrLen);
          if (strs.length) {
            send({kind: 'mem_strings', base: '' + r.base, size: r.size,
                  strings: strs});
            stringsTotal += strs.length;
            dumped++;
          }
        }
      } catch (e) {
        errors++;
        send({kind: 'mem_range_error', base: '' + r.base, error: '' + e});
      }
    }

    send({
      kind:           'memory_dump',
      mode:           mode,
      scanned:        scanned,
      dumped:         dumped,
      stringsTotal:   stringsTotal,
      errors:         errors,
      ready:          true
    });
  });
})();
"""


class AndroidAppMemoryDumpCommand(Command):
    @property
    def name(self) -> str:
        return "app_memory_dump"

    def help(self) -> str:
        return (
            "app_memory_dump <package> [--out DIR] [--spawn] [--seconds N]\n"
            "                  [--strings | --raw] [--min-strlen N]\n"
            "                  [--min-range BYTES] [--max-range BYTES]\n"
            "                  [--filter REGEX]\n"
            "  Dump strings (default) or raw bytes from <package>'s rw- memory\n"
            "  ranges via Frida.  Catches in-RAM-only data: decrypted tokens,\n"
            "  derived keys, OAuth Authorization headers, PII the app fetched\n"
            "  but never persisted.\n"
            "  --strings        Extract printable ASCII runs (default; small\n"
            "                   output, fast to grep through).\n"
            "  --raw            Write every qualifying range as a .bin file\n"
            "                   (can be hundreds of MB).\n"
            "  --min-strlen N   Minimum printable run length for --strings\n"
            "                   (default 6).\n"
            "  --min-range B    Skip ranges smaller than B bytes (default 4096).\n"
            "  --max-range B    Skip ranges larger than B bytes (default 50MB).\n"
            "  --filter REGEX   Only keep strings matching REGEX (Python regex).\n"
            "  --out DIR        Output dir (default ./mem_dumps/<package>/).\n"
            "  --spawn / --seconds N  same as the other Frida commands.\n\n"
            "Examples:\n"
            "  app_memory_dump com.example.target\n"
            "  app_memory_dump com.example.target --filter 'Bearer [A-Za-z0-9_.-]+'\n"
            "  app_memory_dump com.example.target --raw --max-range 4194304"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "app_memory_dump is CLI-only.")
            return

        spawn = False
        seconds = 30
        mode = "strings"
        min_strlen = 6
        min_range = 4096
        max_range = 50 * 1024 * 1024
        out_dir: Optional[str] = None
        filter_regex: Optional[str] = None
        positional: List[str] = []

        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--spawn":
                spawn = True; i += 1
            elif tok == "--strings":
                mode = "strings"; i += 1
            elif tok == "--raw":
                mode = "raw"; i += 1
            elif tok == "--seconds" and i + 1 < len(args):
                try: seconds = max(1, int(args[i + 1]))
                except ValueError: pass
                i += 2
            elif tok == "--min-strlen" and i + 1 < len(args):
                try: min_strlen = max(1, int(args[i + 1]))
                except ValueError: pass
                i += 2
            elif tok == "--min-range" and i + 1 < len(args):
                try: min_range = max(1, int(args[i + 1]))
                except ValueError: pass
                i += 2
            elif tok == "--max-range" and i + 1 < len(args):
                try: max_range = max(min_range, int(args[i + 1]))
                except ValueError: pass
                i += 2
            elif tok == "--out" and i + 1 < len(args):
                out_dir = args[i + 1]; i += 2
            elif tok == "--filter" and i + 1 < len(args):
                filter_regex = args[i + 1]; i += 2
            else:
                positional.append(tok); i += 1

        if len(positional) != 1:
            console._print_message(
                "INFO",
                "Usage: app_memory_dump <package> [--out DIR] [--spawn] "
                "[--seconds N] [--strings | --raw] [--min-strlen N] "
                "[--min-range B] [--max-range B] [--filter REGEX]"
            )
            return
        package = positional[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        try:
            compiled_filter = re.compile(filter_regex) if filter_regex else None
        except re.error as e:
            console._print_message("ERROR", f"Bad --filter regex: {e}")
            return

        if out_dir is None:
            out_dir = os.path.join("mem_dumps", package)
        os.makedirs(out_dir, exist_ok=True)

        # Build the script with the --arg prelude already inlined.
        prelude_pairs = [
            ("mode",       mode),
            ("minStrLen",  str(min_strlen)),
            ("minRange",   str(min_range)),
            ("maxRange",   str(max_range)),
        ]
        prelude_kv = ",\n".join(f"  {k}: {json.dumps(v)}" for k, v in prelude_pairs)
        script_source = (
            "const _args = {\n" + prelude_kv + "\n};\n\n" + _MEM_DUMP_SCRIPT
        )

        frida_mod, device, session, pid = attach_or_spawn(console, package, spawn)
        if session is None:
            return

        state = {
            "ready":       False,
            "ranges":      0,
            "strings":     0,
            "errors":      0,
            "raw_bytes":   0,
        }
        strings_path = os.path.join(out_dir, "strings.txt")
        strings_file = open(strings_path, "w", encoding="utf-8") if mode == "strings" else None

        def _on_message(msg, data):
            try:
                if msg.get("type") != "send":
                    return
                payload = msg.get("payload")
                if not isinstance(payload, dict):
                    return
                kind = payload.get("kind")
                if kind == "mem_strings" and strings_file is not None:
                    base = payload.get("base", "?")
                    size = payload.get("size", 0)
                    strs = payload.get("strings") or []
                    if compiled_filter:
                        strs = [s for s in strs if compiled_filter.search(s)]
                    if strs:
                        strings_file.write(
                            f"# range {base} ({size} bytes)  ({len(strs)} strings)\n"
                        )
                        for s in strs:
                            strings_file.write(s + "\n")
                        strings_file.flush()
                        state["strings"] += len(strs)
                    state["ranges"] += 1
                elif kind == "mem_raw" and data:
                    base = payload.get("base", "0x0").replace("0x", "")
                    size = payload.get("size", len(data))
                    fname = f"range_{base}_{size}.bin"
                    out_path = os.path.join(out_dir, fname)
                    with open(out_path, "wb") as f:
                        f.write(data)
                    state["raw_bytes"] += len(data)
                    state["ranges"] += 1
                elif kind == "memory_dump":
                    state["ready"] = True
                elif kind == "mem_range_error":
                    state["errors"] += 1
            except Exception as e:
                console._print_message("WARNING", f"on_message: {e}")

        console._print_message(
            "INFO",
            f"Dumping {package} memory in {mode!r} mode (max {seconds}s) ..."
        )

        try:
            fired = load_and_wait(
                console, session, device, pid,
                script_source, _on_message,
                sentinel_check=lambda: state["ready"],
                seconds=seconds,
            )
        finally:
            if strings_file is not None:
                strings_file.close()

        summary = (
            f"app_memory_dump done.  Ranges processed: {state['ranges']}, "
            f"strings written: {state['strings']}, "
            f"raw bytes: {state['raw_bytes']}, "
            f"errors: {state['errors']}.  Output: {out_dir}/"
        )
        console._print_message("SUCCESS" if fired else "WARNING", summary)


def register(registry_func):
    registry_func(AndroidAppMemoryDumpCommand())
