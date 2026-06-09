# -*- coding: utf-8 -*-
# commands/android/app_explore.py
"""
app_explore - runtime class / method introspection through Frida.

Walks Java.enumerateLoadedClasses, matches each name against a
user-supplied glob, and emits a structured entry for every match.
With --methods, also dumps the declared methods of each matching
class.  Unlike static decompile, this catches classes loaded via
DexClassLoader / InMemoryDexClassLoader or pulled out of a runtime
unpacker -- they only exist after the app has run for a moment.
"""

import json
import os
import re
from typing import List, Optional

from commands.base import Command, CommandSource
from commands.android._frida_session import attach_or_spawn, load_and_wait


_EXPLORE_SCRIPT = r"""
(function () {
  var A = (typeof _args === 'object' && _args !== null) ? _args : {};
  var classPattern = A.classPattern || '*';
  var withMethods  = ('' + (A.withMethods || 'false')) === 'true';

  function globToRe(g) {
    var esc = g.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp('^' + esc.replace(/\*/g, '.*') + '$');
  }
  var rx = globToRe(classPattern);

  Java.perform(function () {
    var count = 0;
    Java.enumerateLoadedClasses({
      onMatch: function (className) {
        if (!rx.test(className)) return;
        var info = {kind: 'class', name: className};
        if (withMethods) {
          try {
            var K = Java.use(className);
            var methods = K.class.getDeclaredMethods();
            var arr = [];
            for (var i = 0; i < methods.length; i++) {
              arr.push('' + methods[i].toString());
            }
            info.methods = arr;
          } catch (e) {
            info.method_error = '' + e;
          }
        }
        send(info);
        count++;
      },
      onComplete: function () {
        send({kind: 'app_explore', classes: count, ready: true});
      }
    });
  });
})();
"""


class AndroidAppExploreCommand(Command):
    @property
    def name(self) -> str:
        return "app_explore"

    def help(self) -> str:
        return (
            "app_explore <package> [--class PATTERN] [--methods]\n"
            "             [--out FILE] [--spawn] [--seconds N]\n"
            "  Walk the target's loaded Java classes and emit those matching\n"
            "  PATTERN (glob, default '*').  Catches classes loaded at runtime\n"
            "  via DexClassLoader / InMemoryDexClassLoader -- which the static\n"
            "  app_decompile path can't see.  With --methods, also dump every\n"
            "  declared method per class (java.lang.reflect.Method.toString\n"
            "  form: return type + signature + throws).\n"
            "  --class PATTERN   Glob filter; * matches any chars (default '*').\n"
            "  --methods         Include the methods of every matching class.\n"
            "  --out FILE        Write JSON results to FILE (default: stdout).\n"
            "  --spawn / --seconds N  same as the other Frida commands.\n\n"
            "Examples:\n"
            "  app_explore com.example.target --class 'com.example.crypto.*'\n"
            "  app_explore com.example.target --class '*Pinner*' --methods\n"
            "  app_explore com.example.target --class okhttp3.RealCall --methods --out classes.json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if source != "cli":
            console._print_message("WARNING", "app_explore is CLI-only.")
            return
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        class_pattern = "*"
        with_methods = False
        out_file: Optional[str] = None
        spawn = False
        seconds = 15
        positional: List[str] = []

        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--spawn":
                spawn = True; i += 1
            elif tok == "--methods":
                with_methods = True; i += 1
            elif tok == "--class" and i + 1 < len(args):
                class_pattern = args[i + 1]; i += 2
            elif tok == "--out" and i + 1 < len(args):
                out_file = args[i + 1]; i += 2
            elif tok == "--seconds" and i + 1 < len(args):
                try: seconds = max(1, int(args[i + 1]))
                except ValueError: pass
                i += 2
            else:
                positional.append(tok); i += 1

        if len(positional) != 1:
            console._print_message(
                "INFO",
                "Usage: app_explore <package> [--class PATTERN] [--methods] "
                "[--out FILE] [--spawn] [--seconds N]"
            )
            return
        package = positional[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        # Inline _args prelude using the E batch 1 shape so the embedded
        # script can read its config without command-line plumbing.
        prelude = (
            "const _args = {\n"
            f"  classPattern: {json.dumps(class_pattern)},\n"
            f"  withMethods:  {json.dumps('true' if with_methods else 'false')}\n"
            "};\n\n"
        )
        script_source = prelude + _EXPLORE_SCRIPT

        frida_mod, device, session, pid = attach_or_spawn(console, package, spawn)
        if session is None:
            return

        state = {"ready": False, "classes": []}

        def _on_message(msg, data):
            try:
                if msg.get("type") != "send":
                    return
                payload = msg.get("payload")
                if not isinstance(payload, dict):
                    return
                kind = payload.get("kind")
                if kind == "class":
                    state["classes"].append({
                        "name":    payload.get("name"),
                        "methods": payload.get("methods"),
                        "method_error": payload.get("method_error"),
                    })
                elif kind == "app_explore":
                    state["ready"] = True
            except Exception as e:
                console._print_message("WARNING", f"on_message: {e}")

        console._print_message(
            "INFO",
            f"Exploring {package} for classes matching {class_pattern!r} "
            f"(max {seconds}s) ..."
        )
        fired = load_and_wait(
            console, session, device, pid,
            script_source, _on_message,
            sentinel_check=lambda: state["ready"],
            seconds=seconds,
        )

        if not fired:
            console._print_message(
                "WARNING",
                f"Timed out after {seconds}s; got {len(state['classes'])} "
                "class(es) so far."
            )

        # Render
        result = {
            "package":     package,
            "pattern":     class_pattern,
            "withMethods": with_methods,
            "classes":     state["classes"],
        }
        if out_file:
            try:
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2)
                console._print_message(
                    "SUCCESS",
                    f"Wrote {len(state['classes'])} class(es) to {out_file}."
                )
            except Exception as e:
                console._print_message("ERROR", f"Could not write {out_file}: {e}")
        else:
            print(json.dumps(result, indent=2))
            console._print_message(
                "SUCCESS",
                f"app_explore: {len(state['classes'])} class(es) matched."
            )


def register(registry_func):
    registry_func(AndroidAppExploreCommand())
