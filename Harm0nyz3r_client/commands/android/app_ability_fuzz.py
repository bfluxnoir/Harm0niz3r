# commands/android/app_ability_fuzz.py
import os
import re
import random
import string
import time
from typing import List, Optional

from commands.base import Command, CommandSource


def _fuzz_string(base: Optional[str] = None, max_len: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "_-"
    if not base:
        return "".join(random.choice(alphabet) for _ in range(random.randint(1, max_len)))
    s = list(base)
    op = random.choice(["insert", "delete", "replace", "swap"])
    if op == "insert" and len(s) < max_len:
        s.insert(random.randrange(len(s) + 1), random.choice(alphabet))
    elif op == "delete" and len(s) > 1:
        del s[random.randrange(len(s))]
    elif op == "replace" and s:
        s[random.randrange(len(s))] = random.choice(alphabet)
    elif op == "swap" and len(s) > 1:
        i, j = random.sample(range(len(s)), 2)
        s[i], s[j] = s[j], s[i]
    return "".join(s)


def _fuzz_int() -> int:
    return random.randint(0, 1_000_000)


def _fuzz_bool() -> str:
    return random.choice(("true", "false"))


def _infer_type(value: str) -> str:
    if value.lower() in ("true", "false"):
        return "bool"
    if re.fullmatch(r"-?\d+", value):
        return "int"
    return "string"


class AndroidAppAbilityFuzzCommand(Command):
    @property
    def name(self) -> str:
        return "app_ability_fuzz"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_ability_fuzz <package> <activity> [--count N] [--delay ms] [key=value ...] [--log]\n"
            "\n"
            "Fuzz an Activity's Intent extras via repeated 'am start' invocations.\n"
            "\n"
            "Fuzz markers in <value>:\n"
            "  ?s  → fuzzed string    ?i → fuzzed int    ?b → fuzzed bool    ? → random type\n"
            "\n"
            "Special keys: action=, data=, mime=, category= (same as app_ability_want)\n"
            "\n"
            "Examples:\n"
            "  app_ability_fuzz com.example.app .LoginActivity --count 50 username=?s password=?s\n"
            "  app_ability_fuzz com.example.app .SearchActivity query=?s page=?i"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.hdc_device_id:
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
        param_tokens: List[str] = []

        i = 2
        while i < len(args):
            if args[i] == "--count" and i + 1 < len(args):
                try:
                    count = int(args[i + 1])
                except ValueError:
                    pass
                i += 2
            elif args[i] == "--delay" and i + 1 < len(args):
                try:
                    delay_ms = int(args[i + 1])
                except ValueError:
                    pass
                i += 2
            else:
                param_tokens.append(args[i])
                i += 1

        # Parse parameter specs
        param_specs: List[dict] = []
        for token in param_tokens:
            if "=" not in token:
                continue
            key, _, raw_value = token.partition("=")
            if raw_value in ("?s", "?S"):
                mode = "string"
            elif raw_value in ("?i", "?I"):
                mode = "int"
            elif raw_value in ("?b", "?B"):
                mode = "bool"
            elif raw_value == "?":
                mode = "auto"
            else:
                mode = "fixed"
            param_specs.append({
                "key": key,
                "mode": mode,
                "fixed_value": raw_value if mode == "fixed" else None,
                "last_value": None,
            })

        # Log file
        log_file = None
        try:
            log_dir = os.path.join(os.getcwd(), "logs")
            os.makedirs(log_dir, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", f"{package}_{activity}")
            log_file = open(os.path.join(log_dir, f"app_ability_fuzz_{safe}_{ts}.log"), "w", encoding="utf-8")
            log_file.write(f"# app_ability_fuzz android | package={package} activity={activity}\n# count={count} delay={delay_ms}ms\n\n")
            console._print_message("INFO", f"Fuzzer log: {log_file.name}")
        except Exception as e:
            console._print_message("WARNING", f"Could not create log file: {e}")

        console._print_message("INFO", f"Fuzzing {component} × {count} iterations...")
        start_time = time.time()

        try:
            for iteration in range(1, count + 1):
                cmd = ["am", "start", "-n", component]

                for spec in param_specs:
                    key = spec["key"]
                    mode = spec["mode"]

                    if mode == "fixed":
                        value = spec["fixed_value"]
                        vtype = _infer_type(value)
                    elif mode == "string":
                        value = _fuzz_string(spec.get("last_value"))
                        vtype = "string"
                        spec["last_value"] = value
                    elif mode == "int":
                        value = str(_fuzz_int())
                        vtype = "int"
                    elif mode == "bool":
                        value = _fuzz_bool()
                        vtype = "bool"
                    else:  # auto
                        vtype = random.choice(("string", "int", "bool"))
                        if vtype == "string":
                            value = _fuzz_string()
                        elif vtype == "int":
                            value = str(_fuzz_int())
                        else:
                            value = _fuzz_bool()
                        spec["last_value"] = value

                    # Map to am start flags
                    if key == "action":
                        cmd += ["-a", value]
                    elif key == "data":
                        cmd += ["-d", value]
                    elif key == "mime":
                        cmd += ["-t", value]
                    elif key == "category":
                        cmd += ["-c", value]
                    else:
                        if vtype == "bool":
                            cmd += ["--ez", key, value]
                        elif vtype == "int":
                            cmd += ["--ei", key, value]
                        else:
                            cmd += ["--es", key, value]

                console._print_message("INFO", f"[{iteration}/{count}] am start...")
                if console.verbose:
                    console._print_message("DEBUG", " ".join(cmd))

                stdout, stderr, ret = console._get_hdc_shell_output(cmd)
                elapsed = time.time() - start_time

                if log_file:
                    ts_now = time.strftime("%Y-%m-%d %H:%M:%S")
                    log_file.write(f"{ts_now} [+{elapsed:.3f}s] iter={iteration}/{count} ret={ret} cmd={' '.join(cmd)}\n")
                    log_file.flush()

                if ret != 0:
                    console._print_message("ERROR", f"[{iteration}/{count}] Failed (ret={ret})")
                    if stdout:
                        print(f"STDOUT: {stdout}")
                    if stderr:
                        print(f"STDERR: {stderr}")

                if iteration < count and delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
        finally:
            if log_file:
                log_file.close()


def register(registry_func):
    registry_func(AndroidAppAbilityFuzzCommand())
