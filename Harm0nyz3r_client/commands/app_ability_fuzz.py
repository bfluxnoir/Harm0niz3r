# commands/app_ability_fuzz.py
import os
import re
import random
import string
import time
from typing import List, Optional

from .base import Command, CommandSource

try:
    from typing import Literal
    FuzzMode = Literal["fixed", "string", "int", "bool", "auto"]
except ImportError:
    # Fallback for older Python versions
    FuzzMode = str  # type: ignore


def _infer_type_from_value(value: str) -> str:
    """
    Infer parameter type from a literal value.
    Returns: "bool" | "int" | "string"
    """
    # Boolean
    if value.lower() in ("true", "false"):
        return "bool"
    # Integer
    if re.fullmatch(r"\d+", value):
        return "int"
    # Default: string
    return "string"


def _fuzz_string(
    base: Optional[str] = None,
    min_len: int = 1,
    max_len: int = 32,
) -> str:
    """
    Mutational string fuzzer.

    - If base is provided, mutate around it (insert/delete/replace/swap).
    - Otherwise, generate a random string from scratch.
    """
    alphabet = string.ascii_letters + string.digits + "_-"

    # If no base, generate a completely random string
    if not base:
        length = random.randint(min_len, max_len)
        return "".join(random.choice(alphabet) for _ in range(length))

    s = list(base)

    # Choose a mutation strategy
    op = random.choice(["insert", "delete", "replace", "swap"])

    # Ensure we have something to work with
    if not s:
        length = random.randint(min_len, max_len)
        return "".join(random.choice(alphabet) for _ in range(length))

    if op == "insert" and len(s) < max_len:
        pos = random.randrange(0, len(s) + 1)
        s.insert(pos, random.choice(alphabet))

    elif op == "delete" and len(s) > min_len:
        pos = random.randrange(0, len(s))
        del s[pos]

    elif op == "replace":
        pos = random.randrange(0, len(s))
        s[pos] = random.choice(alphabet)

    elif op == "swap" and len(s) > 1:
        i = random.randrange(0, len(s))
        j = random.randrange(0, len(s))
        if i != j:
            s[i], s[j] = s[j], s[i]

    return "".join(s)


def _fuzz_int(min_val: int = 0, max_val: int = 1_000_000) -> int:
    return random.randint(min_val, max_val)


def _fuzz_bool() -> bool:
    return bool(random.getrandbits(1))


def _choose_auto_type() -> str:
    """Randomly choose a type for auto fuzzing."""
    return random.choice(["string", "int", "bool"])


class AppAbilityFuzzCommand(Command):
    @property
    def name(self) -> str:
        return "app_ability_fuzz"

    @property
    def supports_logging(self) -> bool:
        # Allow: app_ability_fuzz ... --log
        # The console wrapper will start/stop device logging for the whole fuzz session.
        return True

    def help(self) -> str:
        return (
            "app_ability_fuzz <namespace> <abilityName> "
            "[--count N] [--delay ms] [key=value ...] [--log]\n"
            "\n"
            "Start an ability repeatedly with a Want whose parameters can be fixed or fuzzed.\n"
            "\n"
            "Parameter syntax (key=value):\n"
            "  action=<value>   → Want action (-A)\n"
            "  uri=<value>      → Want URI (-U)\n"
            "  entity=<value>   → Want entity (-e)\n"
            "  mime=<value>     → MIME type (-t)\n"
            "  anyOtherKey=<value> → Want extra (type inferred: string/int/bool)\n"
            "\n"
            "Fuzz markers for <value>:\n"
            "  ?s   → fuzzed string (mutational)\n"
            "  ?i   → fuzzed integer\n"
            "  ?b   → fuzzed boolean\n"
            "  ?    → auto (random type each iteration)\n"
            "\n"
            "Examples:\n"
            "  app_ability_fuzz com.example.app MainAbility --count 50 name=?s\n"
            "  app_ability_fuzz com.example.app MainAbility --count 10 "
            "action=ohos.want.action.view id=?i premium=?b\n"
            "  app_ability_fuzz com.example.app MainAbility --count 20 "
            "--delay 200 uri=? mime=text/plain\n"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Usage:
            app_ability_fuzz <namespace> <abilityName> [--count N] [--delay ms] [key=value ...] [--log]

        - '--log' is handled outside by the console wrapper (because supports_logging = True).
        - Here we only see cleaned args (without --log).
        """
        if not console.hdc_device_id:
            console._print_message("ERROR", "No HarmonyOS device connected via hdc.")
            return

        if len(args) < 2:
            console._print_message("INFO", self.help())
            return

        namespace = args[0]
        ability_name = args[1]

        # Validate namespace & ability
        if not re.match(r"^[a-zA-Z0-9._-]+$", namespace):
            console._print_message("ERROR", f"Invalid namespace: '{namespace}'")
            return

        if not re.match(r"^[a-zA-Z0-9._/-]+$", ability_name):
            console._print_message("ERROR", f"Invalid ability name: '{ability_name}'")
            return

        # Default fuzz settings
        count = 10        # default number of iterations
        delay_ms = 0      # default delay between iterations
        param_tokens: List[str] = []

        # Parse global options (--count, --delay) + collect key=value tokens
        i = 2
        while i < len(args):
            token = args[i]
            if token == "--count" and i + 1 < len(args):
                try:
                    count = int(args[i + 1])
                except ValueError:
                    console._print_message(
                        "WARNING",
                        f"Invalid --count value: '{args[i + 1]}', using default {count}",
                    )
                i += 2
                continue
            elif token == "--delay" and i + 1 < len(args):
                try:
                    delay_ms = int(args[i + 1])
                except ValueError:
                    console._print_message(
                        "WARNING",
                        f"Invalid --delay value: '{args[i + 1]}', using default {delay_ms}",
                    )
                i += 2
                continue
            else:
                param_tokens.append(token)
                i += 1

        # Parse param_specs: key, mode, fixed_value, fixed_type, last_value
        param_specs: List[dict] = []
        for p in param_tokens:
            if "=" not in p:
                console._print_message("WARNING", f"Skipping invalid parameter (no '='): {p}")
                continue

            key, value = p.split("=", 1)

            # Determine fuzz mode
            if value in ("?s", "?S"):
                mode: FuzzMode = "string"
                fixed_value: Optional[str] = None
            elif value in ("?i", "?I"):
                mode = "int"
                fixed_value = None
            elif value in ("?b", "?B"):
                mode = "bool"
                fixed_value = None
            elif value == "?":
                mode = "auto"
                fixed_value = None
            else:
                mode = "fixed"
                fixed_value = value

            # For fixed values, pre-infer type for extras
            fixed_type: Optional[str] = None
            if mode == "fixed" and key not in ("action", "uri", "entity", "mime"):
                fixed_type = _infer_type_from_value(fixed_value)  # type: ignore[arg-type]

            param_specs.append(
                {
                    "key": key,
                    "mode": mode,
                    "fixed_value": fixed_value,
                    "fixed_type": fixed_type,
                    "last_value": None,  # used for mutational fuzzing
                }
            )

        if not param_specs:
            console._print_message(
                "WARNING",
                "No parameters specified to fuzz or send. "
                "You can still start the ability, but there is nothing to mutate.",
            )

        # Set up per-session command log (independent of device --log)
        start_time = time.time()
        log_file = None
        log_path = None
        try:
            log_dir = os.path.join(os.getcwd(), "logs")
            os.makedirs(log_dir, exist_ok=True)
            start_ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(start_time))
            safe_ns = re.sub(r"[^a-zA-Z0-9_.-]", "_", namespace)
            safe_ab = re.sub(r"[^a-zA-Z0-9_.-]", "_", ability_name)
            log_name = f"{self.name}_{safe_ns}_{safe_ab}_{start_ts}.log"
            log_path = os.path.join(log_dir, log_name)
            log_file = open(log_path, "w", encoding="utf-8")
            log_file.write("# app_ability_fuzz command log\n")
            log_file.write(f"# namespace={namespace}\n")
            log_file.write(f"# ability={ability_name}\n")
            log_file.write(f"# count={count}\n")
            log_file.write(f"# delay_ms={delay_ms}\n\n")
            log_file.flush()
            console._print_message("INFO", f"Fuzzer command log: {log_path}")
        except Exception as e:
            console._print_message(
                "WARNING",
                f"Could not create fuzzer command log file: {e}",
            )
            log_file = None

        console._print_message(
            "INFO",
            f"Starting fuzzing: ability='{ability_name}', app='{namespace}', "
            f"iterations={count}, delay={delay_ms} ms",
        )

        try:
            # Main fuzzing loop
            for iteration in range(1, count + 1):
                # Base aa start command
                cmd = ["aa", "start", "-a", ability_name, "-b", namespace]

                # Build Want parameters for this iteration
                for spec in param_specs:
                    key: str = spec["key"]
                    mode: FuzzMode = spec["mode"]  # type: ignore[assignment]
                    fixed_value: Optional[str] = spec["fixed_value"]
                    fixed_type: Optional[str] = spec["fixed_type"]

                    # Decide on value and type for this iteration
                    if mode == "fixed":
                        value = fixed_value
                        value_type = (
                            _infer_type_from_value(value)  # type: ignore[arg-type]
                            if key not in ("action", "uri", "entity", "mime")
                            else "string"
                        )
                    else:
                        # Fuzzed (mutational for strings)
                        if mode == "string":
                            value_type = "string"
                        elif mode == "int":
                            value_type = "int"
                        elif mode == "bool":
                            value_type = "bool"
                        else:  # auto
                            value_type = _choose_auto_type()

                        # Generate fuzzed value
                        if value_type == "string":
                            # Mutational: seed from last_value or fixed_value if available
                            base_seed = spec.get("last_value") or spec.get("fixed_value")
                            value = _fuzz_string(base=base_seed)
                            spec["last_value"] = value
                        elif value_type == "int":
                            value = str(_fuzz_int())
                            spec["last_value"] = value
                        else:  # bool
                            value = "true" if _fuzz_bool() else "false"
                            spec["last_value"] = value

                    # Map to aa flags
                    if key == "action":
                        cmd += ["-A", value]  # type: ignore[arg-type]
                    elif key == "uri":
                        cmd += ["-U", value]  # type: ignore[arg-type]
                    elif key == "entity":
                        cmd += ["-e", value]  # type: ignore[arg-type]
                    elif key == "mime":
                        cmd += ["-t", value]  # type: ignore[arg-type]
                    else:
                        # Extra parameter
                        if value_type == "bool":
                            cmd += ["--pb", key, str(value).lower()]  # type: ignore[union-attr]
                        elif value_type == "int":
                            cmd += ["--pi", key, str(value)]  # type: ignore[arg-type]
                        else:
                            cmd += ["--ps", key, str(value)]  # type: ignore[arg-type]

                console._print_message(
                    "INFO",
                    f"[{iteration}/{count}] Executing aa start with fuzzed Want.",
                )
                if console.verbose:
                    console._print_message("DEBUG", " ".join(cmd))

                stdout, stderr, ret = console._get_hdc_shell_output(cmd)

                # Write fuzzer command log entry
                if log_file is not None:
                    now = time.time()
                    elapsed = now - start_time
                    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
                    hdc_cmd_str = f"hdc -t {console.hdc_device_id} shell " + " ".join(cmd)
                    log_file.write(
                        f"{ts} [+{elapsed:9.3f}s] iter={iteration}/{count} "
                        f"ret={ret} cmd={hdc_cmd_str}\n"
                    )
                    log_file.flush()

                if ret != 0:
                    console._print_message(
                        "ERROR",
                        f"[{iteration}/{count}] aa start failed (ret={ret}).",
                    )
                    if stdout:
                        print("\n--- stdout ---")
                        print(stdout.rstrip("\n"))
                    if stderr:
                        print("\n--- stderr ---")
                        print(stderr.rstrip("\n"))
                    print("\n-----------------\n")
                else:
                    if console.verbose and stdout:
                        console._print_message(
                            "DEBUG",
                            f"[{iteration}/{count}] aa start succeeded with output:",
                        )
                        print(stdout.rstrip("\n"))

                # Delay between iterations (if requested)
                if iteration < count and delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
        finally:
            if log_file is not None:
                log_file.close()


def register(registry_func):
    registry_func(AppAbilityFuzzCommand())
