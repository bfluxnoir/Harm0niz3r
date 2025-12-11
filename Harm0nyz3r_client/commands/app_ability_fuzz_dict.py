# commands/app_ability_fuzz_dict.py
import os
import re
import random
import time
from typing import List, Optional

from .base import Command, CommandSource

try:
    from typing import Literal
    FuzzMode = Literal["fixed", "dict"]
except ImportError:
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


def _load_dictionary(path: str) -> List[str]:
    """
    Load dictionary values from a text file (one value per line).

    - Strips whitespace.
    - Skips empty lines.
    - Skips comment lines starting with '#'.
    """
    values: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                if s.startswith("#"):
                    continue
                values.append(s)
    except Exception as e:
        # We won't raise here; caller should handle empty list as "no dictionary".
        print(f"[DICT] Error loading dictionary '{path}': {e}")
    return values


class AppAbilityFuzzDictCommand(Command):
    @property
    def name(self) -> str:
        return "app_ability_fuzz_dict"

    @property
    def supports_logging(self) -> bool:
        # Allow: app_ability_fuzz_dict ... --log
        # The console wrapper will start/stop device logging for the whole fuzz session.
        return True

    def help(self) -> str:
        return (
            "app_ability_fuzz_dict <namespace> <abilityName> "
            "[--count N] [--delay ms] [--dict-mode sequential|random] "
            "[key=value or key=@dictfile] [--log]\n"
            "\n"
            "Start an ability repeatedly with a Want whose parameters can come from\n"
            "fixed values or dictionary files (one value per line).\n"
            "\n"
            "Parameter syntax (key=value):\n"
            "  action=<value>   → Want action (-A)\n"
            "  uri=<value>      → Want URI (-U)\n"
            "  entity=<value>   → Want entity (-e)\n"
            "  mime=<value>     → MIME type (-t)\n"
            "  anyOtherKey=<value> → Want extra (type inferred: string/int/bool)\n"
            "\n"
            "Dictionary mode:\n"
            "  key=@path/to/file.txt\n"
            "    - File is read once, each line is a candidate value.\n"
            "    - Selection strategy:\n"
            "        * default / --dict-mode sequential → iterate values in order\n"
            "        * --dict-mode random               → pick a random value per use\n"
            "\n"
            "Examples:\n"
            "  app_ability_fuzz_dict com.example.app MainAbility --count 50 "
            "name=@names.txt\n"
            "  app_ability_fuzz_dict com.example.app MainAbility --count 20 "
            "--dict-mode random action=ohos.want.action.view uri=@uris.txt\n"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        """
        Usage:
            app_ability_fuzz_dict <namespace> <abilityName>
                [--count N] [--delay ms] [--dict-mode sequential|random]
                [key=value or key=@dictfile] [--log]

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
        dict_mode = "sequential"  # default dictionary strategy
        param_tokens: List[str] = []

        # Parse global options (--count, --delay, --dict-mode) + collect key=value tokens
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
            elif token == "--dict-mode" and i + 1 < len(args):
                mode_val = args[i + 1].lower()
                if mode_val in ("sequential", "seq"):
                    dict_mode = "sequential"
                elif mode_val in ("random", "rand"):
                    dict_mode = "random"
                else:
                    console._print_message(
                        "WARNING",
                        f"Unknown --dict-mode '{args[i + 1]}', using default '{dict_mode}'",
                    )
                i += 2
                continue
            else:
                param_tokens.append(token)
                i += 1

        # Parse param_specs: key, mode, fixed_value, dict_path, dict_values, dict_index
        param_specs: List[dict] = []
        for p in param_tokens:
            if "=" not in p:
                console._print_message("WARNING", f"Skipping invalid parameter (no '='): {p}")
                continue

            key, value = p.split("=", 1)

            # Dictionary mode: value starts with '@'
            if value.startswith("@"):
                dict_path_raw = value[1:].strip()
                dict_path = os.path.abspath(dict_path_raw)
                dict_values = _load_dictionary(dict_path)
                if not dict_values:
                    console._print_message(
                        "WARNING",
                        f"Dictionary '{dict_path_raw}' is empty or could not be loaded. "
                        f"Parameter '{key}' will be skipped.",
                    )
                    # We can choose to skip or treat as fixed empty; here we skip:
                    continue

                mode: FuzzMode = "dict"
                fixed_value: Optional[str] = None
                fixed_type: Optional[str] = None
                param_specs.append(
                    {
                        "key": key,
                        "mode": mode,
                        "fixed_value": fixed_value,
                        "fixed_type": fixed_type,
                        "dict_path": dict_path,
                        "dict_values": dict_values,
                        "dict_index": 0,  # used for sequential mode
                    }
                )
                continue

            # Fixed value mode
            mode = "fixed"
            fixed_value = value
            fixed_type: Optional[str] = None
            if key not in ("action", "uri", "entity", "mime"):
                fixed_type = _infer_type_from_value(fixed_value)

            param_specs.append(
                {
                    "key": key,
                    "mode": mode,
                    "fixed_value": fixed_value,
                    "fixed_type": fixed_type,
                    "dict_path": None,
                    "dict_values": None,
                    "dict_index": 0,
                }
            )

        if not param_specs:
            console._print_message(
                "WARNING",
                "No valid parameters specified (fixed or dictionary). "
                "You can still start the ability, but there is nothing to vary.",
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
            log_file.write("# app_ability_fuzz_dict command log\n")
            log_file.write(f"# namespace={namespace}\n")
            log_file.write(f"# ability={ability_name}\n")
            log_file.write(f"# count={count}\n")
            log_file.write(f"# delay_ms={delay_ms}\n")
            log_file.write(f"# dict_mode={dict_mode}\n\n")
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
            f"Starting dictionary-based fuzzing: ability='{ability_name}', "
            f"app='{namespace}', iterations={count}, delay={delay_ms} ms",
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
                    dict_values: Optional[List[str]] = spec["dict_values"]
                    dict_index: int = spec.get("dict_index", 0)

                    # Decide value for this iteration
                    if mode == "fixed":
                        value = fixed_value
                        value_type = (
                            fixed_type
                            if fixed_type is not None
                            else (
                                _infer_type_from_value(value)  # type: ignore[arg-type]
                                if key not in ("action", "uri", "entity", "mime")
                                else "string"
                            )
                        )
                    else:
                        # dict mode
                        if not dict_values:
                            # Should not happen, but be defensive
                            console._print_message(
                                "WARNING",
                                f"No dictionary values loaded for key '{key}', skipping.",
                            )
                            continue

                        if dict_mode == "random":
                            value = random.choice(dict_values)
                        else:
                            # sequential
                            value = dict_values[dict_index]
                            dict_index = (dict_index + 1) % len(dict_values)
                            spec["dict_index"] = dict_index

                        # For dictionary, infer type similarly to fixed
                        if key in ("action", "uri", "entity", "mime"):
                            value_type = "string"
                        else:
                            value_type = _infer_type_from_value(value)

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
                        # Extra parameter (string/int/bool)
                        if value_type == "bool":
                            cmd += ["--pb", key, str(value).lower()]  # type: ignore[union-attr]
                        elif value_type == "int":
                            cmd += ["--pi", key, str(value)]  # type: ignore[arg-type]
                        else:
                            cmd += ["--ps", key, str(value)]  # type: ignore[arg-type]

                console._print_message(
                    "INFO",
                    f"[{iteration}/{count}] Executing aa start with dictionary-based Want.",
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
    registry_func(AppAbilityFuzzDictCommand())
