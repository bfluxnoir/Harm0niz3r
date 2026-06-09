# commands/android/app_provider.py
import json
import re
from typing import List, Optional, Tuple

from commands.base import Command, CommandSource
from parsers.android_parser import parse_pm_dump, parse_content_query


# Android 'content' tool bind types.
_BIND_TYPES = {"s", "i", "l", "f", "d", "b"}

# Markers that flip a write verdict from ERROR to DENIED.  Same set as
# app_provider_probe so the two commands speak with one voice.
_DENIED_MARKERS = (
    "SecurityException",
    "Permission Denial",
    "java.lang.SecurityException",
)


def _classify_write(stdout: str, stderr: str, retcode: int) -> Tuple[str, List[str]]:
    """Return (verdict, hit markers)."""
    combined = (stdout or "") + "\n" + (stderr or "")
    hit = [m for m in _DENIED_MARKERS if m in combined]
    if hit:
        return "DENIED", hit
    if retcode != 0:
        return "ERROR", []
    return "OK", []


def _validate_bind_spec(spec: str) -> Tuple[str, str, str]:
    """
    Parse 'col:type:value' into (col, type, value).  The value may itself
    contain colons -- only the first two are treated as separators.
    Raises ValueError on a malformed spec or unknown type.
    """
    parts = spec.split(":", 2)
    if len(parts) != 3:
        raise ValueError(f"--bind expects col:type:value, got {spec!r}")
    col, typ, val = parts
    col = col.strip()
    typ = typ.strip()
    if not col:
        raise ValueError(f"--bind has empty column: {spec!r}")
    if typ not in _BIND_TYPES:
        raise ValueError(
            f"--bind type must be one of {sorted(_BIND_TYPES)} (s, i, l, f, d, b), got {typ!r}"
        )
    return col, typ, val


def _build_content_args(
    op: str,
    uri: str,
    binds: List[Tuple[str, str, str]],
    where: Optional[str],
) -> List[str]:
    """
    Compose the 'content <op> --uri <uri> ...' command line.  Bind specs
    are stitched back together as 'col:type:value' the way Android's
    'content' tool expects them; the value half can contain colons because
    we never split it on the way out.
    """
    cmd = ["content", op, "--uri", uri]
    for col, typ, val in binds:
        cmd += ["--bind", f"{col}:{typ}:{val}"]
    if where:
        cmd += ["--where", where]
    return cmd


class AndroidAppProviderCommand(Command):
    """
    Android-specific: enumerate exported Content Providers, query them
    read-only, or (C13) drive writes against them via the Android
    'content' tool.
    """

    @property
    def name(self) -> str:
        return "app_provider"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_provider <package> [uri] [-a] [--log]\n"
            "  Enumerate exported Content Providers for <package>.\n"
            "  If <uri> is given without an action flag, run a read-only query.\n"
            "  -a  Send results to the Android agent.\n\n"
            "Write operations (require <uri>):\n"
            "  --insert  --bind col:type:value [--bind ...]\n"
            "  --update  --bind col:type:value [--bind ...] [--where \"<expr>\"]\n"
            "  --delete  [--where \"<expr>\"]\n"
            "  Bind types: s=String, i=Integer, l=Long, f=Float, d=Double, b=Boolean\n"
            "  Each write classifies as OK / DENIED (SecurityException) / ERROR.\n\n"
            "Examples:\n"
            "  app_provider com.example.app\n"
            "  app_provider com.example.app content://com.example.provider/users\n"
            "  app_provider com.example.app content://com.example.provider/users \\\n"
            "      --insert --bind name:s:Alice --bind active:b:true\n"
            "  app_provider com.example.app content://com.example.provider/users \\\n"
            "      --update --bind name:s:Bob --where \"_id=1\"\n"
            "  app_provider com.example.app content://com.example.provider/users \\\n"
            "      --delete --where \"_id=1\""
        )

    # ------------------------------------------------------------------
    # Arg parsing
    # ------------------------------------------------------------------

    def _parse_args(self, args: List[str]):
        """
        Returns a tuple
          (package, uri, op, binds, where, send_to_app, log, error_or_None)
        op is one of None / 'insert' / 'update' / 'delete'.  Any
        misuse comes back via the trailing error string instead of an
        exception so the caller can format it through _print_message.
        """
        send_to_app = False
        log_flag = False
        op: Optional[str] = None
        binds: List[Tuple[str, str, str]] = []
        where: Optional[str] = None
        positional: List[str] = []

        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "-a":
                send_to_app = True; i += 1
            elif tok == "--log":
                log_flag = True; i += 1
            elif tok in ("--insert", "--update", "--delete"):
                new_op = tok[2:]
                if op is not None:
                    return (None,) * 5 + (False, False,
                                          "--insert / --update / --delete are mutually exclusive.")
                op = new_op
                i += 1
            elif tok == "--bind" and i + 1 < len(args):
                try:
                    binds.append(_validate_bind_spec(args[i + 1]))
                except ValueError as e:
                    return (None,) * 5 + (False, False, str(e))
                i += 2
            elif tok == "--where" and i + 1 < len(args):
                where = args[i + 1]; i += 2
            else:
                positional.append(tok); i += 1

        if not positional:
            return (None,) * 5 + (False, False, "Missing <package>.")
        package = positional[0]
        uri = positional[1] if len(positional) >= 2 else None

        if op in ("insert", "update", "delete") and uri is None:
            return (None,) * 5 + (False, False, f"--{op} requires a URI as the second positional.")
        if op == "insert" and not binds:
            return (None,) * 5 + (False, False, "--insert needs at least one --bind col:type:value.")
        if op == "update" and not binds:
            return (None,) * 5 + (False, False, "--update needs at least one --bind col:type:value.")
        if op == "delete" and binds:
            return (None,) * 5 + (False, False, "--delete does not take --bind.")

        return (package, uri, op, binds, where, send_to_app, log_flag, None)

    # ------------------------------------------------------------------

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        parsed_args = self._parse_args(args)
        package, uri, op, binds, where, send_to_app, _log, err = parsed_args
        if err:
            console._print_message("ERROR", err)
            return

        if source == "app":
            send_to_app = True

        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: '{package}'")
            return

        if send_to_app and not console.connected:
            console._print_message("WARNING", "Not connected to agent. Printing to console.")
            send_to_app = False

        # --- Enumerate providers ---
        stdout, stderr, ret = console._run_shell(["pm", "dump", package])
        if ret != 0 or not stdout:
            console._print_message("ERROR", f"pm dump failed: {stderr or 'no output'}")
            return

        parsed = parse_pm_dump(stdout, package)
        providers = [c for c in parsed.get("exposedComponents", []) if c.get("type") == "Provider"]

        print(f"\n--- Content Providers: {package} ({len(providers)}) ---")
        for p in providers:
            exported_tag = "EXPORTED" if p.get("visible") else "internal"
            auth = p.get("authority", "N/A")
            perm = ", ".join(p.get("permissionsRequired", [])) or "(none)"
            print(f"  [{exported_tag}] {p.get('name')}")
            print(f"    Authority  : {auth}")
            print(f"    Permission : {perm}")
        print()

        if uri is None:
            return

        # --- Write op? ---
        if op:
            self._do_write(console, uri, op, binds, where)
            return

        # --- Read-only query (existing behaviour) ---
        console._print_message("INFO", f"Querying: {uri}")
        q_stdout, q_stderr, q_ret = console._run_shell(
            ["content", "query", "--uri", uri]
        )
        if q_ret != 0:
            console._print_message("ERROR", f"content query failed: {q_stderr or 'no output'}")
            return

        result = parse_content_query(q_stdout, uri)
        print(f"--- Query Result: {uri} ---")
        if result["rows"]:
            for row in result["rows"]:
                print(f"  {row}")
        else:
            print("  No rows returned (or provider requires permissions).")
        print()

        if send_to_app and console.connected:
            console.send_data_to_app(f"PROVIDER_QUERY_RESULT:{json.dumps(result)}")

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def _do_write(
        self,
        console,
        uri: str,
        op: str,
        binds: List[Tuple[str, str, str]],
        where: Optional[str],
    ) -> None:
        # Mini guard rail -- the operator is asking us to mutate provider
        # state, so we make the intent visible before issuing the command.
        bind_summary = ", ".join(f"{c}={v}({t})" for c, t, v in binds) or "(no binds)"
        where_summary = f"WHERE {where}" if where else "WHERE *"
        console._print_message(
            "INFO",
            f"Provider {op.upper()} {uri}  {bind_summary}  {where_summary}"
        )

        cmd = _build_content_args(op, uri, binds, where)
        out, err, ret = console._run_shell(cmd)
        verdict, markers = _classify_write(out or "", err or "", ret)

        if verdict == "OK":
            console._print_message("SUCCESS", f"Provider {op} returned cleanly.")
        elif verdict == "DENIED":
            console._print_message(
                "WARNING",
                f"Provider {op} blocked by permissions: {', '.join(markers)}"
            )
        else:
            console._print_message("ERROR", f"Provider {op} failed (exit {ret}).")

        # Surface the raw bridge output so the operator can see whatever
        # the content tool printed (row counts, exception traces, etc.).
        if out:
            print("--- stdout ---")
            print(out.strip())
        if err:
            print("--- stderr ---")
            print(err.strip())


def register(registry_func):
    registry_func(AndroidAppProviderCommand())
