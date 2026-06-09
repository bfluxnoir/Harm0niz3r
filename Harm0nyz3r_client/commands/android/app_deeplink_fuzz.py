# -*- coding: utf-8 -*-
# commands/android/app_deeplink_fuzz.py
"""
app_deeplink_fuzz - enumerate every exported deeplink handler on
<package>, generate a small mutational corpus per handler, and fire
each candidate via 'am start -W'.  Classify the outcomes so the
operator can spot the URIs that crashed, raised a SecurityException,
or unexpectedly resolved to a non-deeplink component.

V1 is intentionally constrained.  It is NOT a heavyweight fuzzer:

  * the corpus per handler is small (<= 15 URIs)
  * every fire goes through 'am start -W' so each attempt yields a
    deterministic exit code and stdout we can parse
  * no body / extras fuzzing -- only the URI surface is touched

Classifications
  OK         am exit 0 + 'Status: ok' in the launcher output, no
             error markers
  REJECTED   am exit 0 but 'Error: Activity not started' shape (the
             intent was filtered out) -- typically because the
             pattern didn't match a handler
  ANOMALY    am stdout / stderr contains one of the suspicious
             markers ('SecurityException', 'AndroidRuntime',
             'Crash', 'FATAL EXCEPTION', 'IllegalArgumentException',
             'NullPointerException', 'BadParcelableException')
  ERROR      am exit != 0 with no obvious anomaly marker

Output
  Console table (default) or JSON (--json).  Anomalies sorted first.
"""

import json
import re
from typing import Dict, List, Optional, Tuple

from commands.base import Command, CommandSource
from parsers.android_parser import parse_pm_dump, looks_thin
from commands.android.app_deeplinks import _collect_handlers


# ---------------------------------------------------------------------------
# Markers
# ---------------------------------------------------------------------------

_ANOMALY_MARKERS = (
    "SecurityException",
    "AndroidRuntime",
    "FATAL EXCEPTION",
    "Process Crashed",
    "IllegalArgumentException",
    "NullPointerException",
    "BadParcelableException",
    "ANR ",  # leading-space guards against matching 'ANRobotics' etc.
    "Permission Denial",
)

_REJECTED_MARKERS = (
    "Error: Activity not started",
    "Error: Intent does not match",
    "Error type 3",
)


# ---------------------------------------------------------------------------
# Corpus builder
# ---------------------------------------------------------------------------

def _example_for(handler: dict) -> Optional[str]:
    examples = handler.get("examples") or []
    return examples[0] if examples else None


def _seed_components(handler: dict) -> Tuple[str, str, str]:
    """Return (scheme, host, path) -- with sensible fall-backs."""
    scheme = (handler.get("scheme") or "").strip()
    host = (handler.get("host") or "").strip()
    path = handler.get("path") or "/"
    if not path.startswith("/"):
        path = "/" + path
    return scheme, host, path


def _build_corpus(handler: dict) -> List[Tuple[str, str]]:
    """
    Build a (mutation_id, uri) list for one handler.  De-duplicated;
    each URI appears at most once even when multiple mutations would
    have produced it.
    """
    scheme, host, path = _seed_components(handler)
    if not scheme:
        return []
    h = host or "example.com"

    base = f"{scheme}://{h}{path}"
    seen: Dict[str, str] = {}

    def add(mid: str, uri: str) -> None:
        if uri and uri not in seen.values():
            seen[mid] = uri

    # 1. canonical example or rebuilt base
    add("base", _example_for(handler) or base)

    # 2. very long path
    add("long_path", f"{scheme}://{h}/" + "A" * 1024)

    # 3. classic traversal
    add("traversal", f"{scheme}://{h}/../../../../etc/passwd")

    # 4. SQL-ish payload via query
    add("sqli_quote", f"{scheme}://{h}{path}?id=1' OR '1'='1")
    add("sqli_union", f"{scheme}://{h}{path}?id=-1 UNION SELECT 1,2,3 --")

    # 5. XSS / JS scheme pivots
    add("xss_payload",   f"{scheme}://{h}{path}?q=<script>alert(1)</script>")
    add("js_scheme",     "javascript:alert(1)")

    # 6. dangerous schema swaps
    add("file_scheme",    f"file://{h}{path}")
    add("content_scheme", "content://com.android.providers.media.documents/document/audio:1")

    # 7. null bytes + encoding edges
    add("null_byte",     f"{scheme}://{h}/%00")
    add("urlencoded",    f"{scheme}://{h}/{'%41' * 32}")

    # 8. unicode shenanigans (RTL override, full-width)
    add("unicode_rtl",   f"{scheme}://{h}/‮gnp.evil")
    add("unicode_full",  f"{scheme}://{h}/%EF%BC%9Cscript%EF%BC%9E")

    # 9. empty host
    add("empty_host",    f"{scheme}:///")

    return [(mid, uri) for mid, uri in seen.items()]


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _classify(stdout: str, stderr: str, retcode: int) -> Tuple[str, List[str]]:
    """Return (verdict, hit_markers)."""
    combined = (stdout or "") + "\n" + (stderr or "")
    anomalies = [m for m in _ANOMALY_MARKERS if m in combined]
    if anomalies:
        return "ANOMALY", anomalies
    rejected = [m for m in _REJECTED_MARKERS if m in combined]
    if rejected:
        return "REJECTED", rejected
    if retcode != 0:
        return "ERROR", []
    return "OK", []


# ---------------------------------------------------------------------------
# Fire one URI
# ---------------------------------------------------------------------------

def _fire(console, package: str, uri: str) -> dict:
    cmd = [
        "am", "start", "-W",
        "-a", "android.intent.action.VIEW",
        "-d", uri,
        package,
    ]
    out, err, ret = console._run_shell(cmd)
    verdict, markers = _classify(out or "", err or "", ret)
    return {
        "uri":      uri,
        "exit":     ret,
        "stdout":   (out or "").strip(),
        "stderr":   (err or "").strip(),
        "verdict":  verdict,
        "markers":  markers,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_BOLD = "\033[1m"; _DIM = "\033[2m"; _RST = "\033[0m"
_VERDICT_COLOR = {
    "ANOMALY":  "\033[1;91m",
    "ERROR":    "\033[1;93m",
    "REJECTED": "\033[1;94m",
    "OK":       "\033[1;92m",
}
_VERDICT_ORDER = {"ANOMALY": 0, "ERROR": 1, "REJECTED": 2, "OK": 3}


def _render_console(package: str, fuzz_results: List[dict]) -> str:
    sep = "=" * 60
    counts: Dict[str, int] = {}
    for r in fuzz_results:
        for shot in r["results"]:
            counts[shot["verdict"]] = counts.get(shot["verdict"], 0) + 1
    total_shots = sum(counts.values())

    lines = [
        sep,
        f"{_BOLD}DEEPLINK FUZZ  {package}{_RST}",
        sep,
        f"  Handlers fuzzed : {len(fuzz_results)}",
        f"  Shots fired     : {total_shots}  "
        + "  ".join(f"{k}:{counts.get(k, 0)}"
                    for k in ("ANOMALY", "ERROR", "REJECTED", "OK")),
        "-" * 60,
    ]
    if not fuzz_results:
        lines.append("  No exported deeplink handlers found.")
        lines.append(sep)
        return "\n".join(lines)

    for entry in fuzz_results:
        h = entry["handler"]
        title = (
            f"{h.get('scheme')}://{h.get('host') or '*'}{h.get('path') or '/'}  "
            f"-> {h.get('component')}"
        )
        lines.append("")
        lines.append(f"  {_BOLD}{title}{_RST}")
        shots = sorted(entry["results"],
                       key=lambda x: _VERDICT_ORDER.get(x["verdict"], 9))
        for s in shots:
            color = _VERDICT_COLOR.get(s["verdict"], "")
            lines.append(
                f"    [{color}{s['verdict']:<8}{_RST}] {s['uri']}"
            )
            if s["markers"]:
                lines.append(f"        {_DIM}markers: {', '.join(s['markers'])}{_RST}")
    lines.append("")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(package: str, fuzz_results: List[dict]) -> str:
    return json.dumps({
        "package":  package,
        "handlers": fuzz_results,
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidAppDeeplinkFuzzCommand(Command):
    @property
    def name(self) -> str:
        return "app_deeplink_fuzz"

    def help(self) -> str:
        return (
            "app_deeplink_fuzz <package> [--max-per-handler N] [--json]\n"
            "  Enumerate exported deeplink handlers for <package>, build a\n"
            "  small mutational URI corpus per handler (long path, traversal,\n"
            "  SQL-ish payload, XSS / JS scheme swap, file:// / content://\n"
            "  pivots, null byte, unicode, empty host) and fire each via\n"
            "  'am start -W'.  Classify each attempt as ANOMALY / ERROR /\n"
            "  REJECTED / OK based on am output.\n"
            "  --max-per-handler N  Hard cap on URIs per handler (default 15)\n"
            "  --json               Emit JSON instead of the console table.\n\n"
            "Examples:\n"
            "  app_deeplink_fuzz com.example.target\n"
            "  app_deeplink_fuzz com.example.target --max-per-handler 5 --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        as_json = False
        max_per_handler = 15
        positional: List[str] = []
        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--json":
                as_json = True; i += 1
            elif tok == "--max-per-handler" and i + 1 < len(args):
                try:
                    max_per_handler = max(1, int(args[i + 1]))
                except ValueError:
                    console._print_message("WARNING", f"Invalid --max-per-handler {args[i+1]!r}; using 15.")
                i += 2
            else:
                positional.append(tok); i += 1

        if len(positional) != 1:
            console._print_message(
                "INFO",
                "Usage: app_deeplink_fuzz <package> [--max-per-handler N] [--json]"
            )
            return
        package = positional[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: {package}")
            return

        # --- collect handlers via pm dump + parser ---
        console._print_message("INFO", f"Enumerating deeplink handlers on {package} ...")
        dump_out, dump_err, ret = console._run_shell(["pm", "dump", package])
        if ret != 0 or not dump_out:
            console._print_message("ERROR", f"pm dump failed: {dump_err or 'no output'}")
            return
        parsed = parse_pm_dump(dump_out, package)
        if looks_thin(parsed):
            console._print_message(
                "WARNING",
                "pm dump produced thin output; fuzz coverage may be partial.  Try "
                "'agent_exec app_info <pkg>' for comparison."
            )
        handlers = _collect_handlers(parsed)
        if not handlers:
            console._print_message("INFO", "No exported deeplink handlers found.")
            return

        # --- fuzz each handler ---
        fuzz_results: List[dict] = []
        for h in handlers:
            corpus = _build_corpus(h)[:max_per_handler]
            results = [_fire(console, package, uri) for _, uri in corpus]
            fuzz_results.append({"handler": h, "results": results})

        if as_json:
            print(_render_json(package, fuzz_results))
        else:
            print(_render_console(package, fuzz_results))


def register(registry_func):
    registry_func(AndroidAppDeeplinkFuzzCommand())
