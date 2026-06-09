# -*- coding: utf-8 -*-
# commands/android/app_deeplinks.py
"""
app_deeplinks - enumerate every deeplink handler registered by an installed
Android package.

Pairs with the existing 'app_deeplink <uri>' which just triggers one URI:
this command discovers the URIs available to trigger in the first place.

Data source: 'pm dump <package>', parsed via parsers/android_parser.  The
parser was enriched in B10 to capture Authority (host) and PatternMatcher
(path) per intent filter, so we can reconstruct full example URIs.

Filtering rule: a deeplink handler is any exported component that declares
an android.intent.action.VIEW intent filter.  In practice the most useful
ones also declare BROWSABLE (so links from other apps/the web can launch
them), but we list both with a column tagging which kind it is.

Output:
  - console (default): per-component grouping with schemes / hosts / paths
    and one example URI per (scheme, host, path) combination, ready to be
    fed back into 'app_deeplink'
  - --json: structured payload for piping into other tooling
"""

import json
import re
from typing import List, Optional

from commands.base import Command, CommandSource
from parsers.android_parser import parse_pm_dump


# Local ANSI palette (kept consistent with app_scan).
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RST = "\033[0m"
_GREEN = "\033[1;92m"
_YELLOW = "\033[1;93m"
_BLUE = "\033[1;94m"


# ---------------------------------------------------------------------------
# Per-handler shaping
# ---------------------------------------------------------------------------

def _is_view_filter(skill: dict) -> bool:
    """A VIEW handler is what makes a deeplink a deeplink."""
    return skill.get("action") == "android.intent.action.VIEW"


def _categories_of(skill: dict) -> list:
    """Flatten primary + secondary categories into one list."""
    cats = []
    primary = skill.get("entity")
    if primary:
        cats.append(primary)
    for c in skill.get("categories") or []:
        if c not in cats:
            cats.append(c)
    return cats


def _is_browsable(skill: dict) -> bool:
    return "android.intent.category.BROWSABLE" in _categories_of(skill)


def _build_example_uri(skill: dict) -> Optional[str]:
    """
    Reconstruct a runnable example URI from a VIEW intent filter.

    The result is best-effort: we use scheme/host/path verbatim for LITERAL
    paths, append a wildcard placeholder for PREFIX/GLOB, and fall back to
    just the scheme://host when only those two are declared.
    """
    scheme = skill.get("scheme")
    if not scheme:
        return None
    host = skill.get("host")
    port = skill.get("port")
    path = skill.get("path")
    ptype = skill.get("pathType")

    out = f"{scheme}://"
    if host:
        out += host
        if port is not None:
            out += f":{port}"
    elif not path:
        # Pure scheme handler (e.g. tel:, mailto:) - leave it bare.
        return scheme + ":"

    if path:
        if ptype == "LITERAL":
            out += path if path.startswith("/") else "/" + path
        elif ptype == "PREFIX":
            base = path if path.startswith("/") else "/" + path
            out += base + ("" if base.endswith("/") else "/") + "<rest>"
        elif ptype in ("GLOB", "ADVANCED_GLOB"):
            base = path if path.startswith("/") else "/" + path
            out += "/<matches:" + base + ">"
        else:
            out += path
    return out


def _collect_handlers(parsed: dict) -> list:
    """
    Build a list of deeplink handlers from the parsed pm-dump output.

    Each entry:
        {
            "component": "com.example.app.LoginActivity",
            "type":      "Activity",
            "exported":  True,
            "permissions": [...],
            "filters":   [<skill dict>, ...],   # only VIEW filters
            "browsable": True / False,
            "examples":  ["myapp://login", "https://example.com/login", ...]
        }
    """
    handlers = []
    for comp in parsed.get("exposedComponents", []):
        if not comp.get("visible"):
            continue
        view_filters = [s for s in (comp.get("skills") or []) if _is_view_filter(s)]
        if not view_filters:
            continue
        examples = []
        for s in view_filters:
            uri = _build_example_uri(s)
            if uri and uri not in examples:
                examples.append(uri)
        handlers.append({
            "component":   comp.get("name", "?"),
            "type":        comp.get("type", "?"),
            "exported":    True,
            "permissions": comp.get("permissionsRequired") or [],
            "filters":     view_filters,
            "browsable":   any(_is_browsable(s) for s in view_filters),
            "examples":    examples,
        })
    return handlers


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _render_console(pkg: str, handlers: list) -> str:
    lines = []
    sep = "=" * 60
    lines.append(sep)
    lines.append(f"{_BOLD}APP DEEPLINKS  {pkg}{_RST}")
    lines.append(sep)
    if not handlers:
        lines.append("  No deeplink handlers found.")
        lines.append(sep)
        return "\n".join(lines)
    browsable = sum(1 for h in handlers if h["browsable"])
    lines.append(f"  Handlers : {len(handlers)} total  ({browsable} BROWSABLE)")
    lines.append("-" * 60)

    for h in handlers:
        tag = (
            f"{_GREEN}BROWSABLE{_RST}" if h["browsable"]
            else f"{_YELLOW}internal{_RST}"
        )
        lines.append("")
        lines.append(f"  {_BOLD}[{h['type']}]{_RST} {h['component']}   ({tag})")
        if h["permissions"]:
            lines.append(f"        Permission   : {', '.join(h['permissions'])}")
        # Aggregate schemes/hosts/paths across the filters.
        schemes = sorted({f.get("scheme") for f in h["filters"] if f.get("scheme")})
        hosts = sorted({f.get("host") for f in h["filters"] if f.get("host")})
        paths = sorted({
            f"{f.get('pathType','?')}:{f.get('path','')}"
            for f in h["filters"] if f.get("path")
        })
        if schemes:
            lines.append(f"        Schemes      : {', '.join(schemes)}")
        if hosts:
            lines.append(f"        Hosts        : {', '.join(hosts)}")
        if paths:
            lines.append(f"        Paths        : {', '.join(paths)}")
        cats = sorted({c for f in h["filters"] for c in _categories_of(f)})
        if cats:
            lines.append(f"        Categories   : {', '.join(cats)}")
        if h["examples"]:
            lines.append(f"        {_BLUE}Try:{_RST}")
            for uri in h["examples"]:
                lines.append(f"          app_deeplink {uri}")
    lines.append("")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(pkg: str, handlers: list) -> str:
    return json.dumps({
        "package": pkg,
        "handlers": handlers,
        "counts": {
            "total": len(handlers),
            "browsable": sum(1 for h in handlers if h["browsable"]),
        },
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


class AndroidAppDeeplinksCommand(Command):
    """
    Enumerate every deeplink handler declared by an installed package.
    Companion to 'app_deeplink', which triggers a single URI.
    """

    @property
    def name(self) -> str:
        return "app_deeplinks"

    @property
    def supports_logging(self) -> bool:
        return True

    def help(self) -> str:
        return (
            "app_deeplinks <package> [--json]\n"
            "  List every component that handles deeplinks (action.VIEW intent\n"
            "  filters) for <package>, with their schemes, hosts, paths and\n"
            "  category set.  Each handler comes with one or more example URIs\n"
            "  you can pass straight to 'app_deeplink' to trigger.\n\n"
            "  --json  Emit structured JSON instead of the pretty console view.\n\n"
            "Examples:\n"
            "  app_deeplinks com.example.app\n"
            "  app_deeplinks com.example.app --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        if not console.device_id:
            console._print_message("ERROR", "No Android device connected via adb.")
            return

        as_json = False
        if "--json" in args:
            as_json = True
            args = [a for a in args if a != "--json"]

        if len(args) != 1:
            console._print_message("INFO", "Usage: app_deeplinks <package> [--json]")
            return

        package = args[0]
        if not re.match(r"^[a-zA-Z0-9._-]+$", package):
            console._print_message("ERROR", f"Invalid package name: '{package}'")
            return

        console._print_message("INFO", f"Scanning deeplink handlers for {package} ...")
        stdout, stderr, retcode = console._run_shell(["pm", "dump", package])
        if retcode != 0 or not stdout:
            console._print_message("ERROR", f"pm dump failed: {stderr or 'no output'}")
            return

        parsed = parse_pm_dump(stdout, package)
        handlers = _collect_handlers(parsed)

        if as_json:
            print(_render_json(package, handlers))
        else:
            print(_render_console(package, handlers))


def register(registry_func):
    registry_func(AndroidAppDeeplinksCommand())
