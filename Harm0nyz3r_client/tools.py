# -*- coding: utf-8 -*-
# Harm0nyz3r_client/tools.py
"""
Central resolver for the external CLI tools the Harm0nyz3r toolchain
shells out to (jadx, apktool, openssl, adb, ...).  Commands call
resolve_tool('jadx') instead of shutil.which('jadx') so the user can
pin a specific binary in one place rather than relying on whatever
'jadx' happens to mean on PATH.

Resolution order (first hit wins, missing files are skipped)
  1. tools.local.json     personal override, gitignored
  2. tools.json           shipped defaults; ships with everything null
  3. shutil.which(name)   PATH fallback (default; opt out with
                          fallback_path_lookup=False)
  4. None
"""

import json
import os
import shutil
from typing import Optional


_PRIMARY = os.path.join(os.path.dirname(__file__), "tools.json")
_LOCAL   = os.path.join(os.path.dirname(__file__), "tools.local.json")


def _load_one(path: str) -> dict:
    """Read a single config file; return an empty dict on any failure."""
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Drop $ comment keys ($schema, $doc, ...) so they can't shadow a tool.
    return {k: v for k, v in data.items() if not k.startswith("$")}


def resolve_tool(name: str, fallback_path_lookup: bool = True) -> Optional[str]:
    """
    Resolve an external CLI tool to an absolute path.

    Returns None when no source supplies a usable path.  A configured
    entry that points at a file that does not exist on disk is treated
    as 'this source has no opinion' and resolution continues to the
    next source -- this lets a half-finished tools.json with a stale
    path still benefit from the PATH fallback.

    Set fallback_path_lookup=False when the caller wants to require an
    explicit configured path (rare).
    """
    for source in (_LOCAL, _PRIMARY):
        cfg = _load_one(source)
        configured = cfg.get(name)
        if isinstance(configured, str) and configured and os.path.isfile(configured):
            return configured
    if fallback_path_lookup:
        return shutil.which(name)
    return None


def tools_status() -> list:
    """
    Return a list of {name, configured, resolved, source} dicts -- one
    per tool that appears in either config file (union).  Useful for
    a 'why is jadx not found?' diagnostic.
    """
    primary = _load_one(_PRIMARY)
    local = _load_one(_LOCAL)
    names = sorted(set(primary.keys()) | set(local.keys()))
    out = []
    for name in names:
        resolved = resolve_tool(name)
        source = None
        if isinstance(local.get(name), str) and local[name] and os.path.isfile(local[name]):
            source = "local"
        elif isinstance(primary.get(name), str) and primary[name] and os.path.isfile(primary[name]):
            source = "shipped"
        elif resolved is not None:
            source = "PATH"
        out.append({
            "name":       name,
            "configured": local.get(name) or primary.get(name),
            "resolved":   resolved,
            "source":     source,
        })
    return out
