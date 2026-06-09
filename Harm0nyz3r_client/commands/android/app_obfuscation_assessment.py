# -*- coding: utf-8 -*-
# commands/android/app_obfuscation_assessment.py
"""
app_obfuscation_assessment - walk a decompiled Android source tree and
estimate how heavily it's obfuscated.  The point is to give the
operator a quick read on how much manual reverse-engineering effort
they're about to sign up for, not to flag any specific vulnerability.

What we measure
---------------
  * Declared class / method / field names extracted via regex from
    .java / .kt sources (jadx output) AND .smali (apktool output).
    The fraction of names that are 1-2 characters long is the
    canonical R8 / ProGuard obfuscation tell.
  * Kotlin @Metadata annotations -- these survive R8 by default and
    are a reliable indicator that the Kotlin compiler emitted them.
    Their absence in a Kotlin-heavy app is itself a signal.
  * Long hex string literals (>= 64 hex chars) and long base64-shaped
    literals (>= 64 base64 chars) -- typical shapes for encrypted
    string blobs that get decrypted at runtime.
  * Smali debug directives (.source / .line) -- present means the
    debug info wasn't stripped; absent means it was.

Heuristic obfuscation level
---------------------------
A 0..9 score is derived from the metrics above, then bucketed:
  >=6  HEAVY
  >=3  MODERATE
  >=1  LIGHT
   0   NONE

If the tree contains no declared classes (e.g. wrong directory)
the level is reported as UNKNOWN.
"""

import json
import os
import re
from typing import List

from commands.base import Command, CommandSource


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Java / Kotlin -- declaration anchors
_JAVA_CLASS_RE = re.compile(
    r"\b(?:public\s+|private\s+|protected\s+|abstract\s+|final\s+|static\s+|sealed\s+|open\s+|internal\s+)*"
    r"(?:class|interface|object|enum)\s+([A-Za-z_]\w*)"
)
# Methods: <visibility> [static/final/...] <returnType> name(
# We only need the name; the type captures are not used.
_JAVA_METHOD_RE = re.compile(
    r"(?:public|private|protected)\s+(?:static\s+|final\s+|abstract\s+|synchronized\s+|native\s+)*"
    r"[A-Za-z_][\w.<>\[\],\s?]*\s+([A-Za-z_]\w*)\s*\("
)
# Fields: <visibility> [static/final] <type> name [= ...];
_JAVA_FIELD_RE = re.compile(
    r"(?:public|private|protected)\s+(?:static\s+|final\s+|volatile\s+|transient\s+)*"
    r"[A-Za-z_][\w.<>\[\]]*\s+([A-Za-z_]\w*)\s*[=;]"
)

# Smali
_SMALI_CLASS_RE  = re.compile(r"\.class\s+[^\n]*?L(?:[\w/$]+/)*([\w$]+);")
_SMALI_METHOD_RE = re.compile(r"\.method\s+[^\n]*?\b([A-Za-z_$][\w$]*)\s*\(")
_SMALI_FIELD_RE  = re.compile(r"\.field\s+[^\n]*?\b([A-Za-z_$][\w$]*)\s*:")

_SMALI_SOURCE_RE = re.compile(r"\.source\s+\"")
_SMALI_LINE_RE   = re.compile(r"\.line\s+\d+")

# Kotlin metadata annotations (Java view + smali view)
_KOTLIN_META_RE = re.compile(
    r"@Metadata\s*\(|@kotlin\.Metadata|Lkotlin/Metadata;"
)

# Encrypted string blobs (long hex / base64 literals).
_LONG_HEX_RE = re.compile(r'"([A-Fa-f0-9]{64,})"')
_LONG_B64_RE = re.compile(r'"([A-Za-z0-9+/]{64,}={0,2})"')


_TEXT_EXTS = {".java", ".kt", ".smali"}


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------

class Assessment:
    __slots__ = (
        "files_scanned", "java_files", "kt_files", "smali_files",
        "classes_total", "classes_short",
        "methods_total", "methods_short",
        "fields_total", "fields_short",
        "kotlin_metadata_hits",
        "long_hex_strings", "long_base64_strings",
        "smali_source_directives", "smali_line_directives",
    )

    def __init__(self):
        for slot in self.__slots__:
            setattr(self, slot, 0)

    def to_dict(self) -> dict:
        d = {k: getattr(self, k) for k in self.__slots__}
        d["short_class_pct"]  = self.short_pct("class")
        d["short_method_pct"] = self.short_pct("method")
        d["short_field_pct"]  = self.short_pct("field")
        d["score"]            = score_of(self)
        d["level"]            = level_of(self)
        return d

    def short_pct(self, kind: str) -> float:
        total_attr = f"{kind}es_total" if kind == "class" else f"{kind}s_total"
        short_attr = f"{kind}es_short" if kind == "class" else f"{kind}s_short"
        total = getattr(self, total_attr)
        short = getattr(self, short_attr)
        if not total:
            return 0.0
        return round(100.0 * short / total, 1)


def _is_short(name: str) -> bool:
    return len(name) <= 2


def _walk_and_assess(root: str) -> Assessment:
    a = Assessment()
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in _TEXT_EXTS:
                continue
            full = os.path.join(dirpath, name)
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except OSError:
                continue

            a.files_scanned += 1
            if ext == ".java":
                a.java_files += 1
                _ingest_java_or_kotlin(a, text)
            elif ext == ".kt":
                a.kt_files += 1
                _ingest_java_or_kotlin(a, text)
            elif ext == ".smali":
                a.smali_files += 1
                _ingest_smali(a, text)

            # String-obfuscation signals are language-agnostic
            a.kotlin_metadata_hits   += len(_KOTLIN_META_RE.findall(text))
            a.long_hex_strings       += len(_LONG_HEX_RE.findall(text))
            a.long_base64_strings    += len(_LONG_B64_RE.findall(text))

    return a


def _ingest_java_or_kotlin(a: Assessment, text: str) -> None:
    for m in _JAVA_CLASS_RE.finditer(text):
        a.classes_total += 1
        if _is_short(m.group(1)):
            a.classes_short += 1
    for m in _JAVA_METHOD_RE.finditer(text):
        a.methods_total += 1
        if _is_short(m.group(1)):
            a.methods_short += 1
    for m in _JAVA_FIELD_RE.finditer(text):
        a.fields_total += 1
        if _is_short(m.group(1)):
            a.fields_short += 1


def _ingest_smali(a: Assessment, text: str) -> None:
    for m in _SMALI_CLASS_RE.finditer(text):
        a.classes_total += 1
        if _is_short(m.group(1)):
            a.classes_short += 1
    for m in _SMALI_METHOD_RE.finditer(text):
        # smali synthetic ctors -- skip these so they don't bias the short% up
        nm = m.group(1)
        if nm in ("<init>", "<clinit>"):
            continue
        a.methods_total += 1
        if _is_short(nm):
            a.methods_short += 1
    for m in _SMALI_FIELD_RE.finditer(text):
        a.fields_total += 1
        if _is_short(m.group(1)):
            a.fields_short += 1
    a.smali_source_directives += len(_SMALI_SOURCE_RE.findall(text))
    a.smali_line_directives   += len(_SMALI_LINE_RE.findall(text))


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_of(a: Assessment) -> int:
    if a.classes_total == 0 and a.methods_total == 0:
        return 0
    short_class_pct  = a.short_pct("class")
    short_method_pct = a.short_pct("method")
    score = 0

    # Class-name brevity is the strongest single signal
    if   short_class_pct >= 60: score += 3
    elif short_class_pct >= 30: score += 2
    elif short_class_pct >= 10: score += 1

    # Method-name brevity is secondary but also informative
    if   short_method_pct >= 60: score += 2
    elif short_method_pct >= 30: score += 1

    # String-blob density (~ encrypted-string runtime decryption)
    if a.long_hex_strings    + a.long_base64_strings >= 50: score += 2
    elif a.long_hex_strings  + a.long_base64_strings >= 10: score += 1

    # Stripped smali debug info: zero .source AND zero .line directives
    if a.smali_files > 0 and a.smali_source_directives == 0 and a.smali_line_directives == 0:
        score += 1

    return score


def level_of(a: Assessment) -> str:
    if a.classes_total == 0 and a.methods_total == 0:
        return "UNKNOWN"
    s = score_of(a)
    if s >= 6: return "HEAVY"
    if s >= 3: return "MODERATE"
    if s >= 1: return "LIGHT"
    return "NONE"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_BOLD = "\033[1m"; _DIM = "\033[2m"; _RST = "\033[0m"
_LEVEL_COLOR = {
    "NONE":     "\033[1;92m",
    "LIGHT":    "\033[1;94m",
    "MODERATE": "\033[1;93m",
    "HEAVY":    "\033[1;91m",
    "UNKNOWN":  "\033[1;90m",
}


def _render_console(root: str, a: Assessment) -> str:
    sep = "=" * 60
    level = level_of(a)
    color = _LEVEL_COLOR.get(level, "")
    lines = [
        sep,
        f"{_BOLD}OBFUSCATION ASSESSMENT  {root}{_RST}",
        sep,
        f"  Files scanned : {a.files_scanned}  "
        f"(java {a.java_files}, kt {a.kt_files}, smali {a.smali_files})",
        "",
        f"  {_BOLD}Identifier brevity{_RST}",
        f"    classes : {a.classes_short}/{a.classes_total}  "
        f"({a.short_pct('class')}% are <=2 chars)",
        f"    methods : {a.methods_short}/{a.methods_total}  "
        f"({a.short_pct('method')}%)",
        f"    fields  : {a.fields_short}/{a.fields_total}  "
        f"({a.short_pct('field')}%)",
        "",
        f"  {_BOLD}String blobs{_RST}",
        f"    long-hex literals    : {a.long_hex_strings}",
        f"    long-base64 literals : {a.long_base64_strings}",
        "",
        f"  {_BOLD}Debug info (smali){_RST}",
        f"    .source directives : {a.smali_source_directives}",
        f"    .line   directives : {a.smali_line_directives}",
        "",
        f"  {_BOLD}Kotlin{_RST}",
        f"    @Metadata hits : {a.kotlin_metadata_hits}",
        "-" * 60,
        f"  Score : {score_of(a)} / ~9",
        f"  Level : {color}{level}{_RST}",
        sep,
    ]
    return "\n".join(lines)


def _render_json(root: str, a: Assessment) -> str:
    return json.dumps({"root": root, **a.to_dict()}, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidAppObfuscationAssessmentCommand(Command):
    @property
    def name(self) -> str:
        return "app_obfuscation_assessment"

    def help(self) -> str:
        return (
            "app_obfuscation_assessment <directory> [--json]\n"
            "  Walk a decompiled Android source tree and estimate the\n"
            "  obfuscation level: NONE / LIGHT / MODERATE / HEAVY (or\n"
            "  UNKNOWN when no declared classes are found).\n"
            "  Signals: short-identifier %, long hex/base64 literal blobs,\n"
            "  stripped smali debug info, Kotlin @Metadata presence.\n"
            "  --json  Emit metrics + level as JSON.\n\n"
            "Examples:\n"
            "  app_obfuscation_assessment ./decompiled/com.example.target/\n"
            "  app_obfuscation_assessment ./decompiled/com.example.target/ --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        as_json = False
        if "--json" in args:
            as_json = True
            args = [a for a in args if a != "--json"]
        if len(args) != 1:
            console._print_message(
                "INFO",
                "Usage: app_obfuscation_assessment <directory> [--json]"
            )
            return
        root = args[0]
        if not os.path.isdir(root):
            console._print_message("ERROR", f"Not a directory: {root}")
            return
        console._print_message("INFO", f"Assessing {root} ...")
        assess = _walk_and_assess(root)
        if as_json:
            print(_render_json(root, assess))
        else:
            print(_render_console(root, assess))


def register(registry_func):
    registry_func(AndroidAppObfuscationAssessmentCommand())
