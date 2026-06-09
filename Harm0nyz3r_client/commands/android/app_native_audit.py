# -*- coding: utf-8 -*-
# commands/android/app_native_audit.py
"""
app_native_audit - check the security hardening flags of every native
library (.so) shipped inside an Android APK, or any loose .so file the
user points at.

Hardening flags we look at (V1)
  PIE                ELF header e_type must be ET_DYN.  ET_EXEC = no PIE.
  NX                 PT_GNU_STACK program header must NOT carry PF_X.
                     No PT_GNU_STACK at all means the linker decides --
                     reported as NX_UNKNOWN.
  RELRO              PT_GNU_RELRO present:
                       PARTIAL  PT_GNU_RELRO without DT_BIND_NOW /
                                DF_BIND_NOW / DF_1_NOW
                       FULL     PT_GNU_RELRO + any of the BIND_NOW
                                signals
                     No PT_GNU_RELRO at all means no RELRO.
  STACK_CANARY       Raw-byte search for the symbol name
                     '__stack_chk_fail' anywhere in the file -- the
                     linker keeps the symbol string in .dynstr.
  FORTIFY_SOURCE     Raw-byte search for any well-known FORTIFY runtime
                     symbol ('_chk' suffix, e.g. __strcpy_chk).

V1 is intentionally stdlib-only (struct + zipfile) so no extra Python
dependencies are needed.  The raw-byte search for canary / FORTIFY is a
heuristic but matches what readelf-based shell checks actually do.
"""

import json
import os
import re
import struct
import zipfile
from typing import List, Optional, Tuple

from commands.base import Command, CommandSource


# ---------------------------------------------------------------------------
# ELF constants
# ---------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"

ET_EXEC = 2
ET_DYN  = 3

# Standard program-header types
PT_LOAD       = 1
PT_DYNAMIC    = 2
PT_GNU_STACK  = 0x6474E551
PT_GNU_RELRO  = 0x6474E552

PF_X = 1
PF_W = 2
PF_R = 4

# Dynamic-section tags
DT_NULL      = 0
DT_FLAGS     = 30
DT_FLAGS_1   = 0x6FFFFFFB
DT_BIND_NOW  = 24

DF_BIND_NOW = 0x8
DF_1_NOW    = 0x1

# FORTIFY runtime symbols we search for.  Not exhaustive; finding *any*
# means the binary was built with at least one fortified replacement.
_FORTIFY_PROBES = (
    b"__strcpy_chk\x00",
    b"__strcat_chk\x00",
    b"__memcpy_chk\x00",
    b"__memmove_chk\x00",
    b"__sprintf_chk\x00",
    b"__snprintf_chk\x00",
    b"__strncpy_chk\x00",
    b"__strncat_chk\x00",
    b"__read_chk\x00",
    b"__fgets_chk\x00",
    b"__vsprintf_chk\x00",
)

_STACK_CANARY_PROBE = b"__stack_chk_fail\x00"


# ---------------------------------------------------------------------------
# Finding shape
# ---------------------------------------------------------------------------

class NativeFinding:
    __slots__ = ("rule", "severity", "file", "detail")

    def __init__(self, rule, severity, file, detail):
        self.rule = rule
        self.severity = severity
        self.file = file
        self.detail = detail

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


class NativeReport:
    """One audited .so plus the findings derived from it."""
    __slots__ = ("path", "ok", "error", "elf_class", "pie", "nx", "relro",
                 "stack_canary", "fortify", "findings")

    def __init__(self, path):
        self.path = path
        self.ok = False
        self.error: Optional[str] = None
        self.elf_class: Optional[str] = None
        self.pie: Optional[bool] = None
        self.nx: Optional[bool] = None
        self.relro: Optional[str] = None       # "FULL" / "PARTIAL" / "NONE"
        self.stack_canary: Optional[bool] = None
        self.fortify: Optional[bool] = None
        self.findings: List[NativeFinding] = []

    def to_dict(self) -> dict:
        return {
            "path":          self.path,
            "ok":            self.ok,
            "error":         self.error,
            "elf_class":     self.elf_class,
            "pie":           self.pie,
            "nx":            self.nx,
            "relro":         self.relro,
            "stack_canary":  self.stack_canary,
            "fortify":       self.fortify,
            "findings":      [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# ELF parsing
# ---------------------------------------------------------------------------

def _parse_elf(data: bytes, path: str) -> NativeReport:
    rep = NativeReport(path)

    if len(data) < 64 or data[:4] != ELF_MAGIC:
        rep.error = "Not an ELF file"
        return rep

    ei_class = data[4]
    ei_data  = data[5]
    if ei_class not in (1, 2):
        rep.error = f"Unsupported EI_CLASS {ei_class}"
        return rep
    if ei_data not in (1, 2):
        rep.error = f"Unsupported EI_DATA {ei_data}"
        return rep

    is_64 = (ei_class == 2)
    endian = "<" if ei_data == 1 else ">"
    rep.elf_class = "ELF64" if is_64 else "ELF32"

    # ELF header layouts (after the 16-byte e_ident):
    #   ELF32: H H I I I I I H H H H H H        (40 bytes -> total 56)
    #   ELF64: H H I Q Q Q I H H H H H H        (48 bytes -> total 64)
    try:
        if is_64:
            header = struct.unpack(
                endian + "HHIQQQIHHHHHH",
                data[16:64],
            )
        else:
            header = struct.unpack(
                endian + "HHIIIIIHHHHHH",
                data[16:52],
            )
    except struct.error as e:
        rep.error = f"Bad ELF header: {e}"
        return rep

    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
     e_shstrndx) = header

    # --- PIE ---
    rep.pie = (e_type == ET_DYN)

    # --- Program headers (NX / RELRO) ---
    pt_gnu_stack_flags: Optional[int] = None
    pt_gnu_relro_present = False
    pt_dynamic_offset: Optional[int] = None
    pt_dynamic_filesz: Optional[int] = None

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        try:
            if is_64:
                ph = struct.unpack(
                    endian + "IIQQQQQQ",
                    data[off:off + 56],
                )
                (p_type, p_flags, p_offset, p_vaddr, p_paddr,
                 p_filesz, p_memsz, p_align) = ph
            else:
                ph = struct.unpack(
                    endian + "IIIIIIII",
                    data[off:off + 32],
                )
                (p_type, p_offset, p_vaddr, p_paddr,
                 p_filesz, p_memsz, p_flags, p_align) = ph
        except struct.error:
            continue

        if p_type == PT_GNU_STACK:
            pt_gnu_stack_flags = p_flags
        elif p_type == PT_GNU_RELRO:
            pt_gnu_relro_present = True
        elif p_type == PT_DYNAMIC:
            pt_dynamic_offset = p_offset
            pt_dynamic_filesz = p_filesz

    if pt_gnu_stack_flags is None:
        rep.nx = None  # unknown -> linker default
    else:
        rep.nx = not bool(pt_gnu_stack_flags & PF_X)

    # --- Walk PT_DYNAMIC to learn whether BIND_NOW is set ---
    bind_now = False
    if pt_dynamic_offset is not None and pt_dynamic_filesz:
        end = pt_dynamic_offset + pt_dynamic_filesz
        dyn_step = 16 if is_64 else 8
        dyn_fmt = endian + ("qQ" if is_64 else "iI")
        cursor = pt_dynamic_offset
        while cursor + dyn_step <= end and cursor + dyn_step <= len(data):
            try:
                d_tag, d_val = struct.unpack(dyn_fmt, data[cursor:cursor + dyn_step])
            except struct.error:
                break
            cursor += dyn_step
            if d_tag == DT_NULL:
                break
            if d_tag == DT_BIND_NOW:
                bind_now = True
            elif d_tag == DT_FLAGS and (d_val & DF_BIND_NOW):
                bind_now = True
            elif d_tag == DT_FLAGS_1 and (d_val & DF_1_NOW):
                bind_now = True

    if pt_gnu_relro_present and bind_now:
        rep.relro = "FULL"
    elif pt_gnu_relro_present:
        rep.relro = "PARTIAL"
    else:
        rep.relro = "NONE"

    # --- Stack canary + FORTIFY (string-table scan via raw bytes) ---
    rep.stack_canary = _STACK_CANARY_PROBE in data
    rep.fortify = any(p in data for p in _FORTIFY_PROBES)

    rep.ok = True

    # --- Findings ---
    base = os.path.basename(path)
    if rep.pie is False:
        rep.findings.append(NativeFinding(
            "NATIVE_PIE_MISSING", "HIGH", base,
            "ELF header e_type is ET_EXEC; binary is not PIE.",
        ))
    if rep.nx is False:
        rep.findings.append(NativeFinding(
            "NATIVE_NX_MISSING", "HIGH", base,
            "PT_GNU_STACK carries the PF_X flag; stack is executable.",
        ))
    elif rep.nx is None:
        rep.findings.append(NativeFinding(
            "NATIVE_NX_UNKNOWN", "LOW", base,
            "No PT_GNU_STACK program header; linker default applies (usually NX, "
            "but worth confirming).",
        ))
    if rep.relro == "NONE":
        rep.findings.append(NativeFinding(
            "NATIVE_RELRO_MISSING", "HIGH", base,
            "No PT_GNU_RELRO segment; GOT is writeable for the life of the process.",
        ))
    elif rep.relro == "PARTIAL":
        rep.findings.append(NativeFinding(
            "NATIVE_RELRO_PARTIAL", "MEDIUM", base,
            "PT_GNU_RELRO present but no BIND_NOW; PLT GOT entries remain writeable.",
        ))
    if rep.stack_canary is False:
        rep.findings.append(NativeFinding(
            "NATIVE_STACK_CANARY_MISSING", "MEDIUM", base,
            "No __stack_chk_fail symbol; stack canaries are disabled.",
        ))
    if rep.fortify is False:
        rep.findings.append(NativeFinding(
            "NATIVE_FORTIFY_MISSING", "LOW", base,
            "No fortified runtime symbols (*_chk).  Build with -D_FORTIFY_SOURCE=2.",
        ))
    return rep


# ---------------------------------------------------------------------------
# Discovery: dir of .so files OR an APK
# ---------------------------------------------------------------------------

def _audit_path(path: str) -> List[NativeReport]:
    if os.path.isdir(path):
        return _audit_dir(path)
    if os.path.isfile(path):
        if path.lower().endswith(".apk") or _looks_like_zip(path):
            return _audit_apk(path)
        with open(path, "rb") as f:
            return [_parse_elf(f.read(), path)]
    return []


def _audit_dir(root: str) -> List[NativeReport]:
    out: List[NativeReport] = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            if name.lower().endswith(".so"):
                full = os.path.join(dirpath, name)
                try:
                    with open(full, "rb") as f:
                        out.append(_parse_elf(f.read(), full))
                except OSError as e:
                    rep = NativeReport(full)
                    rep.error = f"OSError: {e}"
                    out.append(rep)
    return out


def _audit_apk(apk_path: str) -> List[NativeReport]:
    out: List[NativeReport] = []
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for info in zf.infolist():
                if info.filename.startswith("lib/") and info.filename.endswith(".so"):
                    with zf.open(info) as f:
                        out.append(_parse_elf(f.read(), info.filename))
    except zipfile.BadZipFile as e:
        rep = NativeReport(apk_path)
        rep.error = f"Bad ZIP / APK: {e}"
        out.append(rep)
    return out


def _looks_like_zip(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"PK\x03\x04"
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_BOLD = "\033[1m"
_DIM = "\033[2m"
_RST = "\033[0m"
_GREEN = "\033[1;92m"
_YELLOW = "\033[1;93m"
_RED = "\033[1;91m"
_SEV_COLOR = {
    "HIGH":   "\033[1;91m",
    "MEDIUM": "\033[1;93m",
    "LOW":    "\033[1;94m",
    "INFO":   "\033[1;90m",
}


def _tag(value):
    if value is True:
        return f"{_GREEN}YES{_RST}"
    if value is False:
        return f"{_RED}NO{_RST}"
    return f"{_YELLOW}UNKNOWN{_RST}"


def _relro_tag(value):
    if value == "FULL":
        return f"{_GREEN}FULL{_RST}"
    if value == "PARTIAL":
        return f"{_YELLOW}PARTIAL{_RST}"
    if value == "NONE":
        return f"{_RED}NONE{_RST}"
    return f"{_DIM}?{_RST}"


def _render_console(root: str, reports: List[NativeReport]) -> str:
    sep = "=" * 60
    lines = [
        sep,
        f"{_BOLD}NATIVE LIB AUDIT  {root}{_RST}",
        sep,
        f"  Libraries : {len(reports)} audited",
        "-" * 60,
    ]
    if not reports:
        lines.append("  No native libraries found.")
        lines.append(sep)
        return "\n".join(lines)
    for r in reports:
        lines.append("")
        if not r.ok:
            lines.append(f"  {_RED}[error]{_RST} {r.path}")
            lines.append(f"          {_DIM}{r.error}{_RST}")
            continue
        lines.append(f"  {_BOLD}{r.path}{_RST}  ({r.elf_class})")
        lines.append(
            f"          PIE={_tag(r.pie)}  NX={_tag(r.nx)}  "
            f"RELRO={_relro_tag(r.relro)}  "
            f"Canary={_tag(r.stack_canary)}  FORTIFY={_tag(r.fortify)}"
        )
        for f in r.findings:
            color = _SEV_COLOR.get(f.severity, "")
            lines.append(f"          [{color}{f.severity}{_RST}] {f.rule}: {f.detail}")
    lines.append("")
    lines.append(sep)
    return "\n".join(lines)


def _render_json(root: str, reports: List[NativeReport]) -> str:
    return json.dumps({
        "root":      root,
        "reports":   [r.to_dict() for r in reports],
        "counts":    {
            "total":      len(reports),
            "ok":         sum(1 for r in reports if r.ok),
            "errored":    sum(1 for r in reports if not r.ok),
        },
    }, indent=2)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class AndroidAppNativeAuditCommand(Command):
    @property
    def name(self) -> str:
        return "app_native_audit"

    def help(self) -> str:
        return (
            "app_native_audit <path> [--json]\n"
            "  Audit native libraries for hardening flags.  <path> can be:\n"
            "    - an APK file:   unzips lib/*/*.so in place\n"
            "    - a .so file:    audited directly\n"
            "    - a directory:   recursively audits every .so beneath it\n"
            "  Checks: PIE, NX, RELRO (full / partial / none), stack canary,\n"
            "  FORTIFY_SOURCE.\n"
            "  --json  Emit JSON instead of the console table.\n\n"
            "Examples:\n"
            "  app_native_audit ./pulled-apks/com.example.target/base.apk\n"
            "  app_native_audit ./decompiled/com.example.target/_apk/lib/\n"
            "  app_native_audit /tmp/libfoo.so --json"
        )

    def execute(self, console, args: List[str], source: CommandSource) -> None:
        as_json = False
        if "--json" in args:
            as_json = True
            args = [a for a in args if a != "--json"]
        if len(args) != 1:
            console._print_message("INFO", "Usage: app_native_audit <path> [--json]")
            return
        path = args[0]
        if not os.path.exists(path):
            console._print_message("ERROR", f"Path not found: {path}")
            return
        console._print_message("INFO", f"Auditing native libraries under {path} ...")
        reports = _audit_path(path)
        if as_json:
            print(_render_json(path, reports))
        else:
            print(_render_console(path, reports))


def register(registry_func):
    registry_func(AndroidAppNativeAuditCommand())
