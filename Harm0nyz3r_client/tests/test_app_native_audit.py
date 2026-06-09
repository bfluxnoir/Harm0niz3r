"""Tests for commands/android/app_native_audit.py."""

import io
import os
import struct
import tempfile
import zipfile

from commands.android.app_native_audit import (
    _parse_elf, _audit_path, _STACK_CANARY_PROBE, ET_EXEC, ET_DYN,
    PT_GNU_STACK, PT_GNU_RELRO, PF_X, PF_W, PF_R,
)


# ---------------------------------------------------------------------------
# Tiny synthetic ELF builder so we can test edge cases deterministically.
# ---------------------------------------------------------------------------

def _build_elf64(
    *,
    e_type: int = ET_DYN,
    nx: bool = True,
    relro: bool = True,
    canary: bool = True,
) -> bytes:
    """
    Build a minimal-but-valid-looking ELF64 little-endian binary that the
    parser can chew on.  Not loadable / runnable -- just enough header
    structure for the audit.
    """
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # 16 bytes
    e_phnum = 2  # GNU_STACK + (optional) GNU_RELRO
    if relro:
        e_phnum = 2
    else:
        e_phnum = 1
    e_phentsize = 56
    e_ehsize = 64
    e_phoff = 64

    # Header
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,         # e_type
        0xB7,           # e_machine (AARCH64)
        1,              # e_version
        0,              # e_entry
        e_phoff,        # e_phoff
        0,              # e_shoff
        0,              # e_flags
        e_ehsize,       # e_ehsize
        e_phentsize,    # e_phentsize
        e_phnum,        # e_phnum
        64,             # e_shentsize
        0,              # e_shnum
        0,              # e_shstrndx
    )

    # PT_GNU_STACK
    p_flags = (PF_R | PF_W) | (PF_X if not nx else 0)
    phdr1 = struct.pack(
        "<IIQQQQQQ",
        PT_GNU_STACK,   # p_type
        p_flags,        # p_flags
        0,              # p_offset
        0,              # p_vaddr
        0,              # p_paddr
        0,              # p_filesz
        0,              # p_memsz
        0,              # p_align
    )

    phdrs = phdr1
    if relro:
        phdr2 = struct.pack(
            "<IIQQQQQQ",
            PT_GNU_RELRO,
            PF_R,
            0, 0, 0, 0, 0, 0,
        )
        phdrs += phdr2

    body = e_ident + header + phdrs
    # Optional canary marker so the raw-byte scan picks it up
    if canary:
        body += b"\x00" * 16 + _STACK_CANARY_PROBE + b"\x00" * 16
    return body


# ---------------------------------------------------------------------------
# Synthetic ELF unit tests
# ---------------------------------------------------------------------------

def test_pie_yes_nx_yes_relro_partial_canary_yes():
    blob = _build_elf64(e_type=ET_DYN, nx=True, relro=True, canary=True)
    r = _parse_elf(blob, "synth.so")
    assert r.ok
    assert r.pie is True
    assert r.nx is True
    assert r.relro in ("PARTIAL", "FULL")
    assert r.stack_canary is True
    pie_ids = {f.rule for f in r.findings}
    assert "NATIVE_PIE_MISSING" not in pie_ids
    assert "NATIVE_NX_MISSING" not in pie_ids


def test_no_pie_is_high_finding():
    blob = _build_elf64(e_type=ET_EXEC)
    r = _parse_elf(blob, "synth_no_pie.so")
    assert r.pie is False
    assert any(f.rule == "NATIVE_PIE_MISSING" and f.severity == "HIGH" for f in r.findings)


def test_executable_stack_is_high_finding():
    blob = _build_elf64(nx=False)
    r = _parse_elf(blob, "synth_nx.so")
    assert r.nx is False
    assert any(f.rule == "NATIVE_NX_MISSING" and f.severity == "HIGH" for f in r.findings)


def test_no_relro_is_high_finding():
    blob = _build_elf64(relro=False)
    r = _parse_elf(blob, "synth_relro.so")
    assert r.relro == "NONE"
    assert any(f.rule == "NATIVE_RELRO_MISSING" and f.severity == "HIGH" for f in r.findings)


def test_missing_canary_is_medium_finding():
    blob = _build_elf64(canary=False)
    r = _parse_elf(blob, "synth_canary.so")
    assert r.stack_canary is False
    assert any(f.rule == "NATIVE_STACK_CANARY_MISSING" and f.severity == "MEDIUM" for f in r.findings)


def test_bogus_input_is_marked_not_ok():
    r = _parse_elf(b"not-an-elf-at-all", "bogus")
    assert r.ok is False
    assert r.error == "Not an ELF file"


# ---------------------------------------------------------------------------
# Live system libc.so test (skipped if the file isn't available)
# ---------------------------------------------------------------------------

_LIBC_PATH = os.path.join(
    os.path.dirname(__file__),
    "..", "..", ".scratch", "sos", "libc.so",
)
_LIBC_PATH = os.path.abspath(_LIBC_PATH)


def test_real_libc_is_hardened_if_available():
    if not os.path.isfile(_LIBC_PATH):
        return
    with open(_LIBC_PATH, "rb") as f:
        data = f.read()
    r = _parse_elf(data, _LIBC_PATH)
    assert r.ok, r.error
    assert r.elf_class == "ELF64"
    # A modern Android system libc should have all the boxes ticked.
    assert r.pie is True
    assert r.nx is True
    assert r.relro in ("PARTIAL", "FULL")
    assert r.stack_canary is True


# ---------------------------------------------------------------------------
# APK / directory dispatch
# ---------------------------------------------------------------------------

def test_audit_path_walks_directory_for_so_files():
    tmp = tempfile.mkdtemp()
    so_dir = os.path.join(tmp, "lib", "arm64-v8a")
    os.makedirs(so_dir)
    blob = _build_elf64()
    so_path = os.path.join(so_dir, "libfoo.so")
    with open(so_path, "wb") as f:
        f.write(blob)
    reports = _audit_path(tmp)
    assert len(reports) == 1
    assert reports[0].path.endswith("libfoo.so")
    assert reports[0].ok


def test_audit_path_reads_so_files_inside_an_apk():
    tmp = tempfile.mkdtemp()
    apk_path = os.path.join(tmp, "fake.apk")
    blob = _build_elf64(e_type=ET_DYN, nx=True, relro=False, canary=False)
    with zipfile.ZipFile(apk_path, "w") as zf:
        # Mimic the real APK layout.  Non-.so files are ignored.
        zf.writestr("lib/arm64-v8a/libfoo.so", blob)
        zf.writestr("classes.dex", b"\x00\x01\x02")
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
    reports = _audit_path(apk_path)
    assert len(reports) == 1
    assert reports[0].path.startswith("lib/")
    # The synthetic blob had no PT_GNU_RELRO -> NONE
    assert reports[0].relro == "NONE"


def test_audit_path_handles_single_so_file():
    tmp = tempfile.mkdtemp()
    so_path = os.path.join(tmp, "lone.so")
    with open(so_path, "wb") as f:
        f.write(_build_elf64())
    reports = _audit_path(so_path)
    assert len(reports) == 1
    assert reports[0].ok


def test_audit_path_returns_empty_when_nothing_found():
    tmp = tempfile.mkdtemp()
    # plain text file -> ignored by .so suffix filter
    with open(os.path.join(tmp, "readme.txt"), "w", encoding="utf-8") as f:
        f.write("hi")
    assert _audit_path(tmp) == []
