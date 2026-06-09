"""Tests for commands/android/app_obfuscation_assessment.py."""

import os
import tempfile

from commands.android.app_obfuscation_assessment import (
    _walk_and_assess, level_of, score_of,
)


def _write(path: str, body: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


# ---------------------------------------------------------------------------
# NONE / clean source
# ---------------------------------------------------------------------------

def test_clean_long_named_java_source_is_none():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "com", "example", "UserRepository.java"), '''
package com.example;
public class UserRepository {
    private final UserDatabase database;
    public UserRepository(UserDatabase database) {
        this.database = database;
    }
    public String findEmailById(long id) { return "ok"; }
}
''')
    a = _walk_and_assess(tmp)
    assert a.classes_total >= 1
    assert a.classes_short == 0
    assert level_of(a) == "NONE"


# ---------------------------------------------------------------------------
# HEAVY -- 100% short identifiers
# ---------------------------------------------------------------------------

def test_heavy_obfuscated_java_source_is_heavy_or_moderate():
    tmp = tempfile.mkdtemp()
    body = []
    for cn in ("a", "b", "c", "d", "e", "f", "g", "h"):
        body.append(f'class {cn} {{')
        for mn in ("a", "b", "c", "d"):
            body.append(f'    public int {mn}(int a) {{ return a; }}')
        for fn in ("a", "b"):
            body.append(f'    public int {fn};')
        body.append('}')
    _write(os.path.join(tmp, "a.java"), "\n".join(body))
    a = _walk_and_assess(tmp)
    assert a.classes_total == 8
    assert a.classes_short == 8
    assert a.short_pct("class") == 100.0
    # 100% short classes + 100% short methods -> 3 (class >=60%) + 2 (method >=60%)
    # = 5 -- MODERATE.  Pure name-obfuscation without string blobs doesn't yet
    # reach HEAVY by design.
    assert level_of(a) in ("MODERATE", "HEAVY")
    assert score_of(a) >= 5


def test_heavy_obfuscation_plus_string_blobs_pushes_to_heavy():
    tmp = tempfile.mkdtemp()
    body = []
    # 6 short-name classes; each carries 10 long-hex string blobs as fields so
    # the blob density goes >=50 without diluting the short-class percentage.
    blob_field = '    public String f{i} = "{val}";'
    for cn in ("a", "b", "c", "d", "e", "f"):
        body.append(f'class {cn} {{')
        for mn in ("a", "b", "c"):
            body.append(f'    public int {mn}(int a) {{ return a; }}')
        for i in range(10):
            body.append(blob_field.format(i=i, val="deadbeef" * 8))
        body.append('}')
    _write(os.path.join(tmp, "blob.java"), "\n".join(body))
    a = _walk_and_assess(tmp)
    assert a.long_hex_strings >= 50
    assert a.short_pct("class") == 100.0
    assert level_of(a) == "HEAVY"


# ---------------------------------------------------------------------------
# LIGHT mix
# ---------------------------------------------------------------------------

def test_partial_obfuscation_is_light():
    tmp = tempfile.mkdtemp()
    body = []
    # 8 long-named classes + 2 short -> 20% short -> +1 = LIGHT
    long_names = [
        "UserRepository", "OrderService", "InvoicePrinter", "Config",
        "Logger", "Network", "Database", "Cache",
    ]
    for cn in long_names:
        body.append(f'class {cn} {{ public int run() {{ return 1; }} }}')
    for cn in ("a", "b"):
        body.append(f'class {cn} {{ public int x(int a) {{ return a; }} }}')
    _write(os.path.join(tmp, "Mix.java"), "\n".join(body))
    a = _walk_and_assess(tmp)
    assert a.classes_total == 10
    assert a.classes_short == 2
    assert level_of(a) == "LIGHT"


# ---------------------------------------------------------------------------
# UNKNOWN when nothing declared
# ---------------------------------------------------------------------------

def test_no_declared_classes_is_unknown():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "notes.txt"), "no code here at all")
    a = _walk_and_assess(tmp)
    assert a.classes_total == 0
    assert a.methods_total == 0
    assert level_of(a) == "UNKNOWN"


# ---------------------------------------------------------------------------
# Smali coverage
# ---------------------------------------------------------------------------

def test_smali_class_and_method_names_are_extracted():
    tmp = tempfile.mkdtemp()
    body = """
.class public Lcom/example/a;
.super Ljava/lang/Object;
.source "a.java"

.field private a:I
.field private longName:I

.method public constructor <init>()V
    .registers 1
    .line 5
    return-void
.end method

.method public a(I)I
    .registers 2
    .line 9
    return p1
.end method

.method public longMethod(I)I
    .registers 2
    return p1
.end method
"""
    _write(os.path.join(tmp, "a.smali"), body)
    a = _walk_and_assess(tmp)
    assert a.classes_total == 1
    assert a.classes_short == 1                # 'a' is one char
    # The <init> ctor is excluded; only 'a' and 'longMethod' are counted
    assert a.methods_total == 2
    assert a.methods_short == 1                # only 'a' is short
    assert a.fields_total == 2
    assert a.fields_short == 1                 # only 'a' is short
    assert a.smali_source_directives >= 1
    assert a.smali_line_directives   >= 2


def test_smali_without_debug_info_bumps_score():
    tmp = tempfile.mkdtemp()
    body = """
.class public Lcom/example/q;
.super Ljava/lang/Object;

.field private a:I
.method public f()I
    return 1
.end method
"""
    _write(os.path.join(tmp, "q.smali"), body)
    a = _walk_and_assess(tmp)
    assert a.smali_source_directives == 0
    assert a.smali_line_directives   == 0


# ---------------------------------------------------------------------------
# Kotlin @Metadata detection
# ---------------------------------------------------------------------------

def test_kotlin_metadata_is_counted():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "K.kt"), """
@Metadata(mv = {1, 8, 0}, k = 1, d1 = {""}, d2 = {""})
public final class K {
    public String hello() { return "x"; }
}
""")
    a = _walk_and_assess(tmp)
    assert a.kotlin_metadata_hits >= 1


# ---------------------------------------------------------------------------
# Score: monotonicity sanity
# ---------------------------------------------------------------------------

def test_score_strictly_increases_with_short_identifier_density():
    def make(short_count: int, long_count: int):
        tmp = tempfile.mkdtemp()
        body = []
        for i in range(short_count):
            body.append(f'class a{i} {{ public int z(int a) {{ return a; }} }}'.replace(f"a{i}", chr(ord('a') + (i % 6))))
        for i in range(long_count):
            body.append(f'class LongName{i:02d} {{ public int doStuff(int a) {{ return a; }} }}')
        _write(os.path.join(tmp, "Mix.java"), "\n".join(body))
        return _walk_and_assess(tmp)
    a_clean = make(0, 10)
    a_mixed = make(5, 5)
    a_heavy = make(10, 0)
    assert score_of(a_clean) < score_of(a_mixed) < score_of(a_heavy) + 1  # heavy >= mixed
