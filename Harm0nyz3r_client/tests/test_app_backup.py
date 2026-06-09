"""Tests for commands/android/app_backup.py."""

import io
import os
import tarfile
import tempfile
import zlib

import pytest

from commands.android.app_backup import ab_to_tar, _AB_MAGIC


def _build_tar(entries):
    """entries: list of (name, body_bytes)"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, body in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def _wrap_ab(tar_bytes, *, compressed=True, encryption="none", version=5):
    header = (
        _AB_MAGIC
        + f"{version}\n".encode("ascii")
        + (b"1\n" if compressed else b"0\n")
        + (encryption + "\n").encode("ascii")
    )
    if compressed:
        body = zlib.compress(tar_bytes)
    else:
        body = tar_bytes
    return header + body


# ---------------------------------------------------------------------------
# ab_to_tar happy paths
# ---------------------------------------------------------------------------

def test_compressed_plaintext_ab_round_trips_back_to_tar_bytes():
    tar = _build_tar([("apps/com.example/sp/foo.xml", b"<root>hi</root>")])
    ab = _wrap_ab(tar, compressed=True, encryption="none")
    out = ab_to_tar(ab)
    assert out == tar
    # The recovered tar must actually open
    with tarfile.open(fileobj=io.BytesIO(out), mode="r:") as tf:
        names = tf.getnames()
        assert names == ["apps/com.example/sp/foo.xml"]


def test_uncompressed_plaintext_ab_just_strips_header():
    tar = _build_tar([("apps/com.example/databases/a.db", b"hello")])
    ab = _wrap_ab(tar, compressed=False, encryption="none")
    assert ab_to_tar(ab) == tar


def test_blank_encryption_field_is_treated_as_none():
    tar = _build_tar([("a", b"b")])
    ab = (
        _AB_MAGIC + b"5\n" + b"0\n" + b"\n" + tar  # empty encryption line
    )
    assert ab_to_tar(ab) == tar


# ---------------------------------------------------------------------------
# Error / refusal paths
# ---------------------------------------------------------------------------

def test_missing_magic_header_raises():
    with pytest.raises(ValueError, match="ANDROID BACKUP"):
        ab_to_tar(b"NOT AN AB" + b"\n" * 5)


def test_truncated_header_raises():
    with pytest.raises(ValueError, match="Truncated"):
        ab_to_tar(_AB_MAGIC + b"5\n0\n")  # missing encryption line


def test_unsupported_version_raises():
    body = _AB_MAGIC + b"99\n0\nnone\n" + b"contents"
    with pytest.raises(ValueError, match="Unsupported .ab version"):
        ab_to_tar(body)


def test_encrypted_ab_is_refused_with_abe_hint():
    fake = _AB_MAGIC + b"5\n1\nAES-256\nsalt-blob"
    with pytest.raises(ValueError, match=r"abe\.jar"):
        ab_to_tar(fake)


def test_bad_compression_payload_raises_value_error():
    # Header says compressed, body is junk
    bad = _AB_MAGIC + b"5\n1\nnone\n" + b"this isn't valid zlib"
    with pytest.raises(ValueError, match="inflate"):
        ab_to_tar(bad)


# ---------------------------------------------------------------------------
# End-to-end: write an .ab to disk, convert to .tar, extract, walk
# ---------------------------------------------------------------------------

def test_writing_ab_and_round_tripping_through_tar_extraction(tmp_path):
    tar = _build_tar([
        ("apps/com.example/sp/prefs.xml", b'<map><string name="t">abc</string></map>'),
        ("apps/com.example/files/cache.dat", b"\x00\x01\x02"),
    ])
    ab = _wrap_ab(tar, compressed=True)

    ab_file = tmp_path / "x.ab"
    ab_file.write_bytes(ab)

    tar_bytes = ab_to_tar(ab_file.read_bytes())
    tar_file = tmp_path / "x.tar"
    tar_file.write_bytes(tar_bytes)

    extract_dir = tmp_path / "out"
    with tarfile.open(tar_file, "r:") as tf:
        try:
            tf.extractall(extract_dir, filter="data")
        except TypeError:
            tf.extractall(extract_dir)

    rel_paths = sorted(
        os.path.relpath(os.path.join(d, f), extract_dir).replace("\\", "/")
        for d, _, fs in os.walk(extract_dir) for f in fs
    )
    assert rel_paths == [
        "apps/com.example/files/cache.dat",
        "apps/com.example/sp/prefs.xml",
    ]
    with open(extract_dir / "apps" / "com.example" / "sp" / "prefs.xml",
              "r", encoding="utf-8") as f:
        content = f.read()
    assert "abc" in content
