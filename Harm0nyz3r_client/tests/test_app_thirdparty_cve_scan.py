"""Tests for commands/android/app_thirdparty_cve_scan.py."""

import json
import os
import tempfile

from commands.android.app_thirdparty_cve_scan import (
    _load_db, _detect_libraries, _build_findings, _search_terms, _DB_PATH,
)


def _write(path: str, body: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


# ---------------------------------------------------------------------------
# Bundled DB sanity
# ---------------------------------------------------------------------------

def test_db_loads_and_has_expected_libraries():
    db = _load_db()
    assert db["version"] >= 1
    names = {lib["name"] for lib in db["libraries"]}
    expected_subset = {
        "OkHttp 3.x",
        "Apache Commons Collections 3.x",
        "Bouncy Castle",
        "Jackson Databind",
        "jsoup",
        "SQLCipher Android",
        "Volley (com.android.volley)",
    }
    missing = expected_subset - names
    assert not missing, f"missing libraries in bundled DB: {missing}"


def test_every_cve_entry_has_required_fields():
    db = _load_db()
    for lib in db["libraries"]:
        for cve in lib.get("cves", []):
            assert cve.get("id"), f"CVE in {lib['name']} missing id"
            assert cve.get("fixed_in"), f"{cve['id']} missing fixed_in"
            assert cve.get("severity") in ("HIGH", "MEDIUM", "LOW", "INFO")
            assert cve.get("summary"), f"{cve['id']} missing summary"


# ---------------------------------------------------------------------------
# _search_terms
# ---------------------------------------------------------------------------

def test_search_terms_emits_both_dot_and_slash_forms():
    t = _search_terms("okhttp3.OkHttpClient")
    assert "okhttp3.OkHttpClient" in t
    assert "okhttp3/OkHttpClient" in t


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_okhttp_import_is_detected_from_java_source():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "Net.java"), '''
import okhttp3.OkHttpClient;
class Net { OkHttpClient c = new OkHttpClient(); }
''')
    found = _detect_libraries(tmp, _load_db())
    assert "OkHttp 3.x" in found
    assert any("Net.java" in f for f in found["OkHttp 3.x"]["files"])


def test_smali_class_reference_is_detected():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "X.smali"), '''
.class public Lcom/example/X;
.super Ljava/lang/Object;

.method public f()Lokhttp3/OkHttpClient;
    return-object v0
.end method
''')
    found = _detect_libraries(tmp, _load_db())
    assert "OkHttp 3.x" in found


def test_apache_commons_collections_invokertransformer_is_detected():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "S.java"), '''
import org.apache.commons.collections.functors.InvokerTransformer;
class S { Object x; }
''')
    found = _detect_libraries(tmp, _load_db())
    assert "Apache Commons Collections 3.x" in found


def test_clean_source_finds_no_libraries():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "Clean.java"), '''
class Clean { String greeting = "hello"; }
''')
    found = _detect_libraries(tmp, _load_db())
    assert found == {}


# ---------------------------------------------------------------------------
# Finding generation
# ---------------------------------------------------------------------------

def test_findings_attach_cves_for_libraries_with_known_cves():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "Net.java"), 'import okhttp3.OkHttpClient;')
    findings = _build_findings(_detect_libraries(tmp, _load_db()))
    assert findings, "expected at least one finding for OkHttp"
    cve_ids = {f.cve_id for f in findings if f.cve_id}
    assert "CVE-2018-20200" in cve_ids
    assert "CVE-2021-0341" in cve_ids
    # Severities should be carried through from the DB entry
    for f in findings:
        if f.cve_id == "CVE-2018-20200":
            assert f.severity in ("HIGH", "MEDIUM")


def test_finding_for_library_with_no_cves_is_info():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "Pic.java"), 'import com.squareup.picasso.Picasso;')
    findings = _build_findings(_detect_libraries(tmp, _load_db()))
    assert any(
        f.library == "Picasso" and f.severity == "INFO" and not f.cve_id
        for f in findings
    )


def test_finding_carries_file_list():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "a", "Net.java"), 'import okhttp3.OkHttpClient;')
    _write(os.path.join(tmp, "b", "Net2.java"), 'import okhttp3.OkHttpClient;')
    findings = _build_findings(_detect_libraries(tmp, _load_db()))
    okhttp = [f for f in findings if f.library == "OkHttp 3.x"]
    assert okhttp
    # Both files should appear in the file list of every OkHttp finding
    for f in okhttp:
        joined = "|".join(f.files)
        assert "Net.java" in joined
        assert "Net2.java" in joined


# ---------------------------------------------------------------------------
# Module-level DB path
# ---------------------------------------------------------------------------

def test_db_path_exists():
    assert os.path.isfile(_DB_PATH)
