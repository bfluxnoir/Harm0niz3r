"""Tests for commands/android/app_root_detection_scan.py."""

import os
import tempfile

from commands.android.app_root_detection_scan import _walk_and_scan


def _write(path: str, body: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


def _ids(findings):
    return {f.rule for f in findings}


# ---------------------------------------------------------------------------
# Library + 3rd-party detector references
# ---------------------------------------------------------------------------

def test_rootbeer_import_is_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "A.java"), '''
import com.scottyab.rootbeer.RootBeer;
class A { boolean f() { return new RootBeer(null).isRooted(); } }
''')
    assert "ROOT_LIB_ROOTBEER" in _ids(_walk_and_scan(tmp))


def test_roottools_static_call_is_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "B.java"), '''
import com.stericson.RootTools.RootTools;
class B { boolean f() { return RootTools.isAccessGiven(); } }
''')
    assert "ROOT_LIB_ROOTTOOLS" in _ids(_walk_and_scan(tmp))


def test_safetynet_reference_is_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "C.java"), '''
import com.google.android.gms.safetynet.SafetyNetApi;
class C { void f() { SafetyNetApi.attest("xyz", null); } }
''')
    assert "ROOT_LIB_SAFETYNET" in _ids(_walk_and_scan(tmp))


# ---------------------------------------------------------------------------
# File path / package literals
# ---------------------------------------------------------------------------

def test_su_binary_literal_is_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "D.java"), '''
class D {
  String[] PATHS = new String[] {
    "/system/bin/su",
    "/sbin/su",
    "/vendor/bin/su"
  };
}
''')
    assert "ROOT_SU_BINARY_PATH" in _ids(_walk_and_scan(tmp))


def test_magisk_file_literal_is_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "E.java"), '''
class E {
  String M = "/data/adb/magisk";
  String N = "/sbin/magisk";
}
''')
    assert "ROOT_MAGISK_FILE_REF" in _ids(_walk_and_scan(tmp))


def test_magisk_package_check_is_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "F.java"), '''
class F {
  String pkg = "com.topjohnwu.magisk";
  String su  = "eu.chainfire.supersu";
}
''')
    rules = _ids(_walk_and_scan(tmp))
    assert "ROOT_MAGISK_PKG_CHECK" in rules


# ---------------------------------------------------------------------------
# Build / system property heuristics
# ---------------------------------------------------------------------------

def test_build_tags_testkeys_is_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "G.java"), '''
import android.os.Build;
class G {
  boolean f() { return Build.TAGS != null && Build.TAGS.contains("test-keys"); }
}
''')
    rules = _ids(_walk_and_scan(tmp))
    assert "ROOT_BUILD_TAGS_TESTKEYS" in rules


def test_ro_debuggable_check_is_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "H.java"), '''
import android.os.SystemProperties;
class H { String d = SystemProperties.get("ro.debuggable", "0"); }
''')
    rules = _ids(_walk_and_scan(tmp))
    assert "ROOT_SYSPROP_DEBUGGABLE" in rules


def test_ro_secure_check_is_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "I.java"), '''
class I { String s = "ro.secure"; }
''')
    assert "ROOT_SYSPROP_SECURE" in _ids(_walk_and_scan(tmp))


# ---------------------------------------------------------------------------
# Process-exec heuristics
# ---------------------------------------------------------------------------

def test_runtime_exec_which_su_is_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "J.java"), '''
import java.lang.Runtime;
class J {
  Process p() throws Exception {
    return Runtime.getRuntime().exec("which su");
  }
}
''')
    assert "ROOT_RUNTIME_EXEC_SU" in _ids(_walk_and_scan(tmp))


# ---------------------------------------------------------------------------
# Negative case
# ---------------------------------------------------------------------------

def test_clean_source_has_no_findings():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "Clean.java"), '''
class Clean { String greeting = "hello, world!"; }
''')
    assert _walk_and_scan(tmp) == []
