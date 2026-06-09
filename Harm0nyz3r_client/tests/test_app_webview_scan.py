"""Tests for commands/android/app_webview_scan.py."""

import os
import tempfile

from commands.android.app_webview_scan import _walk_and_scan


def _write(path: str, body: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


def test_js_enabled_is_medium():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "A.java"), '''
class A {
  void cfg(WebView wv) {
    wv.getSettings().setJavaScriptEnabled(true);
  }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "WEBVIEW_JS_ENABLED" and f.severity == "MEDIUM" for f in findings)


def test_file_access_pair_is_high():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "B.java"), '''
class B {
  void cfg(android.webkit.WebSettings s) {
    s.setAllowFileAccess(true);
    s.setAllowFileAccessFromFileURLs(true);
    s.setAllowUniversalAccessFromFileURLs(true);
  }
}
''')
    rules = {f.rule for f in _walk_and_scan(tmp)}
    assert "WEBVIEW_FILE_ACCESS" in rules
    assert "WEBVIEW_FILE_FROM_FILE_URLS" in rules
    assert "WEBVIEW_UNIVERSAL_ACCESS" in rules


def test_add_javascript_interface_is_high():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "C.java"), '''
class C {
  void bind(android.webkit.WebView wv, Object bridge) {
    wv.addJavascriptInterface(bridge, "AndroidBridge");
  }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "WEBVIEW_JS_INTERFACE" and f.severity == "HIGH" for f in findings)


def test_mixed_content_always_allow_is_medium():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "D.java"), '''
import android.webkit.WebSettings;
class D {
  void cfg(WebSettings s) {
    s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
  }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "WEBVIEW_MIXED_CONTENT_ALLOW" and f.severity == "MEDIUM" for f in findings)


def test_should_override_returning_true_is_medium():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "E.java"), '''
class E extends android.webkit.WebViewClient {
  @Override
  public boolean shouldOverrideUrlLoading(android.webkit.WebView wv, String url) {
    return true;
  }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "WEBVIEW_SHOULD_OVERRIDE_TRUE" and f.severity == "MEDIUM" for f in findings)


def test_clean_source_has_no_findings():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "Clean.java"), '''
class Clean { String hello = "world"; }
''')
    assert _walk_and_scan(tmp) == []


def test_debugging_enabled_is_medium():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "F.java"), '''
class F {
  void init() {
    android.webkit.WebView.setWebContentsDebuggingEnabled(true);
  }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "WEBVIEW_DEBUGGING" and f.severity == "MEDIUM" for f in findings)
