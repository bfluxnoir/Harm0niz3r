"""Tests for commands/android/app_pinning_check.py."""

import os
import tempfile

from commands.android.app_pinning_check import _walk_and_scan


def _write(path: str, body: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


def test_okhttp_certificate_pinner_is_flagged():
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "com", "example", "Net.java")
    _write(src, '''
package com.example;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;

public class Net {
  public OkHttpClient build() {
    CertificatePinner pinner = new CertificatePinner.Builder()
        .add("api.example.com", "sha256/AAAA...")
        .build();
    return new OkHttpClient.Builder().certificatePinner(pinner).build();
  }
}
''')
    findings = _walk_and_scan(tmp)
    ids = {f.rule for f in findings}
    assert "PINNING_OKHTTP_LIB" in ids
    assert "PINNING_OKHTTP_PIN" in ids


def test_trust_all_certs_pattern_is_high():
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "com", "example", "Bad.java")
    _write(src, '''
package com.example;

import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class Bad {
  public X509TrustManager bypass() {
    return new X509TrustManager() {
      @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
      @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
      @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    };
  }
}
''')
    findings = _walk_and_scan(tmp)
    high = [f for f in findings if f.severity == "HIGH"]
    assert any(f.rule == "TRUST_ALL_CERTS" for f in high), [f.rule for f in findings]


def test_allow_all_hostname_verifier_is_high():
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "Bad2.java")
    _write(src, '''
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

class Bad2 {
  HostnameVerifier allowAll = new HostnameVerifier() {
    @Override public boolean verify(String hostname, SSLSession session) { return true; }
  };
}
''')
    findings = _walk_and_scan(tmp)
    assert any(
        f.rule == "HOSTNAME_VERIFIER_ALLOW_ALL" and f.severity == "HIGH"
        for f in findings
    ), [(f.rule, f.severity) for f in findings]


def test_clean_source_has_no_findings():
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "Clean.java")
    _write(src, 'class Clean { String hello = "world"; }')
    assert _walk_and_scan(tmp) == []


def test_third_party_pinning_libraries_are_info():
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "Net2.java")
    _write(src, '''
import com.datatheorem.android.trustkit.TrustKit;
import com.appmattus.certificatetransparency.CTLoggerKt;
class Net2 {}
''')
    findings = _walk_and_scan(tmp)
    ids = {f.rule for f in findings}
    assert "PINNING_TRUSTKIT" in ids
    assert "PINNING_APPMATTUS_CT" in ids
    # All should be INFO severity
    assert all(f.severity == "INFO" for f in findings if f.rule in ("PINNING_TRUSTKIT", "PINNING_APPMATTUS_CT"))
