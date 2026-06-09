"""Tests for commands/android/app_crypto_scan.py."""

import os
import tempfile

from commands.android.app_crypto_scan import _walk_and_scan


def _write(path: str, body: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


def test_des_cipher_is_high():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "A.java"), '''
import javax.crypto.Cipher;
class A {
  Cipher c() throws Exception {
    return Cipher.getInstance("DES/CBC/PKCS5Padding");
  }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "CRYPTO_DES_CIPHER" and f.severity == "HIGH" for f in findings)


def test_aes_ecb_mode_is_high():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "B.java"), '''
import javax.crypto.Cipher;
class B {
  Cipher c() throws Exception {
    return Cipher.getInstance("AES/ECB/NoPadding");
  }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "CRYPTO_AES_ECB_MODE" and f.severity == "HIGH" for f in findings)


def test_default_aes_is_medium():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "C.java"), '''
import javax.crypto.Cipher;
class C {
  Cipher c() throws Exception { return Cipher.getInstance("AES"); }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "CRYPTO_AES_DEFAULT_MODE" and f.severity == "MEDIUM" for f in findings)


def test_md5_and_sha1_hashes_are_flagged():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "D.java"), '''
import java.security.MessageDigest;
class D {
  byte[] md5(byte[] x) throws Exception {
    return MessageDigest.getInstance("MD5").digest(x);
  }
  byte[] sha1(byte[] x) throws Exception {
    return MessageDigest.getInstance("SHA-1").digest(x);
  }
}
''')
    rules = {f.rule for f in _walk_and_scan(tmp)}
    assert "CRYPTO_MD5_HASH" in rules
    assert "CRYPTO_SHA1_HASH" in rules


def test_insecure_random_is_medium():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "E.java"), '''
import java.util.Random;
class E {
  int nonce() { return new Random().nextInt(); }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "CRYPTO_INSECURE_RANDOM" and f.severity == "MEDIUM" for f in findings)


def test_zero_iv_is_high():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "F.java"), '''
import javax.crypto.spec.IvParameterSpec;
class F {
  IvParameterSpec iv() { return new IvParameterSpec(new byte[16]); }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "CRYPTO_ZERO_IV" and f.severity == "HIGH" for f in findings)


def test_hardcoded_secret_key_is_high():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "G.java"), '''
import javax.crypto.spec.SecretKeySpec;
class G {
  SecretKeySpec k1() { return new SecretKeySpec("0123456789ABCDEF".getBytes(), "AES"); }
  SecretKeySpec k2() { return new SecretKeySpec(new byte[]{1,2,3,4,5,6,7,8}, "DES"); }
}
''')
    findings = _walk_and_scan(tmp)
    assert sum(1 for f in findings if f.rule == "CRYPTO_HARDCODED_KEY" and f.severity == "HIGH") >= 1


def test_weak_keygen_is_high():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "H.java"), '''
import javax.crypto.KeyGenerator;
class H {
  KeyGenerator kg() throws Exception { return KeyGenerator.getInstance("DES"); }
}
''')
    findings = _walk_and_scan(tmp)
    assert any(f.rule == "CRYPTO_WEAK_KEYGEN" and f.severity == "HIGH" for f in findings)


def test_clean_modern_crypto_has_no_findings():
    tmp = tempfile.mkdtemp()
    _write(os.path.join(tmp, "Clean.java"), '''
import javax.crypto.Cipher;
import java.security.SecureRandom;
class Clean {
  Cipher c() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }
  byte[] r() {
    byte[] x = new byte[16];
    new SecureRandom().nextBytes(x);
    return x;
  }
}
''')
    assert _walk_and_scan(tmp) == []
