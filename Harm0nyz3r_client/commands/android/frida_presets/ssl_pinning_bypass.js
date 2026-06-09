/*
 * Harm0niz3r preset: ssl_pinning_bypass.js
 *
 * Disables common certificate-pinning and TLS-validation paths so a
 * pentester running with mitmproxy / Burp's user CA installed can see
 * traffic without rebuilding the APK.
 *
 * Targets covered (V1):
 *   - okhttp3.CertificatePinner.check (and ...$okhttp)
 *   - okhttp3.CertificatePinner.check$okhttp
 *   - javax.net.ssl.X509TrustManager (custom impls -> empty
 *     checkServerTrusted)
 *   - android.net.http.X509TrustManagerExtensions.checkServerTrusted
 *   - com.android.org.conscrypt.TrustManagerImpl.checkTrusted /
 *     verifyChain (Android 8+)
 *   - WebViewClient.onReceivedSslError -> proceed
 *
 * Drop targets that aren't present in the target app are skipped with
 * a 'send' notification so the operator sees what fired.
 */

Java.perform(function () {

  function safeReplace(label, fn) {
    try { fn(); send("[ssl_pinning_bypass] hooked: " + label); }
    catch (e) { send("[ssl_pinning_bypass] skipped: " + label + " (" + e + ")"); }
  }

  // --- OkHttp 3.x CertificatePinner ----------------------------------
  safeReplace("okhttp3.CertificatePinner.check", function () {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload("java.lang.String", "java.util.List")
      .implementation = function (host, peerCerts) {
        // do nothing -> no pinning enforcement
      };
  });

  safeReplace("okhttp3.CertificatePinner.check$okhttp", function () {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner["check$okhttp"]
      .implementation = function (host, fn) {
        // swallow
      };
  });

  // --- javax.net.ssl X509TrustManager (custom impls) ------------------
  safeReplace("javax.net.ssl.X509TrustManager (TrustManagerFactory)", function () {
    var TrustManager = Java.registerClass({
      name: "com.harm0niz3r.NoCheckTrustManager",
      implements: [Java.use("javax.net.ssl.X509TrustManager")],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManagers = [TrustManager.$new()];
    SSLContext.init.overload(
      "[Ljavax.net.ssl.KeyManager;",
      "[Ljavax.net.ssl.TrustManager;",
      "java.security.SecureRandom"
    ).implementation = function (km, tm, sr) {
      send("[ssl_pinning_bypass] SSLContext.init() -> NoCheckTrustManager");
      return this.init(km, TrustManagers, sr);
    };
  });

  // --- X509TrustManagerExtensions -------------------------------------
  safeReplace("android.net.http.X509TrustManagerExtensions.checkServerTrusted", function () {
    var Ext = Java.use("android.net.http.X509TrustManagerExtensions");
    Ext.checkServerTrusted.overload(
      "[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String"
    ).implementation = function (chain, authType, host) {
      // return the chain unchanged so the caller is happy
      return Java.use("java.util.Arrays").asList(chain);
    };
  });

  // --- Conscrypt TrustManagerImpl -------------------------------------
  safeReplace("conscrypt.TrustManagerImpl.checkTrusted", function () {
    var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    var checks = ["checkTrusted", "verifyChain", "verifyChainStrict"];
    checks.forEach(function (m) {
      try {
        var fn = TMI[m];
        if (!fn) return;
        fn.overloads.forEach(function (overload) {
          overload.implementation = function () { return arguments[0]; };
        });
      } catch (e) { /* ignore per-method */ }
    });
  });

  // --- WebViewClient.onReceivedSslError -> proceed --------------------
  safeReplace("WebViewClient.onReceivedSslError -> proceed", function () {
    var WVC = Java.use("android.webkit.WebViewClient");
    WVC.onReceivedSslError
      .overload("android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError")
      .implementation = function (view, handler, error) {
        send("[ssl_pinning_bypass] WebViewClient.onReceivedSslError -> proceed");
        handler.proceed();
      };
  });

  send("[ssl_pinning_bypass] ready");
});
