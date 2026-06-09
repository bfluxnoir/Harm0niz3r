/*
 * Harm0niz3r preset: http_capture.js
 *
 * Emits structured 'send' messages for every outbound HTTP request and
 * its response across the three transports a modern Android app
 * actually uses:
 *
 *   - okhttp3 (RealCall.execute for sync, RealCall.enqueue for async)
 *   - java.net.HttpURLConnection (connect + response code readers)
 *   - android.webkit.WebView (loadUrl / loadDataWithBaseURL)
 *
 * The intent is to give a pentester a usable wire trace when SSL
 * pinning blocks Burp / mitmproxy.  Combine with ssl_pinning_bypass
 * for sites the app actually goes to the network for.
 *
 * Message shape
 * -------------
 *   {category: 'okhttp'           | 'httpurlconnection' | 'webview',
 *    verb:     'request' / 'response' / 'enqueue' / 'connect' / 'loadUrl',
 *    method:   'GET' / 'POST' / ...                       (when known),
 *    url:      'https://...',                             (always)
 *    headers:  '<Name>: <value>\n...',                    (when known),
 *    code:     200 / 404 / ...                            (responses only)}
 *
 * Bodies are not logged in V1 because they can be megabytes of binary
 * data and we don't want to flood the receive loop.  Hook the relevant
 * RequestBody / ResponseBody.string() yourself if you need them.
 */

Java.perform(function () {

  function safe(label, fn) {
    try { fn(); send("[http_capture] hooked: " + label); }
    catch (e) { send("[http_capture] skipped: " + label + " (" + e + ")"); }
  }

  function asString(v) {
    if (v === null || v === undefined) return null;
    try { return "" + v; } catch (e) { return "<unprintable>"; }
  }

  // ------------------------------------------------------------------
  // OkHttp 3.x  (RealCall is the actual carrier of execute / enqueue)
  // ------------------------------------------------------------------

  safe("okhttp3.RealCall.execute", function () {
    var RealCall = Java.use("okhttp3.RealCall");
    RealCall.execute.implementation = function () {
      try {
        var req = this.request();
        send({
          category: "okhttp",
          verb:     "request",
          method:   asString(req.method()),
          url:      asString(req.url()),
          headers:  asString(req.headers()),
        });
      } catch (e) { /* request-side log is best-effort */ }
      var resp = this.execute();
      try {
        send({
          category: "okhttp",
          verb:     "response",
          code:     resp.code(),
          url:      asString(resp.request().url()),
          headers:  asString(resp.headers()),
        });
      } catch (e) { /* response log is best-effort */ }
      return resp;
    };
  });

  safe("okhttp3.RealCall.enqueue", function () {
    var RealCall = Java.use("okhttp3.RealCall");
    RealCall.enqueue.implementation = function (callback) {
      try {
        var req = this.request();
        send({
          category: "okhttp",
          verb:     "enqueue",
          method:   asString(req.method()),
          url:      asString(req.url()),
          headers:  asString(req.headers()),
        });
      } catch (e) { /* log best-effort */ }
      this.enqueue(callback);
    };
  });

  // ------------------------------------------------------------------
  // java.net.HttpURLConnection  (stdlib path; many SDKs use it under
  // the covers)
  // ------------------------------------------------------------------

  safe("java.net.HttpURLConnection.connect", function () {
    var HUC = Java.use("java.net.HttpURLConnection");
    HUC.connect.implementation = function () {
      try {
        send({
          category: "httpurlconnection",
          verb:     "connect",
          method:   asString(this.getRequestMethod()),
          url:      asString(this.getURL()),
        });
      } catch (e) { /* log best-effort */ }
      this.connect();
    };
  });

  safe("java.net.HttpURLConnection.getResponseCode", function () {
    var HUC = Java.use("java.net.HttpURLConnection");
    HUC.getResponseCode.implementation = function () {
      var code = this.getResponseCode();
      try {
        send({
          category: "httpurlconnection",
          verb:     "response",
          code:     code,
          url:      asString(this.getURL()),
        });
      } catch (e) { /* log best-effort */ }
      return code;
    };
  });

  // ------------------------------------------------------------------
  // WebView (loadUrl is the common entry; loadDataWithBaseURL covers
  // pre-loaded HTML pages that still resolve relative URLs against a
  // base)
  // ------------------------------------------------------------------

  safe("android.webkit.WebView.loadUrl", function () {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
      send({
        category: "webview",
        verb:     "loadUrl",
        url:      asString(url),
      });
      this.loadUrl(url);
    };
    WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation =
      function (url, headers) {
        send({
          category: "webview",
          verb:     "loadUrl[headers]",
          url:      asString(url),
          headers:  asString(headers),
        });
        this.loadUrl(url, headers);
      };
  });

  safe("android.webkit.WebView.loadDataWithBaseURL", function () {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadDataWithBaseURL.implementation = function (
      baseUrl, data, mimeType, encoding, historyUrl
    ) {
      send({
        category: "webview",
        verb:     "loadDataWithBaseURL",
        url:      asString(baseUrl),
        method:   asString(mimeType),
      });
      this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
    };
  });

  send("[http_capture] ready");
});
