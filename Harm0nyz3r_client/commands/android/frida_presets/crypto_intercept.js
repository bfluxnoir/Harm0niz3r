/*
 * Harm0niz3r preset: crypto_intercept.js
 *
 * Dynamic counterpart to the static app_crypto_scan (C9).  Where the
 * static scanner sees only the bytecode shape, this preset shows the
 * actual algorithm / key / IV / input / output the app uses at runtime --
 * essential when string-encryption or runtime-loaded JCE providers
 * obscure the static view.
 *
 * Hooked APIs
 *   javax.crypto.Cipher.init(int, java.security.Key, ...)
 *   javax.crypto.Cipher.doFinal([B)
 *   javax.crypto.Mac.init(java.security.Key)
 *   javax.crypto.Mac.doFinal([B)
 *   java.security.MessageDigest.digest()
 *   java.security.MessageDigest.digest([B)
 *   javax.crypto.spec.SecretKeySpec.<init>([B, String)
 *   javax.crypto.spec.SecretKeySpec.<init>([B, int, int, String)
 *   javax.crypto.spec.IvParameterSpec.<init>([B)
 *   javax.crypto.spec.PBEKeySpec.<init>(char[], byte[], int, int)
 *   javax.crypto.KeyGenerator.generateKey()
 *
 * Bytes are hex-encoded.  Values longer than 512 hex chars are
 * truncated with '...' so the receive loop isn't flooded.
 */

Java.perform(function () {

  function hex(bytes) {
    if (bytes === null || bytes === undefined) return null;
    try {
      var arr = new Int8Array(bytes);
      var out = '';
      for (var i = 0; i < arr.length; i++) {
        var b = arr[i] & 0xff;
        out += (b < 16 ? '0' : '') + b.toString(16);
        if (out.length >= 512) { out += '...'; break; }
      }
      return out;
    } catch (e) {
      return '<unprintable bytes>';
    }
  }

  function safe(label, fn) {
    try { fn(); send("[crypto_intercept] hooked: " + label); }
    catch (e) { send("[crypto_intercept] skipped: " + label + " (" + e + ")"); }
  }

  // ----------------------------------------------------------------
  // javax.crypto.Cipher
  // ----------------------------------------------------------------

  safe("javax.crypto.Cipher.init", function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var args = Array.prototype.slice.call(arguments);
        var algo = "";
        try { algo = "" + this.getAlgorithm(); } catch (e) {}
        send({
          category:   "cipher",
          verb:       "init",
          algorithm:  algo,
          opmode:     args[0],
          keyAlgo:    (args[1] && args[1].getAlgorithm)
                        ? "" + args[1].getAlgorithm() : null,
        });
        return overload.apply(this, args);
      };
    });
  });

  safe("javax.crypto.Cipher.doFinal([B)", function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
      var out = this.doFinal(input);
      send({
        category:  "cipher",
        verb:      "doFinal",
        algorithm: "" + this.getAlgorithm(),
        input:     hex(input),
        output:    hex(out),
      });
      return out;
    };
  });

  // ----------------------------------------------------------------
  // javax.crypto.Mac
  // ----------------------------------------------------------------

  safe("javax.crypto.Mac.doFinal([B)", function () {
    var Mac = Java.use("javax.crypto.Mac");
    Mac.doFinal.overload("[B").implementation = function (input) {
      var out = this.doFinal(input);
      send({
        category:  "mac",
        verb:      "doFinal",
        algorithm: "" + this.getAlgorithm(),
        input:     hex(input),
        output:    hex(out),
      });
      return out;
    };
  });

  // ----------------------------------------------------------------
  // java.security.MessageDigest
  // ----------------------------------------------------------------

  safe("java.security.MessageDigest.digest", function () {
    var MD = Java.use("java.security.MessageDigest");
    MD.digest.overload().implementation = function () {
      var out = this.digest();
      send({
        category:  "digest",
        verb:      "digest",
        algorithm: "" + this.getAlgorithm(),
        output:    hex(out),
      });
      return out;
    };
    MD.digest.overload("[B").implementation = function (input) {
      var out = this.digest(input);
      send({
        category:  "digest",
        verb:      "digest[input]",
        algorithm: "" + this.getAlgorithm(),
        input:     hex(input),
        output:    hex(out),
      });
      return out;
    };
  });

  // ----------------------------------------------------------------
  // javax.crypto.spec.SecretKeySpec  (key material at the moment of birth)
  // ----------------------------------------------------------------

  safe("javax.crypto.spec.SecretKeySpec.<init>", function () {
    var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
    SKS.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
      send({
        category:  "key",
        verb:      "SecretKeySpec",
        algorithm: "" + algo,
        keyHex:    hex(key),
        keyLen:    key ? key.length : 0,
      });
      return this.$init(key, algo);
    };
    SKS.$init.overload("[B", "int", "int", "java.lang.String").implementation =
      function (key, off, len, algo) {
        send({
          category:  "key",
          verb:      "SecretKeySpec[range]",
          algorithm: "" + algo,
          offset:    off,
          length:    len,
          keyHex:    hex(key),
        });
        return this.$init(key, off, len, algo);
      };
  });

  // ----------------------------------------------------------------
  // javax.crypto.spec.IvParameterSpec
  // ----------------------------------------------------------------

  safe("javax.crypto.spec.IvParameterSpec.<init>", function () {
    var IPS = Java.use("javax.crypto.spec.IvParameterSpec");
    IPS.$init.overload("[B").implementation = function (iv) {
      send({
        category: "iv",
        verb:     "IvParameterSpec",
        ivHex:    hex(iv),
        ivLen:    iv ? iv.length : 0,
      });
      return this.$init(iv);
    };
  });

  // ----------------------------------------------------------------
  // javax.crypto.spec.PBEKeySpec  (password-based key derivation)
  // ----------------------------------------------------------------

  safe("javax.crypto.spec.PBEKeySpec.<init>(char[], byte[], int, int)", function () {
    var PBE = Java.use("javax.crypto.spec.PBEKeySpec");
    PBE.$init.overload("[C", "[B", "int", "int").implementation =
      function (password, salt, iterCount, keyLength) {
        var pwd = "";
        try {
          for (var i = 0; i < password.length; i++) pwd += String.fromCharCode(password[i]);
        } catch (e) { pwd = "<unprintable>"; }
        send({
          category:  "pbe",
          verb:      "PBEKeySpec",
          password:  pwd,
          saltHex:   hex(salt),
          iterCount: iterCount,
          keyLength: keyLength,
        });
        return this.$init(password, salt, iterCount, keyLength);
      };
  });

  // ----------------------------------------------------------------
  // javax.crypto.KeyGenerator
  // ----------------------------------------------------------------

  safe("javax.crypto.KeyGenerator.generateKey", function () {
    var KG = Java.use("javax.crypto.KeyGenerator");
    KG.generateKey.implementation = function () {
      var key = this.generateKey();
      var algo = "";
      try { algo = "" + this.getAlgorithm(); } catch (e) {}
      var encoded = null;
      try { encoded = key.getEncoded(); } catch (e) {}
      send({
        category:  "key",
        verb:      "generateKey",
        algorithm: algo,
        keyHex:    hex(encoded),
      });
      return key;
    };
  });

  send("[crypto_intercept] ready");
});
