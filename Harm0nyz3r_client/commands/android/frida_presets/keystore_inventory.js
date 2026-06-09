/*
 * Harm0niz3r preset: keystore_inventory.js
 *
 * One-shot enumeration of every entry in the app's AndroidKeyStore at
 * runtime.  Useful for spot-checking MASVS-CRYPTO-5 / MSTG-CRYPTO-5
 * (key storage) -- does the app actually put its long-lived secrets in
 * the hardware-backed keystore, or is it just using AndroidKeyStore in
 * software because the framework let it?
 *
 * For every alias the script emits:
 *   alias                Java string
 *   algorithm            e.g. AES, RSA, EC, HmacSHA256
 *   keySize              bits
 *   purposesMask         raw KeyProperties.PURPOSE_* bitmask value
 *   purposes             human-readable list, e.g. ['ENCRYPT', 'DECRYPT']
 *   userAuthRequired     boolean
 *   invalidatedByBiometric  boolean
 *   insideSecureHardware boolean (API 23-30; deprecated in 31+)
 *   securityLevel        'SOFTWARE' / 'TRUSTED_ENVIRONMENT' /
 *                        'STRONGBOX' / 'UNKNOWN' (API 31+)
 *
 * Each message also carries a 'kind: "keystore_entry"' so the receive
 * loop / session log can filter cleanly.
 */

Java.perform(function () {

  var KeyStore           = Java.use("java.security.KeyStore");
  var KeyFactory         = Java.use("java.security.KeyFactory");
  var SecretKeyFactory   = Java.use("javax.crypto.SecretKeyFactory");
  var KeyInfo            = Java.use("android.security.keystore.KeyInfo");

  // KeyProperties.PURPOSE_* values (defined since API 23).
  var PURPOSES = [
    [1,   "ENCRYPT"],
    [2,   "DECRYPT"],
    [4,   "SIGN"],
    [8,   "VERIFY"],
    [32,  "WRAP_KEY"],
    [64,  "AGREE_KEY"],
    [128, "ATTEST_KEY"],
  ];

  function decodePurposes(mask) {
    if (typeof mask !== "number") return [];
    var out = [];
    for (var i = 0; i < PURPOSES.length; i++) {
      if ((mask & PURPOSES[i][0]) !== 0) out.push(PURPOSES[i][1]);
    }
    return out;
  }

  // KeyProperties.SECURITY_LEVEL_* (API 31+).
  var LEVELS = {
    "-2": "UNKNOWN_SECURE",
    "-1": "UNKNOWN",
    "0":  "SOFTWARE",
    "1":  "TRUSTED_ENVIRONMENT",
    "2":  "STRONGBOX",
  };

  function safe(fn, fallback) {
    try { return fn(); } catch (e) { return fallback; }
  }

  function describeEntry(ks, alias) {
    var entry = {
      kind:  "keystore_entry",
      alias: "" + alias,
    };

    var key;
    try {
      key = ks.getKey(alias, null);
    } catch (e) {
      entry.error = "ks.getKey failed: " + e;
      return entry;
    }
    if (key === null) {
      entry.error = "ks.getKey returned null (entry may be a certificate-only entry)";
      return entry;
    }

    try { entry.algorithm = "" + key.getAlgorithm(); } catch (e) {}

    var info = null;

    // Symmetric keys (AES, HMAC*) come back via SecretKeyFactory; asymmetric
    // (RSA, EC) via KeyFactory.  Try the symmetric path first if the
    // algorithm looks symmetric; fall back to asymmetric on any error.
    var algo = entry.algorithm || "";
    var triedSymmetric = false;
    if (algo === "AES" || algo.indexOf("Hmac") === 0) {
      triedSymmetric = true;
      try {
        var skf = SecretKeyFactory.getInstance(algo, "AndroidKeyStore");
        var spec = skf.getKeySpec(key, KeyInfo.class);
        info = Java.cast(spec, KeyInfo);
      } catch (e) { /* fall through */ }
    }
    if (info === null) {
      try {
        var kf = KeyFactory.getInstance(algo, "AndroidKeyStore");
        var spec2 = kf.getKeySpec(key, KeyInfo.class);
        info = Java.cast(spec2, KeyInfo);
      } catch (e) {
        if (!triedSymmetric) {
          try {
            var skf2 = SecretKeyFactory.getInstance(algo, "AndroidKeyStore");
            var spec3 = skf2.getKeySpec(key, KeyInfo.class);
            info = Java.cast(spec3, KeyInfo);
          } catch (e2) { /* give up on KeyInfo */ }
        }
      }
    }

    if (info !== null) {
      entry.keySize               = safe(function () { return info.getKeySize(); });
      var mask                    = safe(function () { return info.getPurposes(); });
      if (mask !== undefined) entry.purposesMask = mask;
      var dec                     = decodePurposes(mask);
      if (dec.length) entry.purposes = dec;
      entry.userAuthRequired      = safe(function () { return info.isUserAuthenticationRequired(); });
      entry.invalidatedByBiometric = safe(function () {
        return info.isInvalidatedByBiometricEnrollment();
      });
      // API 23-30: isInsideSecureHardware
      var hw = safe(function () { return info.isInsideSecureHardware(); });
      if (typeof hw === "boolean") entry.insideSecureHardware = hw;
      // API 31+: getSecurityLevel
      var lvl = safe(function () { return info.getSecurityLevel(); });
      if (typeof lvl === "number") {
        entry.securityLevelRaw = lvl;
        entry.securityLevel    = LEVELS["" + lvl] || ("RAW_" + lvl);
      }
    } else {
      entry.error_keyinfo = "Could not derive KeyInfo for algorithm " + algo;
    }

    return entry;
  }

  // ----- main enumeration -----

  var ks;
  try {
    ks = KeyStore.getInstance("AndroidKeyStore");
    ks.load(null);
  } catch (e) {
    send({kind: "keystore_inventory", error: "Could not open AndroidKeyStore: " + e});
    return;
  }

  var aliases;
  try {
    aliases = ks.aliases();
  } catch (e) {
    send({kind: "keystore_inventory", error: "ks.aliases() failed: " + e});
    return;
  }

  var count = 0;
  while (aliases.hasMoreElements()) {
    var alias = aliases.nextElement();
    send(describeEntry(ks, alias));
    count++;
  }
  send({kind: "keystore_inventory", count: count, ready: true});
});
