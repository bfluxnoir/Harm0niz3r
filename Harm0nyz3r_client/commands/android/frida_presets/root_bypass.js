/*
 * Harm0niz3r preset: root_bypass.js
 *
 * Stubs common root-detection paths so an app that refuses to run on
 * rooted / Magisk-equipped devices still launches under a pentest.
 * Combine with Magisk Hide / DenyList for the kernel-level checks
 * Frida can't reach from userspace.
 *
 * Targets covered (V1):
 *   - RootBeer (Scott Alexander-Bown):
 *       isRooted / isRootedWithoutBusyBoxCheck / detectRootManagementApps /
 *       detectPotentiallyDangerousApps / detectTestKeys /
 *       checkForBusyBoxBinary / checkForSuBinary / checkSuExists /
 *       checkForRWPaths / checkForDangerousProps
 *   - File.exists() on canonical su paths
 *   - Runtime.exec("su" | "which su" | "mount" | "getprop")
 *
 * Each successful hook emits a 'send' so the operator can confirm
 * which checks fired.
 */

Java.perform(function () {

  function safe(label, fn) {
    try { fn(); send("[root_bypass] hooked: " + label); }
    catch (e) { send("[root_bypass] skipped: " + label + " (" + e + ")"); }
  }

  // ---- RootBeer ----
  safe("com.scottyab.rootbeer.RootBeer", function () {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    var bools = [
      "isRooted", "isRootedWithoutBusyBoxCheck", "detectRootManagementApps",
      "detectPotentiallyDangerousApps", "detectTestKeys",
      "checkForBusyBoxBinary", "checkForSuBinary", "checkSuExists",
      "checkForRWPaths", "checkForDangerousProps", "checkForRootNative",
      "checkForMagiskBinary"
    ];
    bools.forEach(function (m) {
      try {
        RootBeer[m].overloads.forEach(function (overload) {
          overload.implementation = function () { return false; };
        });
      } catch (e) { /* ignore single method */ }
    });
  });

  // ---- java.io.File.exists() on known su paths ----
  safe("java.io.File.exists() canonical su paths", function () {
    var File = Java.use("java.io.File");
    var bannedSuffixes = [
      "/su", "/.su", "/magisk", "/.magisk", "/MagiskHide",
      "/busybox", "/system/xbin/su", "/system/bin/su",
      "/sbin/su", "/sbin/magisk", "/system/app/Superuser.apk",
      "/system/app/SuperSU", "/data/adb/magisk"
    ];
    File.exists.implementation = function () {
      var path = "" + this.getAbsolutePath();
      for (var i = 0; i < bannedSuffixes.length; i++) {
        if (path === bannedSuffixes[i] || path.endsWith(bannedSuffixes[i])) {
          send("[root_bypass] File.exists -> false for " + path);
          return false;
        }
      }
      return this.exists();
    };
  });

  // ---- Runtime.exec("su" | "which su" | "getprop" | "mount") ----
  safe("Runtime.exec(...) common detection commands", function () {
    var Runtime = Java.use("java.lang.Runtime");
    var sentinel = ["su", "which su", "/system/bin/su", "magisk"];
    function isSuspicious(s) {
      if (!s) return false;
      var lower = ("" + s).toLowerCase();
      return sentinel.some(function (k) { return lower.indexOf(k) !== -1; });
    }
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
      if (isSuspicious(cmd)) {
        send("[root_bypass] Runtime.exec(\"" + cmd + "\") -> throwing IOException");
        var IOException = Java.use("java.io.IOException");
        throw IOException.$new("Permission denied");
      }
      return this.exec(cmd);
    };
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
      if (cmds && cmds.length > 0 && isSuspicious(cmds[0])) {
        send("[root_bypass] Runtime.exec([\"" + cmds[0] + "\"...]) -> throwing");
        var IOException = Java.use("java.io.IOException");
        throw IOException.$new("Permission denied");
      }
      return this.exec(cmds);
    };
  });

  send("[root_bypass] ready");
});
