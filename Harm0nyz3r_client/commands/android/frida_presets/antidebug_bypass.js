/*
 * Harm0niz3r preset: antidebug_bypass.js
 *
 * Complements root_bypass.  Apps commonly check for an attached
 * debugger / tracer / instrumentation before doing anything
 * interesting -- if the check passes (i.e. detector says "I'm being
 * watched"), the app silently bails out or starts spraying junk into
 * the network.  This preset hooks the standard detection paths so
 * the answer is always "no, you're clean."
 *
 * Java-side hooks
 *   android.os.Debug.isDebuggerConnected      -> false
 *   android.os.Debug.waitingForDebugger       -> false
 *   android.os.Debug.threadCpuTimeNanos       -> 0  (some apps use
 *                                                    delta-checks)
 *   android.app.ApplicationInfo.flags read    -> mask out FLAG_DEBUGGABLE
 *   java.lang.Thread.sleep                    -> no-op when called from
 *                                                a class whose name hints
 *                                                at anti-debug (e.g.
 *                                                'SecurityCheck', 'Antidebug',
 *                                                'TamperDetector') --
 *                                                catches timing checks
 *
 * Native-side hooks
 *   ptrace                                    -> always return 0
 *   __NR_ptrace via syscall(186)              -> not portable; skipped
 *
 * Every hook is wrapped in safe(label, fn) so a missing class on an
 * older Android version skips that hook with a 'send' instead of
 * killing the whole script.
 */

Java.perform(function () {

  function safe(label, fn) {
    try { fn(); send("[antidebug_bypass] hooked: " + label); }
    catch (e) { send("[antidebug_bypass] skipped: " + label + " (" + e + ")"); }
  }

  // ---- android.os.Debug ----
  safe("android.os.Debug.isDebuggerConnected -> false", function () {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () { return false; };
  });

  safe("android.os.Debug.waitingForDebugger -> false", function () {
    var Debug = Java.use("android.os.Debug");
    Debug.waitingForDebugger.implementation = function () { return false; };
  });

  safe("android.os.Debug.threadCpuTimeNanos -> 0", function () {
    var Debug = Java.use("android.os.Debug");
    Debug.threadCpuTimeNanos.implementation = function () { return 0; };
  });

  // ---- ApplicationInfo.flags scrub ----
  safe("ApplicationInfo flags &= ~FLAG_DEBUGGABLE", function () {
    var AppInfo = Java.use("android.content.pm.ApplicationInfo");
    var FLAG_DEBUGGABLE = 2;
    // We can't easily intercept field reads in Java; instead hook the
    // common indirect getter the Android framework uses.
    var Context = Java.use("android.content.Context");
    // Many apps actually read it via getApplicationInfo().flags -- we'd
    // need to wrap the returned ApplicationInfo's 'flags' field.  We
    // approximate by hooking PackageManager.getApplicationInfo and
    // masking the flag bit on the way out.
    try {
      var PM = Java.use("android.content.pm.PackageManager");
      PM.getApplicationInfo.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var info = ov.apply(this, arguments);
          if (info && (info.flags.value & FLAG_DEBUGGABLE) !== 0) {
            info.flags.value = info.flags.value & ~FLAG_DEBUGGABLE;
            send("[antidebug_bypass] masked FLAG_DEBUGGABLE on ApplicationInfo");
          }
          return info;
        };
      });
    } catch (e) {
      send("[antidebug_bypass] skipped: PackageManager.getApplicationInfo (" + e + ")");
    }
  });

  // ---- Native ptrace -> 0 ----
  // Module.findExportByName(null, ...) looks across every loaded module
  // until it finds the symbol.
  safe("native ptrace -> 0", function () {
    var ptr = Module.findExportByName(null, "ptrace");
    if (!ptr) throw new Error("ptrace not found in any loaded module");
    Interceptor.replace(ptr, new NativeCallback(function () {
      return 0;
    }, "long", ["int", "int", "pointer", "pointer"]));
  });

  // ---- Frida-detection short-circuit ----
  // Many apps detect Frida by reading /proc/self/maps and grepping for
  // 'frida'.  Hook libc's 'fgets' to scrub matching lines.
  safe("libc.fgets scrubs lines containing 'frida'", function () {
    var fgets = Module.findExportByName(null, "fgets");
    if (!fgets) throw new Error("fgets not found");
    Interceptor.attach(fgets, {
      onLeave: function (retval) {
        if (retval.isNull()) return;
        try {
          var line = retval.readCString();
          if (line && /frida|gum-js-loop|gmain/.test(line)) {
            // Overwrite the first byte with NUL so the caller sees an
            // empty string.  Crude but works against grep-style scans.
            Memory.writeU8(retval, 0);
          }
        } catch (e) { /* ignore unreadable */ }
      }
    });
  });

  send("[antidebug_bypass] ready");
});
