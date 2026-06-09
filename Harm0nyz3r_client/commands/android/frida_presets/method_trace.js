/*
 * Harm0niz3r preset: method_trace.js
 *
 * Universal Java method tracer.  Enumerates every loaded class, matches
 * each one against a user-supplied glob, and replaces every overload of
 * every declared method on each match with a thin wrapper that logs:
 *
 *   {kind: 'trace', class, method, args, ret}
 *
 * Parameters (read from the _args object injected by 'frida_run --arg')
 *   classPattern    glob; * = any chars       (default: 'okhttp3.RealCall*')
 *   methodPattern   glob; * = any chars       (default: '*' = every method)
 *   includeArgs     'true' / 'false'          (default: true)
 *   includeReturn   'true' / 'false'          (default: true)
 *
 * Examples
 *   frida_run com.example.target --preset method_trace
 *   frida_run com.example.target --preset method_trace \
 *     --arg classPattern=okhttp3.* --arg methodPattern=execute
 *   frida_run com.example.target --preset method_trace --spawn \
 *     --arg classPattern=com.example.crypto.* \
 *     --arg includeArgs=true --arg includeReturn=false
 *
 * Warnings
 *   classPattern='*' on a real app will instrument tens of thousands of
 *   methods.  The receive loop survives (we have B3 framing) but the app
 *   will run noticeably slower.  Keep the pattern as narrow as the
 *   investigation allows.
 */

(function () {
  var A = (typeof _args === "object" && _args !== null) ? _args : {};
  var classPattern  = A.classPattern  || "okhttp3.RealCall*";
  var methodPattern = A.methodPattern || "*";
  var incArgs   = (A.includeArgs   == null) ? true : ("" + A.includeArgs)   === "true";
  var incReturn = (A.includeReturn == null) ? true : ("" + A.includeReturn) === "true";

  function globToRe(g) {
    // Escape regex metachars, then unescape '*' into '.*'.
    var esc = g.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp("^" + esc.replace(/\*/g, ".*") + "$");
  }

  var classRe  = globToRe(classPattern);
  var methodRe = globToRe(methodPattern);
  var hookCount = 0;
  var classCount = 0;

  function stringify(v) {
    if (v === null || v === undefined) return null;
    try { return "" + v; } catch (e) { return "<?>"; }
  }

  Java.perform(function () {
    Java.enumerateLoadedClasses({
      onMatch: function (className) {
        if (!classRe.test(className)) return;
        classCount++;

        var Klass;
        try { Klass = Java.use(className); }
        catch (e) {
          send({kind: "trace_error", "class": className, error: "Java.use failed: " + e});
          return;
        }

        var methods;
        try { methods = Klass.class.getDeclaredMethods(); }
        catch (e) {
          send({kind: "trace_error", "class": className, error: "getDeclaredMethods failed: " + e});
          return;
        }

        var seen = {};
        for (var i = 0; i < methods.length; i++) {
          var name = "" + methods[i].getName();
          if (seen[name]) continue;
          if (!methodRe.test(name)) continue;
          seen[name] = true;

          try {
            var overloads = Klass[name].overloads;
            overloads.forEach(function (ov) {
              ov.implementation = function () {
                var args = null;
                if (incArgs) {
                  args = [];
                  for (var j = 0; j < arguments.length; j++) {
                    args.push(stringify(arguments[j]));
                  }
                }
                var ret = ov.apply(this, arguments);
                send({
                  kind:   "trace",
                  "class": className,
                  method: name,
                  args:   args,
                  ret:    incReturn ? stringify(ret) : null,
                });
                return ret;
              };
              hookCount++;
            });
          } catch (e) {
            send({
              kind:    "trace_error",
              "class": className,
              method:  name,
              error:   "" + e,
            });
          }
        }
      },
      onComplete: function () {
        send({
          kind:          "method_trace",
          classPattern:  classPattern,
          methodPattern: methodPattern,
          classes:       classCount,
          hooks:         hookCount,
          ready:         true,
        });
      }
    });
  });
})();
