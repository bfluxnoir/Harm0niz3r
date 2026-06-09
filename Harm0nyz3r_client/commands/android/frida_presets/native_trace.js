/*
 * Harm0niz3r preset: native_trace.js
 *
 * Universal native-function tracer.  Walks Process.enumerateModules,
 * matches each module name against _args.moduleFilter, walks each
 * matching module's exports, matches each export name against
 * _args.exportFilter, and replaces every match with an Interceptor
 * that logs entry (and optionally exit) per call.
 *
 * Parameters (read from the _args object injected by 'frida_run --arg')
 *   moduleFilter    glob; default '*libssl*'      (avoid blanket '*' --
 *                                                  hooking every libc
 *                                                  export crashes apps)
 *   exportFilter    glob; default 'SSL_*'         ('*' is fine here)
 *   includeArgs     'true' / 'false'              (default true; logs
 *                                                  the first four args
 *                                                  as raw pointer strings)
 *   includeReturn   'true' / 'false'              (default false)
 *
 * Examples
 *   frida_run com.example.target --preset native_trace
 *   frida_run com.example.target --preset native_trace \
 *     --arg moduleFilter='*libcrypto*' --arg exportFilter='EVP_*'
 *
 * Output
 *   {kind: 'ntrace', module, fn, args: [..], ret?}
 *   {kind: 'native_trace', hooks, ready: true}
 */

(function () {
  var A = (typeof _args === "object" && _args !== null) ? _args : {};
  var moduleFilter = A.moduleFilter || "*libssl*";
  var exportFilter = A.exportFilter || "SSL_*";
  var incArgs   = (A.includeArgs   == null) ? true  : ("" + A.includeArgs)   === "true";
  var incReturn = (A.includeReturn == null) ? false : ("" + A.includeReturn) === "true";

  function globToRe(g) {
    var esc = g.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp("^" + esc.replace(/\*/g, ".*") + "$");
  }
  var moduleRe = globToRe(moduleFilter);
  var exportRe = globToRe(exportFilter);

  Java.perform(function () {
    var hookCount = 0;
    Process.enumerateModules().forEach(function (mod) {
      if (!moduleRe.test(mod.name)) return;
      try {
        Module.enumerateExports(mod.name).forEach(function (exp) {
          if (!exportRe.test(exp.name)) return;
          try {
            Interceptor.attach(exp.address, {
              onEnter: function (a) {
                this.args = null;
                if (incArgs) {
                  var arr = [];
                  for (var i = 0; i < 4; i++) {
                    try { arr.push("" + a[i]); } catch (e) { arr.push("?"); }
                  }
                  this.args = arr;
                  this.modName = mod.name;
                  this.fnName  = exp.name;
                }
              },
              onLeave: function (retval) {
                var msg = {
                  kind:   "ntrace",
                  module: this.modName || mod.name,
                  fn:     this.fnName  || exp.name,
                };
                if (incArgs)   msg.args = this.args || null;
                if (incReturn) msg.ret  = "" + retval;
                send(msg);
              }
            });
            hookCount++;
          } catch (e) {
            send({kind: "ntrace_error", module: mod.name, fn: exp.name, error: "" + e});
          }
        });
      } catch (e) {
        send({kind: "ntrace_module_error", module: mod.name, error: "" + e});
      }
    });
    send({
      kind:         "native_trace",
      moduleFilter: moduleFilter,
      exportFilter: exportFilter,
      hooks:        hookCount,
      ready:        true,
    });
  });
})();
