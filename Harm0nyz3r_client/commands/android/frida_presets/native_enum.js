/*
 * Harm0niz3r preset: native_enum.js
 *
 * Walk every loaded native module in the target process and emit every
 * export.  Pairs with the static app_native_audit (C15): the static
 * side sees only the .so files shipped in the APK, while this dynamic
 * walk also catches modules loaded from /data/app/.../oat/, dlopen'd
 * by JNI at runtime, or pulled out of a packer.
 *
 * Message shapes
 *   {kind: 'module',  name, base, size, path}
 *   {kind: 'export',  module, name, type, address}
 *   {kind: 'export_error', module, error}              (per-module errors)
 *   {kind: 'native_enum', modules, exports, ready: true}
 *
 * Optional --arg
 *   moduleFilter   glob; * = any chars (default: '*.so')
 *
 * Exports are only enumerated for modules whose name matches
 * moduleFilter -- the default skips the main process binary and OAT
 * artefacts so the receive loop stays manageable.
 */

(function () {
  var A = (typeof _args === "object" && _args !== null) ? _args : {};
  var moduleFilter = A.moduleFilter || "*.so";

  function globToRe(g) {
    var esc = g.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp("^" + esc.replace(/\*/g, ".*") + "$");
  }
  var moduleRe = globToRe(moduleFilter);

  Java.perform(function () {
    var moduleCount = 0;
    var exportCount = 0;

    Process.enumerateModules().forEach(function (mod) {
      moduleCount++;
      send({
        kind: "module",
        name: mod.name,
        base: "" + mod.base,
        size: mod.size,
        path: mod.path,
      });

      if (!moduleRe.test(mod.name)) return;

      try {
        Module.enumerateExports(mod.name).forEach(function (exp) {
          exportCount++;
          send({
            kind:    "export",
            module:  mod.name,
            name:    exp.name,
            type:    exp.type,
            address: "" + exp.address,
          });
        });
      } catch (e) {
        send({kind: "export_error", module: mod.name, error: "" + e});
      }
    });

    send({
      kind:    "native_enum",
      modules: moduleCount,
      exports: exportCount,
      filter:  moduleFilter,
      ready:   true,
    });
  });
})();
