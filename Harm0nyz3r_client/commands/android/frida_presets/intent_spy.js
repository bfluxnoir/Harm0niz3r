/*
 * Harm0niz3r preset: intent_spy.js
 *
 * Logs every Intent the target app launches or broadcasts: action,
 * component, data URI, extras keys.  Use during a manual click-through
 * to see what the app is sending around -- handy for finding
 * implicit intents you can hijack, deep links worth fuzzing, and
 * leakage of sensitive data into broadcasts.
 *
 * Hooks:
 *   - android.app.Activity.startActivity / startActivityForResult /
 *     startActivities
 *   - android.content.ContextWrapper.startActivity / sendBroadcast /
 *     sendOrderedBroadcast / sendStickyBroadcast
 *   - android.content.Intent.<init>(...) just to log freshly-built
 *     intents that never get sent (e.g. stored for later)
 */

Java.perform(function () {

  function safe(label, fn) {
    try { fn(); send("[intent_spy] hooked: " + label); }
    catch (e) { send("[intent_spy] skipped: " + label + " (" + e + ")"); }
  }

  function describeIntent(intent) {
    if (!intent) return "<null>";
    try {
      var out = {
        action:    intent.getAction ? "" + (intent.getAction() || "") : null,
        component: intent.getComponent ? ("" + (intent.getComponent() || "")) : null,
        data:      intent.getDataString ? ("" + (intent.getDataString() || "")) : null,
        package:   intent.getPackage ? ("" + (intent.getPackage() || "")) : null,
        type:      intent.getType ? ("" + (intent.getType() || "")) : null,
        flags:     intent.getFlags ? intent.getFlags() : null,
        extras:    null
      };
      try {
        var b = intent.getExtras ? intent.getExtras() : null;
        if (b) {
          var keys = b.keySet().toArray();
          out.extras = [];
          for (var i = 0; i < keys.length; i++) {
            out.extras.push("" + keys[i]);
          }
        }
      } catch (e) { /* extras unreadable */ }
      return out;
    } catch (e) {
      return "<error: " + e + ">";
    }
  }

  // ---- Activity.startActivity ----
  safe("Activity.startActivity", function () {
    var Activity = Java.use("android.app.Activity");
    Activity.startActivity.overload("android.content.Intent")
      .implementation = function (intent) {
        send({ verb: "startActivity", intent: describeIntent(intent) });
        return this.startActivity(intent);
      };
    Activity.startActivity.overload("android.content.Intent", "android.os.Bundle")
      .implementation = function (intent, opts) {
        send({ verb: "startActivity[opts]", intent: describeIntent(intent) });
        return this.startActivity(intent, opts);
      };
  });

  safe("Activity.startActivityForResult", function () {
    var Activity = Java.use("android.app.Activity");
    Activity.startActivityForResult
      .overload("android.content.Intent", "int")
      .implementation = function (intent, code) {
        send({ verb: "startActivityForResult", code: code, intent: describeIntent(intent) });
        return this.startActivityForResult(intent, code);
      };
  });

  // ---- ContextWrapper / Context.* ----
  safe("ContextWrapper.startActivity / sendBroadcast / sendOrderedBroadcast", function () {
    var CW = Java.use("android.content.ContextWrapper");

    CW.startActivity.overload("android.content.Intent")
      .implementation = function (intent) {
        send({ verb: "ctx.startActivity", intent: describeIntent(intent) });
        return this.startActivity(intent);
      };

    CW.sendBroadcast.overload("android.content.Intent")
      .implementation = function (intent) {
        send({ verb: "sendBroadcast", intent: describeIntent(intent) });
        return this.sendBroadcast(intent);
      };
    CW.sendBroadcast.overload("android.content.Intent", "java.lang.String")
      .implementation = function (intent, perm) {
        send({ verb: "sendBroadcast[perm]", perm: "" + perm, intent: describeIntent(intent) });
        return this.sendBroadcast(intent, perm);
      };

    CW.sendOrderedBroadcast
      .overload("android.content.Intent", "java.lang.String")
      .implementation = function (intent, perm) {
        send({ verb: "sendOrderedBroadcast", perm: "" + perm, intent: describeIntent(intent) });
        return this.sendOrderedBroadcast(intent, perm);
      };
  });

  send("[intent_spy] ready");
});
