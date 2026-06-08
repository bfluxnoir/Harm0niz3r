package com.dekra.harm0niz3r

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.PrintWriter
import kotlin.random.Random

private const val TAG = "CommandHandler"

/** Runtime / dangerous permissions — mirrors the Python client's app_permissions list. */
private val DANGEROUS_PERMISSIONS = setOf(
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.MANAGE_ACCOUNTS",
    "android.permission.AUTHENTICATE_ACCOUNTS",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.PROCESS_OUTGOING_CALLS",
)

/**
 * Processes commands received from the Python server and writes responses
 * back through writer.
 *
 * Message format from server:  "COMMAND_REQUEST:<cmd> args..."
 * Response format to server:   "<TYPE>:<payload> \n\n"  (framing done by TcpServer.sendMessage)
 *
 * Supported commands
 * ------------------
 * apps_list                            → HDC_OUTPUT_ALL_APPS:<json array of package names>
 * app_surface <package>                → HDC_OUTPUT_APP_SURFACE_JSON:<json>
 * app_info <package>                   → HDC_OUTPUT_APP_DETAILS:<json>
 * apps_visible_abilities               → HDC_OUTPUT_EXPOSED_ABILITIES:<json>
 * app_ability <pkg> <activity>         → EXEC_RESULT:<msg>
 * app_ability_want <pkg> <act> [k=v..] → EXEC_RESULT:<msg>  (Intent extras)
 * app_ability_fuzz <pkg> <act> [..]    → EXEC_RESULT:<summary>  (fuzzed Intent extras)
 * app_broadcast <action> [-n c] [k=v..]→ EXEC_RESULT:<msg>
 * app_deeplink <uri> [-n c]            → EXEC_RESULT:<msg>
 * app_permissions <package> [--dangerous] → HDC_OUTPUT_APP_PERMISSIONS:<json>
 * shell_exec <cmd>                     → EXEC_RESULT:<output>
 * app_provider <authority> projection  → PROVIDER_QUERY_RESULT:<json>
 *
 * Note: app_ability_want / app_ability_fuzz / app_deeplink start Activities from a
 * Service context.  Android 10+ (API 29+) background-activity-start restrictions may
 * silently block these unless the app is foreground/recently interacted with — the
 * same constraint already affects app_ability.
 */
class CommandHandler(private val context: Context) {

    private val pm: PackageManager = context.packageManager

    fun handle(rawMessage: String, writer: PrintWriter) {
        if (!rawMessage.startsWith("COMMAND_REQUEST:")) {
            Log.d(TAG, "Ignoring non-command message: $rawMessage")
            return
        }

        val payload = rawMessage.removePrefix("COMMAND_REQUEST:").trim()
        val parts = payload.split(" ")
        val cmd = parts[0].lowercase()
        val args = parts.drop(1)

        Log.i(TAG, "Executing command: $cmd  args=$args")

        try {
            when (cmd) {
                "apps_list"              -> cmdAppsList(writer)
                "app_surface"            -> cmdAppSurface(args, writer)
                "app_info"               -> cmdAppInfo(args, writer)
                "apps_visible_abilities" -> cmdAppsVisibleAbilities(writer)
                "app_ability"            -> cmdAppAbility(args, writer)
                "app_ability_want"       -> cmdAppAbilityWant(args, writer)
                "app_ability_fuzz"       -> cmdAppAbilityFuzz(args, writer)
                "app_broadcast"          -> cmdAppBroadcast(args, writer)
                "app_deeplink"           -> cmdAppDeeplink(args, writer)
                "app_permissions"        -> cmdAppPermissions(args, writer)
                "shell_exec"             -> cmdShellExec(args, writer)
                "app_provider"           -> cmdAppProvider(args, writer)
                else -> sendError(writer, "Unknown command: $cmd")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling command '$cmd': ${e.message}")
            sendError(writer, "Internal error in $cmd: ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // apps_list
    // ------------------------------------------------------------------

    private fun cmdAppsList(writer: PrintWriter) {
        val flags = PackageManager.GET_META_DATA.toLong()
        val packages = pm.getInstalledPackages(flags.toInt())
        val arr = JSONArray()
        packages.forEach { arr.put(it.packageName) }
        send(writer, "HDC_OUTPUT_ALL_APPS", arr.toString())
    }

    // ------------------------------------------------------------------
    // app_surface <package>
    // ------------------------------------------------------------------

    private fun cmdAppSurface(args: List<String>, writer: PrintWriter) {
        val pkgName = args.firstOrNull() ?: return sendError(writer, "app_surface requires <package>")
        val info = getPackageInfo(pkgName) ?: return sendError(writer, "Package not found: $pkgName")

        val obj = JSONObject()
        obj.put("packageName", pkgName)
        obj.put("debugMode", info.applicationInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        obj.put("systemApp", info.applicationInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0)

        val perms = JSONArray()
        info.requestedPermissions?.forEach { perms.put(it) }
        obj.put("requiredAppPermissions", perms)

        val components = JSONArray()

        // Activities
        info.activities?.forEach { a ->
            if (a.exported) {
                components.put(buildComponent(a.name, "Activity", true, a.permission))
            }
        }
        // Services
        info.services?.forEach { s ->
            if (s.exported) {
                components.put(buildComponent(s.name, "Service", true, s.permission))
            }
        }
        // Receivers
        info.receivers?.forEach { r ->
            if (r.exported) {
                components.put(buildComponent(r.name, "Receiver", true, r.permission))
            }
        }
        // Providers
        info.providers?.forEach { p ->
            if (p.exported) {
                val c = buildComponent(p.name, "Provider", true, p.readPermission ?: p.writePermission)
                c.put("authority", p.authority ?: "")
                components.put(c)
            }
        }

        obj.put("exposedComponents", components)
        send(writer, "HDC_OUTPUT_APP_SURFACE_JSON", obj.toString())
    }

    private fun buildComponent(
        name: String,
        type: String,
        exported: Boolean,
        permission: String?
    ): JSONObject {
        val o = JSONObject()
        o.put("name", name)
        o.put("type", type)
        o.put("visible", exported)
        val perms = JSONArray()
        if (!permission.isNullOrBlank()) perms.put(permission)
        o.put("permissionsRequired", perms)
        o.put("skills", JSONArray())
        return o
    }

    // ------------------------------------------------------------------
    // app_info <package>
    // ------------------------------------------------------------------

    private fun cmdAppInfo(args: List<String>, writer: PrintWriter) {
        val pkgName = args.firstOrNull() ?: return sendError(writer, "app_info requires <package>")
        val info = getPackageInfo(pkgName) ?: return sendError(writer, "Package not found: $pkgName")

        val obj = JSONObject()
        obj.put("packageName", pkgName)
        obj.put("versionName", info.versionName ?: "")
        obj.put("versionCode", info.longVersionCode)
        obj.put("targetSdk", info.applicationInfo?.targetSdkVersion ?: -1)
        obj.put("minSdk", info.applicationInfo?.minSdkVersion ?: -1)
        obj.put("debugMode", info.applicationInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        obj.put("systemApp", info.applicationInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0)
        val perms = JSONArray()
        info.requestedPermissions?.forEach { perms.put(it) }
        obj.put("requiredAppPermissions", perms)
        send(writer, "HDC_OUTPUT_APP_DETAILS", obj.toString())
    }

    // ------------------------------------------------------------------
    // apps_visible_abilities
    // ------------------------------------------------------------------

    private fun cmdAppsVisibleAbilities(writer: PrintWriter) {
        val result = JSONArray()
        val packages = pm.getInstalledPackages(
            PackageManager.GET_ACTIVITIES
        )
        for (pkg in packages) {
            pkg.activities?.filter { it.exported && it.permission.isNullOrBlank() }?.forEach { a ->
                val entry = JSONObject()
                entry.put("app", pkg.packageName)
                entry.put("activity", a.name)
                entry.put("skills", JSONArray())
                result.put(entry)
            }
        }
        send(writer, "HDC_OUTPUT_EXPOSED_ABILITIES", result.toString())
    }

    // ------------------------------------------------------------------
    // app_ability <package> <activity>
    // ------------------------------------------------------------------

    private fun cmdAppAbility(args: List<String>, writer: PrintWriter) {
        if (args.size < 2) return sendError(writer, "app_ability requires <package> <activity>")
        val pkg = args[0]
        val activity = if (args[1].startsWith(".")) pkg + args[1] else args[1]

        val intent = Intent().apply {
            setClassName(pkg, activity)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
        send(writer, "EXEC_RESULT", "Activity $activity started")
    }

    // ------------------------------------------------------------------
    // shell_exec <command...>
    // ------------------------------------------------------------------

    private fun cmdShellExec(args: List<String>, writer: PrintWriter) {
        if (args.isEmpty()) return sendError(writer, "shell_exec requires a command")
        val cmdStr = args.joinToString(" ")
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmdStr))
            val output = process.inputStream.bufferedReader().readText()
            val errOutput = process.errorStream.bufferedReader().readText()
            process.waitFor()
            val combined = if (errOutput.isNotBlank()) "$output\n[stderr]\n$errOutput" else output
            send(writer, "EXEC_RESULT", combined.trim())
        } catch (e: Exception) {
            sendError(writer, "shell_exec error: ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // app_provider <content-uri> [projection columns comma-separated]
    // ------------------------------------------------------------------

    private fun cmdAppProvider(args: List<String>, writer: PrintWriter) {
        if (args.isEmpty()) return sendError(writer, "app_provider requires <content-uri>")
        val uriStr = args[0]
        val projection = args.getOrNull(1)?.split(",")?.toTypedArray()

        val uri = try {
            Uri.parse(uriStr)
        } catch (e: Exception) {
            return sendError(writer, "Invalid URI: $uriStr")
        }

        val result = JSONObject()
        result.put("uri", uriStr)
        val rows = JSONArray()

        try {
            context.contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
                val cols = cursor.columnNames
                while (cursor.moveToNext()) {
                    val row = JSONObject()
                    for (col in cols) {
                        val idx = cursor.getColumnIndex(col)
                        row.put(col, cursor.getString(idx) ?: "null")
                    }
                    rows.put(row)
                }
            }
        } catch (e: Exception) {
            return sendError(writer, "Content query failed: ${e.message}")
        }

        result.put("rows", rows)
        send(writer, "PROVIDER_QUERY_RESULT", result.toString())
    }

    // ------------------------------------------------------------------
    // app_ability_want <package> <activity> [key=value ...]
    // ------------------------------------------------------------------

    private fun cmdAppAbilityWant(args: List<String>, writer: PrintWriter) {
        if (args.size < 2) return sendError(writer, "app_ability_want requires <package> <activity>")
        val pkg = args[0]
        val activity = qualifyClassName(pkg, args[1])

        val intent = Intent().apply {
            setClassName(pkg, activity)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        applyParams(intent, args.drop(2)) { token -> token }

        try {
            context.startActivity(intent)
            send(writer, "EXEC_RESULT", "Activity $activity started with Intent extras")
        } catch (e: Exception) {
            sendError(writer, "Failed to start $activity: ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // app_ability_fuzz <package> <activity> [--count N] [--delay ms] [key=value ...]
    // ------------------------------------------------------------------

    private fun cmdAppAbilityFuzz(args: List<String>, writer: PrintWriter) {
        if (args.size < 2) return sendError(writer, "app_ability_fuzz requires <package> <activity>")
        val pkg = args[0]
        val activity = qualifyClassName(pkg, args[1])

        var count = 10
        var delayMs = 0L
        val paramTokens = mutableListOf<String>()

        var i = 2
        while (i < args.size) {
            when {
                args[i] == "--count" && i + 1 < args.size -> {
                    count = args[i + 1].toIntOrNull() ?: count; i += 2
                }
                args[i] == "--delay" && i + 1 < args.size -> {
                    delayMs = args[i + 1].toLongOrNull() ?: delayMs; i += 2
                }
                else -> { paramTokens.add(args[i]); i += 1 }
            }
        }

        var ok = 0
        var failed = 0
        for (iter in 1..count) {
            val intent = Intent().apply {
                setClassName(pkg, activity)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            applyParams(intent, paramTokens) { fuzzValue(it) }
            try {
                context.startActivity(intent)
                ok++
            } catch (e: Exception) {
                failed++
                Log.w(TAG, "fuzz iteration $iter failed: ${e.message}")
            }
            if (iter < count && delayMs > 0) {
                try { Thread.sleep(delayMs) } catch (_: InterruptedException) {}
            }
        }
        send(writer, "EXEC_RESULT", "Fuzzed $activity x$count  (ok=$ok, failed=$failed)")
    }

    // ------------------------------------------------------------------
    // app_broadcast <action> [-n <package/receiver>] [key=value ...]
    // ------------------------------------------------------------------

    private fun cmdAppBroadcast(args: List<String>, writer: PrintWriter) {
        if (args.isEmpty()) return sendError(writer, "app_broadcast requires <action>")
        val action = args[0]
        val intent = Intent(action)

        var i = 1
        while (i < args.size) {
            val token = args[i]
            if (token == "-n" && i + 1 < args.size) {
                applyComponentOverride(intent, args[i + 1])
                i += 2
            } else if (token.contains("=")) {
                val eq = token.indexOf('=')
                putInferredExtra(intent, token.substring(0, eq), token.substring(eq + 1))
                i += 1
            } else {
                i += 1
            }
        }

        try {
            context.sendBroadcast(intent)
            send(writer, "EXEC_RESULT", "Broadcast sent: action='$action'")
        } catch (e: Exception) {
            sendError(writer, "Failed to send broadcast '$action': ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // app_deeplink <uri> [-n <package/activity>]
    // ------------------------------------------------------------------

    private fun cmdAppDeeplink(args: List<String>, writer: PrintWriter) {
        if (args.isEmpty()) return sendError(writer, "app_deeplink requires <uri>")
        val uriStr = args[0]
        val uri = try {
            Uri.parse(uriStr)
        } catch (e: Exception) {
            return sendError(writer, "Invalid URI: $uriStr")
        }

        val intent = Intent(Intent.ACTION_VIEW, uri).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val nIdx = args.indexOf("-n")
        if (nIdx != -1 && nIdx + 1 < args.size) {
            applyComponentOverride(intent, args[nIdx + 1])
        }

        try {
            context.startActivity(intent)
            send(writer, "EXEC_RESULT", "Deep link triggered: $uriStr")
        } catch (e: Exception) {
            sendError(writer, "Failed to trigger deep link $uriStr: ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // app_permissions <package> [--dangerous]
    // ------------------------------------------------------------------

    private fun cmdAppPermissions(args: List<String>, writer: PrintWriter) {
        val dangerousOnly = args.contains("--dangerous")
        val pkgName = args.firstOrNull { it != "--dangerous" }
            ?: return sendError(writer, "app_permissions requires <package>")

        val info = try {
            pm.getPackageInfo(pkgName, PackageManager.GET_PERMISSIONS)
        } catch (e: PackageManager.NameNotFoundException) {
            return sendError(writer, "Package not found: $pkgName")
        }

        val requested = JSONArray()
        val granted = JSONArray()
        val names = info.requestedPermissions
        val flags = info.requestedPermissionsFlags
        if (names != null) {
            for (idx in names.indices) {
                val perm = names[idx]
                if (dangerousOnly && perm !in DANGEROUS_PERMISSIONS) continue
                requested.put(perm)
                val isGranted = flags != null && idx < flags.size &&
                    (flags[idx] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                if (isGranted) granted.put(perm)
            }
        }

        val obj = JSONObject()
        obj.put("packageName", pkgName)
        obj.put("debugMode", info.applicationInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        obj.put("systemApp", info.applicationInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0)
        obj.put("dangerousOnly", dangerousOnly)
        obj.put("requiredAppPermissions", requested)
        obj.put("grantedPermissions", granted)
        send(writer, "HDC_OUTPUT_APP_PERMISSIONS", obj.toString())
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Fully-qualify a component class name against its package. */
    private fun qualifyClassName(pkg: String, name: String): String = when {
        name.startsWith(".") -> pkg + name
        !name.contains(".")  -> "$pkg.$name"
        else                 -> name
    }

    /** Apply a "package/class" component string to an Intent. */
    private fun applyComponentOverride(intent: Intent, component: String) {
        val slash = component.indexOf('/')
        if (slash > 0 && slash < component.length - 1) {
            val p = component.substring(0, slash)
            val c = component.substring(slash + 1)
            intent.setClassName(p, qualifyClassName(p, c))
        } else {
            Log.w(TAG, "Ignoring malformed component override: $component")
        }
    }

    /** Put an Intent extra, inferring bool / int / string from the value (matches the CLI). */
    private fun putInferredExtra(intent: Intent, key: String, value: String) {
        when {
            value.equals("true", true) || value.equals("false", true) ->
                intent.putExtra(key, value.toBoolean())
            value.matches(Regex("-?\\d+")) -> {
                val asLong = value.toLongOrNull()
                if (asLong != null && asLong in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong())
                    intent.putExtra(key, asLong.toInt())
                else
                    intent.putExtra(key, value)
            }
            else -> intent.putExtra(key, value)
        }
    }

    /**
     * Apply a list of "key=value" tokens to an Intent.  `transform` is applied to each
     * raw value before use (identity for app_ability_want, fuzzing for app_ability_fuzz).
     * Special keys: action, data, mime, category, component.
     */
    private fun applyParams(intent: Intent, tokens: List<String>, transform: (String) -> String) {
        var dataUri: String? = null
        var mimeType: String? = null
        for (token in tokens) {
            val eq = token.indexOf('=')
            if (eq <= 0) continue
            val key = token.substring(0, eq)
            val value = transform(token.substring(eq + 1))
            when (key) {
                "action"    -> intent.action = value
                "data"      -> dataUri = value
                "mime"      -> mimeType = value
                "category"  -> intent.addCategory(value)
                "component" -> applyComponentOverride(intent, value)
                else        -> putInferredExtra(intent, key, value)
            }
        }
        val uri = dataUri?.let { Uri.parse(it) }
        when {
            uri != null && mimeType != null -> intent.setDataAndType(uri, mimeType)
            uri != null                     -> intent.data = uri
            mimeType != null                -> intent.type = mimeType
        }
    }

    private val fuzzAlphabet: List<Char> =
        ('a'..'z') + ('A'..'Z') + ('0'..'9') + listOf('_', '-')

    private fun fuzzString(): String {
        val len = Random.nextInt(1, 33)
        return buildString { repeat(len) { append(fuzzAlphabet.random()) } }
    }

    private fun fuzzInt(): Int = Random.nextInt(0, 1_000_001)

    private fun fuzzBool(): String = if (Random.nextBoolean()) "true" else "false"

    /** Expand fuzz markers (?s ?i ?b ?) in a raw value; non-markers pass through unchanged. */
    private fun fuzzValue(raw: String): String = when (raw.lowercase()) {
        "?s" -> fuzzString()
        "?i" -> fuzzInt().toString()
        "?b" -> fuzzBool()
        "?"  -> when (Random.nextInt(3)) {
            0 -> fuzzString()
            1 -> fuzzInt().toString()
            else -> fuzzBool()
        }
        else -> raw
    }

    private fun getPackageInfo(pkgName: String): PackageInfo? = try {
        pm.getPackageInfo(
            pkgName,
            PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_PROVIDERS or
            PackageManager.GET_PERMISSIONS
        )
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    private fun send(writer: PrintWriter, type: String, payload: String) {
        val msg = "$type:$payload"
        writer.print("$msg \n\n")
        writer.flush()
        Log.d(TAG, "Sent: ${msg.take(120)}")
    }

    private fun sendError(writer: PrintWriter, message: String) {
        Log.w(TAG, "Error: $message")
        send(writer, "HDC_OUTPUT_ERROR", message)
    }
}
