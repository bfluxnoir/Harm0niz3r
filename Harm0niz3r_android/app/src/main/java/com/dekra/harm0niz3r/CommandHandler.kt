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

private const val TAG = "CommandHandler"

/**
 * Processes commands received from the Python server and writes responses
 * back through [writer].
 *
 * Message format from server:  "COMMAND_REQUEST:<cmd> [args...]"
 * Response format to server:   "<TYPE>:<payload> \n\n"  (framing done by TcpServer.sendMessage)
 *
 * Supported commands
 * ------------------
 * apps_list                       → HDC_OUTPUT_ALL_APPS:<json array of package names>
 * app_surface <package>           → HDC_OUTPUT_APP_SURFACE_JSON:<json>
 * app_info <package>              → HDC_OUTPUT_APP_DETAILS:<json>
 * apps_visible_abilities          → HDC_OUTPUT_EXPOSED_ABILITIES:<json>
 * app_ability <pkg> <activity>    → (starts Activity, no response body)
 * shell_exec <cmd>                → EXEC_RESULT:<output>
 * app_provider <authority> [projection] → UDMF_QUERY_RESULT:<json>
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
        send(writer, "UDMF_QUERY_RESULT", result.toString())
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

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
