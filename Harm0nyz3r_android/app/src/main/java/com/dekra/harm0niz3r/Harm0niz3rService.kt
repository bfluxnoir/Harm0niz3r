package com.dekra.harm0niz3r

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * Foreground service that owns the TCP server lifecycle.
 * Survives app minimisation so the connection to the Python host stays alive.
 */
class Harm0niz3rService : Service() {

    companion object {
        const val TAG = "Harm0niz3rService"
        const val DEFAULT_PORT = 51337
        private const val PREFS_NAME = "harm0niz3r_prefs"
        private const val KEY_PORT = "agent_port"
        private const val CHANNEL_ID = "harm0niz3r_channel"
        private const val NOTIFICATION_ID = 1337

        @Volatile
        var isRunning = false
            private set

        /** Port the service is currently bound to (DEFAULT_PORT until first start). */
        @Volatile
        var activePort: Int = DEFAULT_PORT
            private set

        /** Read the persisted port (or DEFAULT_PORT on first launch). */
        fun readPort(context: Context): Int {
            return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getInt(KEY_PORT, DEFAULT_PORT)
        }

        /** Persist a new port choice; takes effect at the next service start. */
        fun writePort(context: Context, port: Int) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putInt(KEY_PORT, port)
                .apply()
        }
    }

    private var tcpServer: TcpServer? = null

    // ------------------------------------------------------------------
    // Service lifecycle
    // ------------------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val port = readPort(applicationContext)
        activePort = port
        Log.i(TAG, "Service starting on port $port")
        startForeground(NOTIFICATION_ID, buildNotification("Listening on port $port…"))
        isRunning = true

        tcpServer = TcpServer(
            port = port,
            context = applicationContext,
            onStatusChange = { msg ->
                Log.i(TAG, msg)
                updateNotification(msg)
            }
        )
        Thread(tcpServer, "Harm0niz3r-TCP").start()

        return START_STICKY
    }

    override fun onDestroy() {
        Log.i(TAG, "Service stopping")
        isRunning = false
        tcpServer?.stop()
        tcpServer = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ------------------------------------------------------------------
    // Notification helpers
    // ------------------------------------------------------------------

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Harm0niz3r Agent",
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = "Background TCP agent for security assessment" }
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(channel)
    }

    private fun buildNotification(contentText: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Harm0niz3r Agent")
            .setContentText(contentText)
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }
}
