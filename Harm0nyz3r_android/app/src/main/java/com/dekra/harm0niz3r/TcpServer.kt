package com.dekra.harm0niz3r

import android.content.Context
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException

private const val TAG = "TcpServer"

/**
 * TCP server that listens on 127.0.0.1:<port>.
 *
 * Protocol (mirrors the HarmonyOS ArkTS agent):
 *   1. Python host sends  "MARCO \n\n"
 *   2. Agent replies      "POLO:android:2.0"
 *   3. Full-duplex message exchange begins.
 *
 * Messages from host end with " \n\n" (space + newline + newline).
 * Messages sent to host also end with " \n\n".
 */
class TcpServer(
    private val port: Int,
    private val context: Context,
    private val onStatusChange: (String) -> Unit
) : Runnable {

    @Volatile
    private var running = true
    private var serverSocket: ServerSocket? = null

    override fun run() {
        try {
            serverSocket = ServerSocket(port, 1, InetAddress.getLoopbackAddress())
            onStatusChange("Listening on 127.0.0.1:$port")
            Log.i(TAG, "TCP server listening on port $port")

            while (running) {
                val client = try {
                    serverSocket?.accept() ?: break
                } catch (e: SocketException) {
                    if (running) Log.e(TAG, "Accept error: ${e.message}")
                    break
                }
                // Keep the connection alive when idle so the OS detects broken tunnels
                try { client.keepAlive = true } catch (_: Exception) {}
                onStatusChange("Client connected: ${client.inetAddress.hostAddress}")
                Thread({ handleClient(client) }, "Harm0nizer-Client").start()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Server error: ${e.message}")
        } finally {
            onStatusChange("Server stopped")
        }
    }

    fun stop() {
        running = false
        try {
            serverSocket?.close()
        } catch (_: Exception) {}
    }

    // ------------------------------------------------------------------
    // Client session
    // ------------------------------------------------------------------

    private fun handleClient(socket: Socket) {
        Log.i(TAG, "Handling client session")
        try {
            val reader = BufferedReader(InputStreamReader(socket.inputStream, Charsets.UTF_8))
            val writer = PrintWriter(socket.outputStream, true)

            // --- MARCO-POLO handshake ---
            val handshake = readMessage(reader) ?: run {
                Log.w(TAG, "Client disconnected before handshake")
                return
            }
            if (handshake.trim() != "MARCO") {
                Log.w(TAG, "Unexpected handshake: '$handshake'")
                return
            }
            // Include platform tag so the Python server knows what it is talking to
            sendMessage(writer, "POLO:android:2.0")
            onStatusChange("Session established")
            Log.i(TAG, "MARCO-POLO handshake complete")

            // --- Command loop ---
            val handler = CommandHandler(context)
            while (running && !socket.isClosed) {
                val msg = readMessage(reader) ?: break
                Log.d(TAG, "Received: $msg")
                handler.handle(msg.trim(), writer)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Client session error: ${e.message}")
        } finally {
            try { socket.close() } catch (_: Exception) {}
            onStatusChange("Client disconnected. Listening on port $port…")
            Log.i(TAG, "Client session closed")
        }
    }

    // ------------------------------------------------------------------
    // Message framing  (matching HarmonyOS " \n\n" convention)
    // ------------------------------------------------------------------

    /**
     * Read bytes until " \n\n" terminator, return the content before it.
     * Returns null on EOF / disconnect.
     */
    private fun readMessage(reader: BufferedReader): String? {
        val sb = StringBuilder()
        try {
            while (true) {
                val line = reader.readLine()
                if (line == null) {
                    Log.d(TAG, "readMessage: EOF — remote end closed the stream")
                    return null
                }
                sb.append(line).append('\n')
                // The Python host sends "payload \n\n" — after stripping the trailing
                // newline each readLine() call adds, we detect the empty-line sentinel.
                if (line.isBlank() && sb.length > 1) {
                    // Trim the accumulated trailing whitespace/newlines
                    return sb.toString().trimEnd()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "readMessage: exception — ${e.javaClass.simpleName}: ${e.message}")
            return null
        }
    }

    fun sendMessage(writer: PrintWriter, message: String) {
        writer.print("$message \n\n")
        writer.flush()
    }
}
