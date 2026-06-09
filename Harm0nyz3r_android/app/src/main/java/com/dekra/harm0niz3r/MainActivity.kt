package com.dekra.harm0niz3r

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

/**
 * Minimal launcher Activity.
 * Starts / stops the Harm0niz3rService, exposes the listening port for the
 * user to edit, and surfaces the current status.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var toggleButton: Button
    private lateinit var portEdit: EditText
    private lateinit var portHintText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText   = findViewById(R.id.statusText)
        toggleButton = findViewById(R.id.toggleButton)
        portEdit     = findViewById(R.id.portEdit)
        portHintText = findViewById(R.id.portHintText)

        // Seed the edit field with the persisted choice.
        portEdit.setText(Harm0niz3rService.readPort(this).toString())

        toggleButton.setOnClickListener {
            if (Harm0niz3rService.isRunning) {
                stopService(Intent(this, Harm0niz3rService::class.java))
                updateUi(running = false)
            } else {
                // Persist the user's port choice before starting.  Invalid input
                // falls back to the last-saved value and we let the user know.
                val typed = portEdit.text.toString().toIntOrNull()
                if (typed != null && typed in 1024..65535) {
                    Harm0niz3rService.writePort(this, typed)
                } else {
                    val saved = Harm0niz3rService.readPort(this)
                    portEdit.setText(saved.toString())
                    Toast.makeText(
                        this,
                        getString(R.string.port_invalid, saved),
                        Toast.LENGTH_SHORT
                    ).show()
                }
                startForegroundService(Intent(this, Harm0niz3rService::class.java))
                updateUi(running = true)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        updateUi(Harm0niz3rService.isRunning)
        // Refresh the field in case the user changed it via 'adb shell' between launches.
        portEdit.setText(Harm0niz3rService.readPort(this).toString())
    }

    private fun updateUi(running: Boolean) {
        val port = if (running) Harm0niz3rService.activePort
                   else Harm0niz3rService.readPort(this)
        if (running) {
            statusText.text = getString(R.string.status_running, port)
            toggleButton.text = getString(R.string.stop_service)
            portEdit.isEnabled = false
        } else {
            statusText.text = getString(R.string.status_stopped)
            toggleButton.text = getString(R.string.start_service)
            portEdit.isEnabled = true
        }
        portHintText.text = getString(R.string.port_hint, port)
    }
}
