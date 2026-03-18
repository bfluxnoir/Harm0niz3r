package com.dekra.harm0niz3r

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * Minimal launcher Activity.
 * Its only job is to start/stop the Harm0nizerService and show status.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var toggleButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        toggleButton = findViewById(R.id.toggleButton)

        toggleButton.setOnClickListener {
            if (Harm0nizerService.isRunning) {
                stopService(Intent(this, Harm0nizerService::class.java))
                updateUi(running = false)
            } else {
                startForegroundService(Intent(this, Harm0nizerService::class.java))
                updateUi(running = true)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        updateUi(Harm0nizerService.isRunning)
    }

    private fun updateUi(running: Boolean) {
        if (running) {
            statusText.text = getString(R.string.status_running, Harm0nizerService.PORT)
            toggleButton.text = getString(R.string.stop_service)
        } else {
            statusText.text = getString(R.string.status_stopped)
            toggleButton.text = getString(R.string.start_service)
        }
    }
}
