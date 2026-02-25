package com.gpgverifier.util

import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.*

object AppLogger {
    private const val TAG = "GPGVerifier"
    private const val MAX_LOG_BYTES = 512 * 1024L // rotate di 512 KB

    private var logFile: File? = null
    private val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())

    fun init(filesDir: File) {
        val dir = File(filesDir, "logs").also { it.mkdirs() }
        logFile = File(dir, "app.log").also { rotateIfNeeded(it) }
    }

    fun log(message: String) {
        when {
            message.startsWith("ERROR") -> Log.e(TAG, message)
            message.startsWith("WARN")  -> Log.w(TAG, message)
            else                        -> Log.d(TAG, message)
        }
        logFile?.let { file ->
            try {
                FileOutputStream(file, true).use {
                    it.write("[${fmt.format(Date())}] $message\n".toByteArray())
                }
                rotateIfNeeded(file)
            } catch (e: Exception) {
                Log.e(TAG, "Logger write failed: ${e.message}")
            }
        }
    }

    fun readLogs(): String = logFile?.takeIf { it.exists() }?.readText() ?: "(log empty)"

    fun clearLogs() { logFile?.delete(); logFile?.createNewFile() }

    private fun rotateIfNeeded(file: File) {
        if (file.exists() && file.length() > MAX_LOG_BYTES) {
            File(file.parent, "app.log.bak").also { it.delete() }
            file.renameTo(File(file.parent, "app.log.bak"))
        }
    }
}
