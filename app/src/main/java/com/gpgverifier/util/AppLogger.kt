package com.gpgverifier.util

import android.os.Environment
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.*

object AppLogger {
    fun log(message: String) {
        try {
            // Langsung tembak ke folder Download
            val downloadDir = File("/storage/emulated/0/Download")
            if (!downloadDir.exists()) {
                downloadDir.mkdirs()
            }
            
            val logFile = File(downloadDir, "gpg_debug_log.txt")
            val timeStamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
            val logEntry = "[$timeStamp] $message\n"
            
            FileOutputStream(logFile, true).use { 
                it.write(logEntry.toByteArray()) 
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
