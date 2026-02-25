package com.gpgverifier.util

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import androidx.core.content.FileProvider
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

object FileShareHelper {

    /**
     * Share output file via Android share sheet.
     * Uses FileProvider so no storage permission is required.
     */
    fun shareFile(context: Context, filePath: String) {
        val file = File(filePath)
        if (!file.exists()) {
            AppLogger.log("WARN: shareFile — file not found: $filePath")
            return
        }
        val uri: Uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "*/*"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Save / Share Files"))
        AppLogger.log("INFO: shareFile — share sheet opened for ${file.name}")
    }

    fun saveToDownloads(context: Context, filePath: String): String? {
        return try {
            val src = File(filePath)
            if (!src.exists()) return null
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            downloadsDir.mkdirs()
            val dest = File(downloadsDir, src.name)
            FileInputStream(src).use { ins -> FileOutputStream(dest).use { ins.copyTo(it) } }
            AppLogger.log("INFO: saveToDownloads — saved to ${dest.absolutePath}")
            dest.absolutePath
        } catch (e: Exception) {
            AppLogger.log("ERROR saveToDownloads: ${e.message}")
            null
        }
    }

    fun createSaveIntent(filePath: String): Intent {
        val file = File(filePath)
        return Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_TITLE, file.name)
        }
    }

    fun copyToUri(context: Context, sourcePath: String, destUri: Uri): Boolean {
        return try {
            val src = File(sourcePath)
            context.contentResolver.openOutputStream(destUri)?.use { out ->
                src.inputStream().use { it.copyTo(out) }
            }
            AppLogger.log("INFO: copyToUri — successfully copied ${src.name}")
            true
        } catch (e: Exception) {
            AppLogger.log("ERROR copyToUri: ${e.message}")
            false
        }
    }
}
