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
     * Bagikan file output via Android share sheet.
     * Menggunakan FileProvider sehingga tidak memerlukan izin storage apapun.
     */
    fun shareFile(context: Context, filePath: String) {
        val file = File(filePath)
        if (!file.exists()) {
            AppLogger.w("shareFile() file not found: $filePath", AppLogger.TAG_IO)
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
        AppLogger.i("shareFile() share sheet opened for ${file.name}", AppLogger.TAG_IO)
    }

    fun saveToDownloads(context: Context, filePath: String): String? {
        return try {
            val src = File(filePath)
            if (!src.exists()) return null
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            downloadsDir.mkdirs()
            val dest = File(downloadsDir, src.name)
            FileInputStream(src).use { ins -> FileOutputStream(dest).use { ins.copyTo(it) } }
            AppLogger.i("saveToDownloads() saved to ${dest.absolutePath} (${dest.length()} bytes)", AppLogger.TAG_IO)
            dest.absolutePath
        } catch (e: Exception) {
            AppLogger.ex("saveToDownloads", e, AppLogger.TAG_IO)
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
            AppLogger.i("copyToUri() successfully copied ${src.name}", AppLogger.TAG_IO)
            true
        } catch (e: Exception) {
            AppLogger.ex("copyToUri", e, AppLogger.TAG_IO)
            false
        }
    }
}
