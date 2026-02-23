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
            AppLogger.log("WARN: shareFile — file tidak ditemukan: $filePath")
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
        context.startActivity(Intent.createChooser(intent, "Simpan / Bagikan File"))
        AppLogger.log("INFO: shareFile — share sheet dibuka untuk ${file.name}")
    }

    /**
     * Salin file ke folder Downloads publik.
     * Hanya tersedia di Android 9 ke bawah atau jika izin WRITE_EXTERNAL_STORAGE diberikan.
     * Di Android 10+ gunakan [shareFile] atau SAF (ACTION_CREATE_DOCUMENT).
     *
     * Mengembalikan path tujuan jika berhasil, null jika gagal.
     */
    fun saveToDownloads(context: Context, filePath: String): String? {
        return try {
            val src = File(filePath)
            if (!src.exists()) return null
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            downloadsDir.mkdirs()
            val dest = File(downloadsDir, src.name)
            FileInputStream(src).use { ins -> FileOutputStream(dest).use { ins.copyTo(it) } }
            AppLogger.log("INFO: saveToDownloads — disimpan ke ${dest.absolutePath}")
            dest.absolutePath
        } catch (e: Exception) {
            AppLogger.log("ERROR saveToDownloads: ${e.message}")
            null
        }
    }

    /**
     * Buat Intent ACTION_CREATE_DOCUMENT untuk menyimpan file via SAF (Storage Access Framework).
     * Pengguna memilih lokasi tujuan sendiri. Cocok untuk Android 10+.
     *
     * Cara pakai:
     *   val intent = FileShareHelper.createSaveIntent(outputPath)
     *   launcher.launch(intent)
     * Lalu di callback launcher salin isi file ke Uri yang dikembalikan.
     */
    fun createSaveIntent(filePath: String): Intent {
        val file = File(filePath)
        return Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_TITLE, file.name)
        }
    }

    /**
     * Salin konten dari [sourcePath] ke [destUri] yang diperoleh dari ACTION_CREATE_DOCUMENT.
     */
    fun copyToUri(context: Context, sourcePath: String, destUri: Uri): Boolean {
        return try {
            val src = File(sourcePath)
            context.contentResolver.openOutputStream(destUri)?.use { out ->
                src.inputStream().use { it.copyTo(out) }
            }
            AppLogger.log("INFO: copyToUri — berhasil menyalin ${src.name}")
            true
        } catch (e: Exception) {
            AppLogger.log("ERROR copyToUri: ${e.message}")
            false
        }
    }
}
