package com.gpgverifier.keyring

import android.content.Context
import android.net.Uri
import com.gpgverifier.executor.GpgExecutor
import com.gpgverifier.model.GpgKey
import com.gpgverifier.model.GpgOperationResult
import com.gpgverifier.model.VerificationResult
import com.gpgverifier.util.AppLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class KeyringRepository(context: Context) {

    private val executor = GpgExecutor(context)
    private val cacheDir = context.cacheDir

    // ── Verifikasi ──────────────────────────────────────────────────────────
    suspend fun verify(dataUri: Uri, sigUri: Uri, context: Context): VerificationResult =
        withContext(Dispatchers.IO) {
            AppLogger.log("INFO: Memulai proses verifikasi...")
            try {
                val dataFile = uriToTempFile(dataUri, context, "data_file")
                val sigFile = uriToTempFile(sigUri, context, "sig_file")
                try {
                    val result = executor.verify(dataFile, sigFile)
                    AppLogger.log("INFO: Verifikasi selesai.")
                    result
                } finally {
                    dataFile.delete()
                    sigFile.delete()
                }
            } catch (e: Exception) {
                AppLogger.log("CRASH di verify: ${e.message}")
                AppLogger.log("StackTrace: ${e.stackTraceToString()}")
                throw e
            }
        }

    // ── Key listing ─────────────────────────────────────────────────────────
    suspend fun listPublicKeys(): List<GpgKey> = withContext(Dispatchers.IO) {
        AppLogger.log("INFO: Mencoba list public keys...")
        try {
            val keys = executor.listKeys()
            AppLogger.log("INFO: Berhasil ambil ${keys.size} public keys.")
            keys
        } catch (e: Exception) {
            AppLogger.log("CRASH di listPublicKeys: ${e.message}")
            AppLogger.log("StackTrace: ${e.stackTraceToString()}")
            emptyList<GpgKey>()
        }
    }

    suspend fun listSecretKeys(): List<GpgKey> = withContext(Dispatchers.IO) {
        AppLogger.log("INFO: Mencoba list secret keys...")
        try {
            val keys = executor.listSecretKeys()
            AppLogger.log("INFO: Berhasil ambil ${keys.size} secret keys.")
            keys
        } catch (e: Exception) {
            AppLogger.log("CRASH di listSecretKeys: ${e.message}")
            AppLogger.log("StackTrace: ${e.stackTraceToString()}")
            emptyList<GpgKey>()
        }
    }

    // ── Import ──────────────────────────────────────────────────────────────
    suspend fun importKeyFromFile(uri: Uri, context: Context): GpgOperationResult =
        withContext(Dispatchers.IO) {
            AppLogger.log("INFO: Mencoba import key dari file...")
            try {
                val keyFile = uriToTempFile(uri, context, "import_key")
                try {
                    executor.importKey(keyFile)
                } finally {
                    keyFile.delete()
                }
            } catch (e: Exception) {
                AppLogger.log("CRASH di importKeyFromFile: ${e.message}")
                AppLogger.log("StackTrace: ${e.stackTraceToString()}")
                throw e
            }
        }

    suspend fun importKeyFromKeyserver(keyId: String, keyserver: String): GpgOperationResult =
        withContext(Dispatchers.IO) {
            AppLogger.log("INFO: Import dari keyserver: $keyserver")
            try {
                executor.importKeyFromKeyserver(keyId, keyserver)
            } catch (e: Exception) {
                AppLogger.log("CRASH di importKeyFromKeyserver: ${e.message}")
                AppLogger.log("StackTrace: ${e.stackTraceToString()}")
                throw e
            }
        }

    // ── Delete & Export ─────────────────────────────────────────────────────
    suspend fun deleteKey(fingerprint: String): GpgOperationResult =
        withContext(Dispatchers.IO) {
            try {
                executor.deleteKey(fingerprint)
            } catch (e: Exception) {
                AppLogger.log("CRASH di deleteKey: ${e.message}")
                throw e
            }
        }

    suspend fun exportKey(fingerprint: String): GpgOperationResult =
        withContext(Dispatchers.IO) {
            try {
                executor.exportKey(fingerprint)
            } catch (e: Exception) {
                AppLogger.log("CRASH di exportKey: ${e.message}")
                throw e
            }
        }

    suspend fun trustKey(fingerprint: String, trustLevel: Int): GpgOperationResult =
        withContext(Dispatchers.IO) {
            try {
                executor.trustKey(fingerprint, trustLevel)
            } catch (e: Exception) {
                AppLogger.log("CRASH di trustKey: ${e.message}")
                throw e
            }
        }

    // ── Util ────────────────────────────────────────────────────────────────
    private fun uriToTempFile(uri: Uri, context: Context, prefix: String): File {
        return try {
            val tempFile = File.createTempFile(prefix, ".tmp", cacheDir)
            context.contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            } ?: throw Exception("Gagal buka InputStream dari Uri")
            tempFile
        } catch (e: Exception) {
            AppLogger.log("ERROR di uriToTempFile: ${e.message}")
            throw e
        }
    }
}
