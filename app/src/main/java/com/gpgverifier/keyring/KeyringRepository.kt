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

    suspend fun verify(dataUri: Uri, sigUri: Uri, context: Context): VerificationResult =
        withContext(Dispatchers.IO) {
            AppLogger.log("DEBUG: verify dipanggil")
            try {
                val dataFile = uriToTempFile(dataUri, context, "data_file")
                val sigFile = uriToTempFile(sigUri, context, "sig_file")
                AppLogger.log("DEBUG: Temp files created: ${dataFile.absolutePath}")
                try {
                    val result = executor.verify(dataFile, sigFile)
                    AppLogger.log("INFO: Verifikasi sukses")
                    result
                } finally {
                    dataFile.delete()
                    sigFile.delete()
                }
            } catch (e: Exception) {
                AppLogger.log("ERROR verify: ${e.message}\n${e.stackTraceToString()}")
                throw e
            }
        }

    suspend fun listPublicKeys(): List<GpgKey> = withContext(Dispatchers.IO) {
        try {
            AppLogger.log("DEBUG: Mencoba listPublicKeys")
            executor.listKeys()
        } catch (e: Exception) {
            AppLogger.log("ERROR listPublicKeys: ${e.message}")
            emptyList()
        }
    }

    suspend fun listSecretKeys(): List<GpgKey> = withContext(Dispatchers.IO) {
        try {
            AppLogger.log("DEBUG: Mencoba listSecretKeys")
            executor.listSecretKeys()
        } catch (e: Exception) {
            AppLogger.log("ERROR listSecretKeys: ${e.message}")
            emptyList()
        }
    }

    suspend fun importKeyFromFile(uri: Uri, context: Context): GpgOperationResult = withContext(Dispatchers.IO) {
        try {
            val keyFile = uriToTempFile(uri, context, "import_key")
            try { executor.importKey(keyFile) } finally { keyFile.delete() }
        } catch (e: Exception) {
            AppLogger.log("ERROR importKey: ${e.message}")
            throw e
        }
    }

    suspend fun importKeyFromKeyserver(keyId: String, keyserver: String): GpgOperationResult = withContext(Dispatchers.IO) {
        try { executor.importKeyFromKeyserver(keyId, keyserver) } catch (e: Exception) { throw e }
    }

    suspend fun trustKey(fingerprint: String, trustLevel: Int): GpgOperationResult = withContext(Dispatchers.IO) {
        try { executor.trustKey(fingerprint, trustLevel) } catch (e: Exception) { throw e }
    }

    suspend fun deleteKey(fingerprint: String): GpgOperationResult = withContext(Dispatchers.IO) {
        try { executor.deleteKey(fingerprint) } catch (e: Exception) { throw e }
    }

    suspend fun exportKey(fingerprint: String): GpgOperationResult = withContext(Dispatchers.IO) {
        try { executor.exportKey(fingerprint) } catch (e: Exception) { throw e }
    }

    private fun uriToTempFile(uri: Uri, context: Context, prefix: String): File {
        val tempFile = File.createTempFile(prefix, ".tmp", cacheDir)
        context.contentResolver.openInputStream(uri)?.use { input ->
            tempFile.outputStream().use { output -> input.copyTo(output) }
        }
        return tempFile
    }
}
