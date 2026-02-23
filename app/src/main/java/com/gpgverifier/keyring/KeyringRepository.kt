package com.gpgverifier.keyring

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import com.gpgverifier.executor.GpgExecutor
import com.gpgverifier.model.GpgKey
import com.gpgverifier.model.GpgOperationResult
import com.gpgverifier.model.VerificationResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class KeyringRepository(context: Context) {

    private val executor = GpgExecutor(context)
    private val cacheDir = context.cacheDir

    // ── Verifikasi ──────────────────────────────────────────────────────────
    suspend fun verify(dataUri: Uri, sigUri: Uri, context: Context): VerificationResult =
        withContext(Dispatchers.IO) {
            val dataFile = uriToTempFile(dataUri, context, "data_file")
            val sigFile = uriToTempFile(sigUri, context, "sig_file")
            try {
                executor.verify(dataFile, sigFile)
            } finally {
                dataFile.delete()
                sigFile.delete()
            }
        }

    // ── Key listing ─────────────────────────────────────────────────────────
    suspend fun listPublicKeys(): List<GpgKey> = withContext(Dispatchers.IO) {
        executor.listKeys()
    }

    suspend fun listSecretKeys(): List<GpgKey> = withContext(Dispatchers.IO) {
        executor.listSecretKeys()
    }

    // ── Import ──────────────────────────────────────────────────────────────
    suspend fun importKeyFromFile(uri: Uri, context: Context): GpgOperationResult =
        withContext(Dispatchers.IO) {
            val keyFile = uriToTempFile(uri, context, "import_key")
            try {
                executor.importKey(keyFile)
            } finally {
                keyFile.delete()
            }
        }

    suspend fun importKeyFromKeyserver(keyId: String, keyserver: String): GpgOperationResult =
        withContext(Dispatchers.IO) {
            executor.importKeyFromKeyserver(keyId, keyserver)
        }

    // ── Delete & Export ─────────────────────────────────────────────────────
    suspend fun deleteKey(fingerprint: String): GpgOperationResult =
        withContext(Dispatchers.IO) {
            executor.deleteKey(fingerprint)
        }

    suspend fun exportKey(fingerprint: String): GpgOperationResult =
        withContext(Dispatchers.IO) {
            executor.exportKey(fingerprint)
        }

    suspend fun trustKey(fingerprint: String, trustLevel: Int): GpgOperationResult =
        withContext(Dispatchers.IO) {
            executor.trustKey(fingerprint, trustLevel)
        }

    // ── Util ────────────────────────────────────────────────────────────────
    private fun uriToTempFile(uri: Uri, context: Context, prefix: String): File {
        val tempFile = File.createTempFile(prefix, ".tmp", cacheDir)
        context.contentResolver.openInputStream(uri)?.use { input ->
            tempFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }
        return tempFile
    }
}
