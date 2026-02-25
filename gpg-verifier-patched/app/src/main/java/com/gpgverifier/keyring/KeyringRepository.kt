package com.gpgverifier.keyring

import android.content.Context
import android.net.Uri
import com.gpgverifier.executor.GpgExecutor
import com.gpgverifier.model.*
import com.gpgverifier.util.AppLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class KeyringRepository(context: Context) {
    private val executor = GpgExecutor(context)
    private val cacheDir = context.cacheDir

    // ── Verify (detached) ────────────────────────────────────────────────────
    suspend fun verify(dataUri: Uri, sigUri: Uri, context: Context): VerificationResult =
        withContext(Dispatchers.IO) {
            AppLogger.d("verify() dispatched — dataUri=$dataUri sigUri=$sigUri", AppLogger.TAG_IO)
            val dataFile = uriToTempFile(dataUri, context, "data_file")
            val sigFile  = uriToTempFile(sigUri,  context, "sig_file")
            try {
                executor.verify(dataFile, sigFile).also {
                    AppLogger.i("verify() result=${if (it.isValid) "VALID" else "INVALID"} signedBy=${it.signedBy} hash=${it.hashAlgorithm}", AppLogger.TAG_CRYPTO)
                }
            } finally { dataFile.delete(); sigFile.delete() }
        }

    // ── Verify ClearSign (single file) ───────────────────────────────────────
    suspend fun verifyClearSign(clearSignUri: Uri, context: Context): VerificationResult =
        withContext(Dispatchers.IO) {
            AppLogger.d("verifyClearSign() dispatched — clearSignUri=$clearSignUri", AppLogger.TAG_IO)
            val clearSignFile = uriToTempFile(clearSignUri, context, "clearsign_file")
            try {
                executor.verifyClearSign(clearSignFile).also {
                    AppLogger.i("verifyClearSign() result=${if (it.isValid) "VALID" else "INVALID"} signedBy=${it.signedBy} hash=${it.hashAlgorithm}", AppLogger.TAG_CRYPTO)
                }
            } finally { clearSignFile.delete() }
        }

    // ── Sign ─────────────────────────────────────────────────────────────────
    suspend fun sign(
        dataUri: Uri, context: Context,
        keyFingerprint: String, mode: SignMode, passphrase: String,
        hashAlgorithm: com.gpgverifier.model.HashAlgorithm = com.gpgverifier.model.HashAlgorithm.SHA256
    ): SignResult = withContext(Dispatchers.IO) {
        val dataFile = uriToTempFile(dataUri, context, "sign_input")
        val originalName = getOriginalFileName(dataUri, context)
        try { executor.sign(dataFile, keyFingerprint, mode, passphrase, originalName, hashAlgorithm) }
        finally { dataFile.delete() }
    }

    // ── Encrypt (asymmetric) ──────────────────────────────────────────────────
    suspend fun encrypt(
        dataUri: Uri, context: Context,
        recipientFingerprints: List<String>, armor: Boolean
    ): EncryptResult = withContext(Dispatchers.IO) {
        val dataFile = uriToTempFile(dataUri, context, "enc_input")
        val originalName = getOriginalFileName(dataUri, context)
        try { executor.encrypt(dataFile, recipientFingerprints, armor, originalName) }
        finally { dataFile.delete() }
    }

    // ── Encrypt (symmetric) ───────────────────────────────────────────────────
    suspend fun encryptSymmetric(
        dataUri: Uri, context: Context,
        passphrase: String, armor: Boolean
    ): EncryptResult = withContext(Dispatchers.IO) {
        val dataFile = uriToTempFile(dataUri, context, "enc_sym_input")
        val originalName = getOriginalFileName(dataUri, context)
        try { executor.encryptSymmetric(dataFile, passphrase, armor, originalName) }
        finally { dataFile.delete() }
    }

    // ── Decrypt ──────────────────────────────────────────────────────────────
    suspend fun decrypt(
        dataUri: Uri, context: Context, passphrase: String
    ): DecryptResult = withContext(Dispatchers.IO) {
        val dataFile = uriToTempFile(dataUri, context, "dec_input")
        try { executor.decrypt(dataFile, passphrase) }
        finally { dataFile.delete() }
    }

    // ── Keys ─────────────────────────────────────────────────────────────────
    suspend fun listPublicKeys(): List<GpgKey> = withContext(Dispatchers.IO) {
        try { AppLogger.d("listPublicKeys() starting", AppLogger.TAG_KEYRING); executor.listKeys() }
        catch (e: Exception) { AppLogger.ex("listPublicKeys", e, AppLogger.TAG_KEYRING); emptyList() }
    }

    suspend fun listSecretKeys(): List<GpgKey> = withContext(Dispatchers.IO) {
        try { executor.listSecretKeys() }
        catch (e: Exception) { AppLogger.ex("listSecretKeys", e, AppLogger.TAG_KEYRING); emptyList() }
    }

    suspend fun importKeyFromFile(uri: Uri, context: Context): GpgOperationResult =
        withContext(Dispatchers.IO) {
            val keyFile = uriToTempFile(uri, context, "import_key")
            try { executor.importKey(keyFile) } finally { keyFile.delete() }
        }

    suspend fun importKeyFromKeyserver(keyId: String, keyserver: String): GpgOperationResult =
        withContext(Dispatchers.IO) { executor.importKeyFromKeyserver(keyId, keyserver) }

    suspend fun generateKey(params: KeyGenParams): GpgOperationResult =
        withContext(Dispatchers.IO) { executor.generateKey(params) }

    suspend fun trustKey(fingerprint: String, trustLevel: Int): GpgOperationResult =
        withContext(Dispatchers.IO) { executor.trustKey(fingerprint, trustLevel) }

    suspend fun deleteKey(fingerprint: String): GpgOperationResult =
        withContext(Dispatchers.IO) { executor.deleteKey(fingerprint) }

    suspend fun exportKey(fingerprint: String, armor: Boolean = true, secret: Boolean = false): GpgOperationResult =
        withContext(Dispatchers.IO) { executor.exportKey(fingerprint, armor, secret) }

    suspend fun backupPublicKey(fingerprint: String): GpgOperationResult =
        withContext(Dispatchers.IO) { executor.backupPublicKey(fingerprint) }

    suspend fun backupSecretKey(fingerprint: String): GpgOperationResult =
        withContext(Dispatchers.IO) { executor.backupSecretKey(fingerprint) }

    suspend fun backupAllPublicKeys(): GpgOperationResult =
        withContext(Dispatchers.IO) { executor.backupAllPublicKeys() }

    suspend fun backupAllSecretKeys(): GpgOperationResult =
        withContext(Dispatchers.IO) { executor.backupAllSecretKeys() }

    suspend fun verifyEmbedded(uri: android.net.Uri, context: android.content.Context): VerificationResult =
        withContext(Dispatchers.IO) {
            val tmp = java.io.File(context.cacheDir, "embedded_${System.currentTimeMillis()}.tmp")
            try {
                context.contentResolver.openInputStream(uri)?.use { tmp.outputStream().use { o -> it.copyTo(o) } }
                executor.verifyEmbedded(tmp)
            } finally { tmp.delete() }
        }

    suspend fun exportKeyToKeyserver(fingerprint: String, keyserver: String): GpgOperationResult =
        withContext(Dispatchers.IO) { executor.exportKeyToKeyserver(fingerprint, keyserver) }

    // ── Helpers ──────────────────────────────────────────────────────────────
    private fun uriToTempFile(uri: Uri, context: Context, prefix: String): File {
        val temp = File.createTempFile(prefix, ".tmp", cacheDir)
        context.contentResolver.openInputStream(uri)?.use { it.copyTo(temp.outputStream()) }
        return temp
    }

    private fun getOriginalFileName(uri: Uri, context: Context): String {
        // Try to read display name via ContentResolver
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val col = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (col != -1 && cursor.moveToFirst()) {
                val name = cursor.getString(col)
                if (!name.isNullOrBlank()) return name
            }
        }
        // Fallback: use last path segment of the URI
        return uri.lastPathSegment?.substringAfterLast('/')?.substringAfterLast(':') ?: "output"
    }
}
