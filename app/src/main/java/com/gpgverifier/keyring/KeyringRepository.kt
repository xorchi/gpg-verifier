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
            AppLogger.log("DEBUG: verify dipanggil")
            val dataFile = uriToTempFile(dataUri, context, "data_file")
            val sigFile  = uriToTempFile(sigUri,  context, "sig_file")
            try {
                executor.verify(dataFile, sigFile).also {
                    AppLogger.log("INFO: Verifikasi ${if (it.isValid) "sukses" else "gagal"}")
                }
            } finally { dataFile.delete(); sigFile.delete() }
        }

    // ── Verify ClearSign (single file) ───────────────────────────────────────
    suspend fun verifyClearSign(clearSignUri: Uri, context: Context): VerificationResult =
        withContext(Dispatchers.IO) {
            AppLogger.log("DEBUG: verifyClearSign dipanggil")
            val clearSignFile = uriToTempFile(clearSignUri, context, "clearsign_file")
            try {
                executor.verifyClearSign(clearSignFile).also {
                    AppLogger.log("INFO: ClearSign verifikasi ${if (it.isValid) "sukses" else "gagal"}")
                }
            } finally { clearSignFile.delete() }
        }

    // ── Sign ─────────────────────────────────────────────────────────────────
    suspend fun sign(
        dataUri: Uri, context: Context,
        keyFingerprint: String, mode: SignMode, passphrase: String
    ): SignResult = withContext(Dispatchers.IO) {
        val dataFile = uriToTempFile(dataUri, context, "sign_input")
        val originalName = getOriginalFileName(dataUri, context)
        try { executor.sign(dataFile, keyFingerprint, mode, passphrase, originalName) }
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
        try { AppLogger.log("DEBUG: Mencoba listPublicKeys"); executor.listKeys() }
        catch (e: Exception) { AppLogger.log("ERROR listPublicKeys: ${e.message}"); emptyList() }
    }

    suspend fun listSecretKeys(): List<GpgKey> = withContext(Dispatchers.IO) {
        try { executor.listSecretKeys() }
        catch (e: Exception) { AppLogger.log("ERROR listSecretKeys: ${e.message}"); emptyList() }
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
        withContext(Dispatchers.IO) { executor.backupPublicKey(fingerprint)

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
        // Coba baca display name via ContentResolver
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val col = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (col != -1 && cursor.moveToFirst()) {
                val name = cursor.getString(col)
                if (!name.isNullOrBlank()) return name
            }
        }
        // Fallback: ambil segmen terakhir dari path URI
        return uri.lastPathSegment?.substringAfterLast('/')?.substringAfterLast(':') ?: "output"
    }
}
