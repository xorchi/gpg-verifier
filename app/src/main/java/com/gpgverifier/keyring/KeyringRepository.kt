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

    suspend fun verify(dataUri: Uri, sigUri: Uri, context: Context): VerificationResult = withContext(Dispatchers.IO) {
        AppLogger.log("INFO: Memulai verifikasi")
        try {
            val dataFile = uriToTempFile(dataUri, context, "data")
            val sigFile = uriToTempFile(sigUri, context, "sig")
            try {
                executor.verify(dataFile, sigFile)
            } finally {
                dataFile.delete()
                sigFile.delete()
            }
        } catch (e: Exception) {
            AppLogger.log("CRASH verify: ${e.stackTraceToString()}")
            throw e
        }
    }

    suspend fun listPublicKeys(): List<GpgKey> = withContext(Dispatchers.IO) {
        try {
            executor.listKeys()
        } catch (e: Exception) {
            AppLogger.log("CRASH listPublicKeys: ${e.message}")
            emptyList()
        }
    }

    suspend fun importKeyFromFile(uri: Uri, context: Context): GpgOperationResult = withContext(Dispatchers.IO) {
        try {
            val file = uriToTempFile(uri, context, "import")
            try {
                executor.importKey(file)
            } finally {
                file.delete()
            }
        } catch (e: Exception) {
            AppLogger.log("CRASH importKey: ${e.stackTraceToString()}")
            throw e
        }
    }

    private fun uriToTempFile(uri: Uri, context: Context, prefix: String): File {
        val file = File.createTempFile(prefix, null, cacheDir)
        context.contentResolver.openInputStream(uri)?.use { input ->
            file.outputStream().use { output -> input.copyTo(output) }
        }
        return file
    }
    
    // Tambahkan stub untuk fungsi lain yang lu butuhkan (delete, trust, dll) agar tidak error compile
    suspend fun deleteKey(fp: String): GpgOperationResult = executor.deleteKey(fp)
    suspend fun exportKey(fp: String): GpgOperationResult = executor.exportKey(fp)
}
