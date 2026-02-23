package com.gpgverifier.executor

import android.content.Context
import com.gpgverifier.model.GpgKey
import com.gpgverifier.model.GpgOperationResult
import com.gpgverifier.model.VerificationResult
import com.gpgverifier.util.AppLogger
import java.io.File

class GpgExecutor(private val context: Context) {
    private val gpgBinary: File by lazy {
        val file = File(context.filesDir, "gpg")
        if (!file.exists()) {
            AppLogger.log("DEBUG: Copying binary from assets...")
            context.assets.open("gpg").use { input ->
                file.outputStream().use { output -> input.copyTo(output) }
            }
        }
        file.setExecutable(true)
        AppLogger.log("DEBUG: Binary GPG path: ${file.absolutePath}, Executable: ${file.canExecute()}")
        file
    }

    private val gpgDir: File by lazy {
        val dir = File(context.filesDir, ".gnupg")
        if (!dir.exists()) dir.mkdirs()
        dir
    }

    fun verify(dataFile: File, sigFile: File): VerificationResult {
        val output = runGpg("--verify", sigFile.absolutePath, dataFile.absolutePath)
        AppLogger.log("DEBUG: GPG Output: ${output.message}")
        return VerificationResult(
            isValid = output.exitCode == 0,
            details = output.message,
            signer = "Unknown" 
        )
    }

    fun listKeys(): List<GpgKey> {
        val output = runGpg("--list-keys", "--with-colons")
        if (output.exitCode != 0) AppLogger.log("DEBUG: ListKeys error: ${output.message}")
        // Parsing logic disederhanakan dulu buat debug
        return emptyList() 
    }

    fun listSecretKeys(): List<GpgKey> {
        runGpg("--list-secret-keys", "--with-colons")
        return emptyList()
    }

    fun importKey(keyFile: File): GpgOperationResult = runGpg("--import", keyFile.absolutePath)
    fun importKeyFromKeyserver(keyId: String, keyserver: String): GpgOperationResult = runGpg("--keyserver", keyserver, "--recv-keys", keyId)
    fun trustKey(fingerprint: String, trustLevel: Int): GpgOperationResult = runGpg("--import-ownertrust") // simplified
    fun deleteKey(fingerprint: String): GpgOperationResult = runGpg("--delete-key", fingerprint)
    fun exportKey(fingerprint: String): GpgOperationResult = runGpg("--export", "--armor", fingerprint)

    private fun runGpg(vararg args: String): GpgOperationResult {
        return try {
            val command = mutableListOf(gpgBinary.absolutePath, "--homedir", gpgDir.absolutePath)
            command.addAll(args)
            
            AppLogger.log("DEBUG: Running: ${command.joinToString(" ")}")
            
            val process = ProcessBuilder(command)
                .redirectErrorStream(true)
                .start()
            
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            
            GpgOperationResult(exitCode == 0, output, exitCode)
        } catch (e: Exception) {
            AppLogger.log("CRASH runGpg: ${e.message}")
            GpgOperationResult(false, e.message ?: "Unknown error", -1)
        }
    }
}
