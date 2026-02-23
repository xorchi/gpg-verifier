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
        AppLogger.log("DEBUG: Menjalankan verify...")
        val output = runGpgRaw("--verify", sigFile.absolutePath, dataFile.absolutePath)
        AppLogger.log("DEBUG: Raw Output: $output")
        throw Exception("Cek log untuk hasil verifikasi: $output")
    }

    fun listKeys(): List<GpgKey> {
        AppLogger.log("DEBUG: Menjalankan list-keys...")
        runGpgRaw("--list-keys", "--with-colons")
        return emptyList()
    }

    fun listSecretKeys(): List<GpgKey> {
        runGpgRaw("--list-secret-keys", "--with-colons")
        return emptyList()
    }

    // Fungsi pembantu biar gak pusing sama constructor model lu
    private fun runGpgRaw(vararg args: String): String {
        return try {
            val command = mutableListOf(gpgBinary.absolutePath, "--homedir", gpgDir.absolutePath)
            command.addAll(args)
            
            AppLogger.log("DEBUG: Running: ${command.joinToString(" ")}")
            
            val process = ProcessBuilder(command)
                .redirectErrorStream(true)
                .start()
            
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            
            AppLogger.log("DEBUG: Exit Code: $exitCode, Output: $output")
            output
        } catch (e: Exception) {
            val err = "CRASH runGpgRaw: ${e.message}"
            AppLogger.log(err)
            err
        }
    }

    // Stub supaya tetap bisa build meskipun fungsinya kosong
    fun importKey(keyFile: File): Any? = runGpgRaw("--import", keyFile.absolutePath)
    fun importKeyFromKeyserver(kId: String, ks: String): Any? = null
    fun trustKey(fp: String, tl: Int): Any? = null
    fun deleteKey(fp: String): Any? = null
    fun exportKey(fp: String): Any? = null
}
