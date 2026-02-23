package com.gpgverifier.executor

import android.content.Context
import com.gpgverifier.model.GpgKey
import com.gpgverifier.model.GpgOperationResult
import com.gpgverifier.model.KeyType
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
        AppLogger.log("DEBUG: GPG path: ${file.absolutePath}, executable: ${file.canExecute()}")
        file
    }

    private val gpgDir: File by lazy {
        val dir = File(context.filesDir, ".gnupg")
        if (!dir.exists()) dir.mkdirs()
        dir.setReadable(true, true)
        dir.setWritable(true, true)
        dir.setExecutable(true, true)
        dir
    }

    fun verify(dataFile: File, sigFile: File): VerificationResult {
        AppLogger.log("DEBUG: verify() dipanggil")
        val output = runGpg("--verify", sigFile.absolutePath, dataFile.absolutePath)
        AppLogger.log("DEBUG: verify output: $output")
        return parseVerifyOutput(output)
    }

    fun listKeys(): List<GpgKey> {
        AppLogger.log("DEBUG: listKeys() dipanggil")
        val output = runGpg("--list-keys", "--with-colons", "--fingerprint")
        return parseKeyColons(output, KeyType.PUBLIC)
    }

    fun listSecretKeys(): List<GpgKey> {
        val output = runGpg("--list-secret-keys", "--with-colons", "--fingerprint")
        return parseKeyColons(output, KeyType.SECRET)
    }

    fun importKey(keyFile: File): GpgOperationResult {
        AppLogger.log("DEBUG: importKey() dari ${keyFile.absolutePath}")
        val output = runGpg("--import", keyFile.absolutePath)
        return if (output.contains("imported") || output.contains("unchanged"))
            GpgOperationResult.Success("Key berhasil diimport")
        else
            GpgOperationResult.Failure(output.ifBlank { "Import gagal" })
    }

    fun importKeyFromKeyserver(keyId: String, keyserver: String): GpgOperationResult {
        AppLogger.log("DEBUG: importKeyFromKeyserver() keyId=$keyId ks=$keyserver")
        val output = runGpg("--keyserver", keyserver, "--recv-keys", keyId)
        return if (output.contains("imported") || output.contains("unchanged"))
            GpgOperationResult.Success("Key $keyId berhasil diimport dari $keyserver")
        else
            GpgOperationResult.Failure(output.ifBlank { "Import dari keyserver gagal" })
    }

    fun trustKey(fingerprint: String, trustLevel: Int): GpgOperationResult {
        AppLogger.log("DEBUG: trustKey() fp=$fingerprint level=$trustLevel")
        return try {
            val command = listOf(
                gpgBinary.absolutePath,
                "--homedir", gpgDir.absolutePath,
                "--batch", "--yes",
                "--command-fd", "0",
                "--edit-key", fingerprint
            )
            val process = ProcessBuilder(command)
                .redirectErrorStream(true)
                .start()
            process.outputStream.bufferedWriter().use { it.write("trust\n$trustLevel\ny\nquit\n") }
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()
            AppLogger.log("DEBUG: trustKey output: $output")
            GpgOperationResult.Success("Trust level diset ke $trustLevel")
        } catch (e: Exception) {
            AppLogger.log("ERROR trustKey: ${e.message}")
            GpgOperationResult.Failure(e.message ?: "Gagal set trust")
        }
    }

    fun deleteKey(fingerprint: String): GpgOperationResult {
        AppLogger.log("DEBUG: deleteKey() fp=$fingerprint")
        val output = runGpg("--batch", "--yes", "--delete-key", fingerprint)
        return if (output.isBlank() || output.contains("ok", ignoreCase = true))
            GpgOperationResult.Success("Key dihapus")
        else
            GpgOperationResult.Failure(output)
    }

    fun exportKey(fingerprint: String): GpgOperationResult {
        AppLogger.log("DEBUG: exportKey() fp=$fingerprint")
        val output = runGpg("--armor", "--export", fingerprint)
        return if (output.contains("BEGIN PGP PUBLIC KEY BLOCK"))
            GpgOperationResult.Success(output)
        else
            GpgOperationResult.Failure("Export gagal atau key tidak ditemukan")
    }

    private fun parseVerifyOutput(output: String): VerificationResult {
        val isValid = output.contains("Good signature")
        if (!isValid) {
            val errorMsg = when {
                output.contains("No public key") -> "Public key tidak ditemukan di keyring"
                output.contains("BAD signature") -> "Signature tidak valid"
                output.contains("no valid OpenPGP") -> "File bukan signature GPG yang valid"
                output.contains("Permission denied") -> "Permission denied saat eksekusi GPG"
                else -> output.lines().firstOrNull { it.isNotBlank() } ?: "Verifikasi gagal"
            }
            return VerificationResult(
                isValid = false,
                signedBy = "",
                fingerprint = "",
                timestamp = "",
                trustLevel = "",
                rawOutput = output,
                errorMessage = errorMsg
            )
        }
        return VerificationResult(
            isValid = true,
            signedBy = Regex("Good signature from \"(.+?)\"").find(output)
                ?.groupValues?.get(1) ?: "Unknown",
            fingerprint = Regex("Primary key fingerprint:(.+)").find(output)
                ?.groupValues?.get(1)?.trim()?.replace(" ", "") ?: "",
            timestamp = Regex("Signature made (.+?) using").find(output)
                ?.groupValues?.get(1)?.trim() ?: "",
            trustLevel = when {
                output.contains("fully trusted") -> "Full"
                output.contains("marginally trusted") -> "Marginal"
                output.contains("undefined trust") -> "Undefined"
                else -> "Unknown"
            },
            rawOutput = output
        )
    }

    private fun parseKeyColons(output: String, defaultType: KeyType): List<GpgKey> {
        val keys = mutableListOf<GpgKey>()
        var currentFingerprint = ""
        var currentKeyId = ""
        var currentCreatedAt = ""
        var currentExpiresAt: String? = null
        val currentUids = mutableListOf<String>()
        var currentTrust = ""
        var currentType = defaultType

        fun flush() {
            if (currentFingerprint.isNotBlank()) {
                keys.add(GpgKey(
                    keyId = currentKeyId,
                    fingerprint = currentFingerprint,
                    uids = currentUids.toList(),
                    createdAt = currentCreatedAt,
                    expiresAt = currentExpiresAt,
                    trustLevel = currentTrust,
                    type = currentType
                ))
            }
        }

        output.lines().forEach { line ->
            val f = line.split(":")
            when (f.getOrNull(0)) {
                "pub" -> {
                    flush()
                    currentFingerprint = ""; currentUids.clear()
                    currentKeyId = f.getOrNull(4) ?: ""
                    currentCreatedAt = f.getOrNull(5) ?: ""
                    currentExpiresAt = f.getOrNull(6)?.takeIf { it.isNotBlank() }
                    currentTrust = f.getOrNull(1) ?: ""
                    currentType = KeyType.PUBLIC
                }
                "sec" -> {
                    flush()
                    currentFingerprint = ""; currentUids.clear()
                    currentKeyId = f.getOrNull(4) ?: ""
                    currentCreatedAt = f.getOrNull(5) ?: ""
                    currentExpiresAt = f.getOrNull(6)?.takeIf { it.isNotBlank() }
                    currentTrust = f.getOrNull(1) ?: ""
                    currentType = KeyType.SECRET
                }
                "fpr" -> currentFingerprint = f.getOrNull(9) ?: ""
                "uid" -> f.getOrNull(9)?.takeIf { it.isNotBlank() }?.let { currentUids.add(it) }
            }
        }
        flush()
        return keys
    }

    private fun runGpg(vararg args: String): String {
        return try {
            val command = mutableListOf(
                gpgBinary.absolutePath,
                "--homedir", gpgDir.absolutePath,
                "--no-tty", "--batch"
            )
            command.addAll(args)
            AppLogger.log("DEBUG: Executing: ${command.joinToString(" ")}")
            val process = ProcessBuilder(command)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            AppLogger.log("DEBUG: Exit=$exitCode output=$output")
            output
        } catch (e: Exception) {
            val err = "ERROR runGpg: ${e.message}"
            AppLogger.log(err)
            err
        }
    }

}
