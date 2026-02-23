package com.gpgverifier.executor

import android.content.Context
import android.util.Log
import java.io.File

class GpgExecutor(private val context: Context) {

    private val gpgBinary: File by lazy { extractGpgBinary() }
    private val gnupgHome: File by lazy {
        File(context.filesDir, ".gnupg").also { it.mkdirs() }
    }

    // ── Extract binary GPG dari assets ke filesDir ──────────────────────────
    private fun extractGpgBinary(): File {
        val dest = File(context.filesDir, "gpg")
        if (!dest.exists() || needsUpdate(dest)) {
            context.assets.open("gpg").use { input ->
                dest.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            dest.setExecutable(true, true)
            Log.d(TAG, "GPG binary extracted to ${dest.absolutePath}")
        }
        return dest
    }

    private fun needsUpdate(dest: File): Boolean {
        // Cek versi apk vs binary yang ada
        return try {
            val result = runGpg(listOf("--version"))
            !result.stdout.contains("GnuPG")
        } catch (e: Exception) {
            true
        }
    }

    // ── Runner utama ────────────────────────────────────────────────────────
    fun runGpg(args: List<String>): ProcessResult {
        val cmd = mutableListOf(gpgBinary.absolutePath, "--homedir", gnupgHome.absolutePath)
        cmd.addAll(args)

        Log.d(TAG, "Running: ${cmd.joinToString(" ")}")

        val process = ProcessBuilder(cmd)
            .redirectErrorStream(false)
            .apply {
                environment()["GNUPGHOME"] = gnupgHome.absolutePath
                environment()["HOME"] = context.filesDir.absolutePath
            }
            .start()

        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        Log.d(TAG, "Exit: $exitCode | stdout: $stdout | stderr: $stderr")

        return ProcessResult(exitCode, stdout, stderr)
    }

    // ── Verifikasi signature ────────────────────────────────────────────────
    fun verify(dataFile: File, sigFile: File): com.gpgverifier.model.VerificationResult {
        val result = runGpg(listOf(
            "--batch",
            "--status-fd", "1",
            "--verify", sigFile.absolutePath, dataFile.absolutePath
        ))

        return parseVerificationOutput(result)
    }

    private fun parseVerificationOutput(result: ProcessResult): com.gpgverifier.model.VerificationResult {
        val output = result.stdout + result.stderr
        val isValid = result.exitCode == 0 &&
                (output.contains("Good signature") || output.contains("GOODSIG"))

        val signedBy = extractField(output, "Good signature from \"", "\"")
            ?: extractField(output, "GOODSIG [A-F0-9]+ (.+)", null, regex = true)
            ?: "Unknown"

        val fingerprint = extractField(output, "Primary key fingerprint:", "\n")
            ?.trim()
            ?: extractField(output, "VALIDSIG ([A-F0-9]+)", null, regex = true)
            ?: ""

        val timestamp = extractField(output, "SIG_ID [^ ]+ ([^ ]+)", null, regex = true)
            ?: extractField(output, "Signature made", "\n")?.trim()
            ?: ""

        val trustLevel = when {
            output.contains("TRUST_ULTIMATE") -> "Ultimate"
            output.contains("TRUST_FULL") -> "Full"
            output.contains("TRUST_MARGINAL") -> "Marginal"
            output.contains("TRUST_UNDEFINED") -> "Undefined"
            output.contains("TRUST_NEVER") -> "Never"
            else -> "Unknown"
        }

        return com.gpgverifier.model.VerificationResult(
            isValid = isValid,
            signedBy = signedBy,
            fingerprint = fingerprint,
            timestamp = timestamp,
            trustLevel = trustLevel,
            rawOutput = output,
            errorMessage = if (!isValid) extractErrorMessage(output) else null
        )
    }

    // ── Keyring management ──────────────────────────────────────────────────
    fun listKeys(): List<com.gpgverifier.model.GpgKey> {
        val result = runGpg(listOf(
            "--batch",
            "--with-colons",
            "--with-fingerprint",
            "--list-keys"
        ))
        return parseKeyList(result.stdout, com.gpgverifier.model.KeyType.PUBLIC)
    }

    fun listSecretKeys(): List<com.gpgverifier.model.GpgKey> {
        val result = runGpg(listOf(
            "--batch",
            "--with-colons",
            "--with-fingerprint",
            "--list-secret-keys"
        ))
        return parseKeyList(result.stdout, com.gpgverifier.model.KeyType.SECRET)
    }

    fun importKey(keyFile: File): com.gpgverifier.model.GpgOperationResult {
        val result = runGpg(listOf("--batch", "--import", keyFile.absolutePath))
        return if (result.exitCode == 0) {
            com.gpgverifier.model.GpgOperationResult.Success(
                extractImportSummary(result.stderr)
            )
        } else {
            com.gpgverifier.model.GpgOperationResult.Failure(result.stderr)
        }
    }

    fun importKeyFromKeyserver(keyId: String, keyserver: String = "hkps://keys.openpgp.org"): com.gpgverifier.model.GpgOperationResult {
        val result = runGpg(listOf(
            "--batch",
            "--keyserver", keyserver,
            "--recv-keys", keyId
        ))
        return if (result.exitCode == 0) {
            com.gpgverifier.model.GpgOperationResult.Success("Key $keyId imported from $keyserver")
        } else {
            com.gpgverifier.model.GpgOperationResult.Failure(result.stderr)
        }
    }

    fun deleteKey(fingerprint: String): com.gpgverifier.model.GpgOperationResult {
        val result = runGpg(listOf(
            "--batch",
            "--yes",
            "--delete-key", fingerprint
        ))
        return if (result.exitCode == 0) {
            com.gpgverifier.model.GpgOperationResult.Success("Key deleted")
        } else {
            com.gpgverifier.model.GpgOperationResult.Failure(result.stderr)
        }
    }

    fun exportKey(fingerprint: String): com.gpgverifier.model.GpgOperationResult {
        val result = runGpg(listOf(
            "--batch",
            "--armor",
            "--export", fingerprint
        ))
        return if (result.exitCode == 0 && result.stdout.isNotBlank()) {
            com.gpgverifier.model.GpgOperationResult.Success(result.stdout)
        } else {
            com.gpgverifier.model.GpgOperationResult.Failure("No key found or export failed")
        }
    }

    fun trustKey(fingerprint: String, trustLevel: Int): com.gpgverifier.model.GpgOperationResult {
        // trustLevel: 1=unknown, 2=none, 3=marginal, 4=full, 5=ultimate
        val trustInput = "$fingerprint:$trustLevel:\n"
        val process = ProcessBuilder(
            gpgBinary.absolutePath,
            "--homedir", gnupgHome.absolutePath,
            "--batch",
            "--import-ownertrust"
        ).apply {
            environment()["GNUPGHOME"] = gnupgHome.absolutePath
            environment()["HOME"] = context.filesDir.absolutePath
        }.start()

        process.outputStream.bufferedWriter().use { it.write(trustInput) }
        val stderr = process.errorStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        return if (exitCode == 0) {
            com.gpgverifier.model.GpgOperationResult.Success("Trust level updated")
        } else {
            com.gpgverifier.model.GpgOperationResult.Failure(stderr)
        }
    }

    // ── Parser helper ───────────────────────────────────────────────────────
    private fun parseKeyList(output: String, type: com.gpgverifier.model.KeyType): List<com.gpgverifier.model.GpgKey> {
        val keys = mutableListOf<com.gpgverifier.model.GpgKey>()
        var currentKeyId = ""
        var currentFingerprint = ""
        var currentCreated = ""
        var currentExpires: String? = null
        var currentTrust = ""
        val currentUids = mutableListOf<String>()

        fun flushKey() {
            if (currentKeyId.isNotEmpty()) {
                keys.add(com.gpgverifier.model.GpgKey(
                    keyId = currentKeyId,
                    fingerprint = currentFingerprint,
                    uids = currentUids.toList(),
                    createdAt = currentCreated,
                    expiresAt = currentExpires,
                    trustLevel = currentTrust,
                    type = type
                ))
                currentUids.clear()
            }
        }

        output.lines().forEach { line ->
            val fields = line.split(":")
            when (fields.getOrNull(0)) {
                "pub", "sec" -> {
                    flushKey()
                    currentKeyId = fields.getOrNull(4) ?: ""
                    currentCreated = fields.getOrNull(5) ?: ""
                    currentExpires = fields.getOrNull(6)?.takeIf { it.isNotBlank() }
                    currentTrust = parseTrustChar(fields.getOrNull(1) ?: "")
                }
                "fpr" -> currentFingerprint = fields.getOrNull(9) ?: ""
                "uid" -> {
                    val uid = fields.getOrNull(9) ?: ""
                    if (uid.isNotBlank()) currentUids.add(uid)
                }
            }
        }
        flushKey()
        return keys
    }

    private fun parseTrustChar(char: String): String = when (char) {
        "u" -> "Ultimate"
        "f" -> "Full"
        "m" -> "Marginal"
        "n" -> "None"
        "r" -> "Revoked"
        "e" -> "Expired"
        else -> "Unknown"
    }

    private fun extractField(text: String, start: String, end: String?, regex: Boolean = false): String? {
        return if (regex) {
            Regex(start).find(text)?.groupValues?.getOrNull(1)
        } else {
            val startIdx = text.indexOf(start).takeIf { it >= 0 } ?: return null
            val from = startIdx + start.length
            val endIdx = if (end != null) text.indexOf(end, from).takeIf { it > from } else text.length
            endIdx?.let { text.substring(from, it) }
        }
    }

    private fun extractErrorMessage(output: String): String {
        return when {
            output.contains("No public key") -> "Public key not found. Please import the signer's key."
            output.contains("BAD signature") -> "Signature is INVALID. File may be corrupted or tampered."
            output.contains("no valid OpenPGP data") -> "Signature file is not a valid GPG signature."
            output.contains("Can't check signature") -> "Cannot verify: missing public key."
            else -> output.lines().firstOrNull { it.contains("error", true) } ?: "Verification failed."
        }
    }

    private fun extractImportSummary(stderr: String): String {
        val processed = Regex("Total number processed: (\\d+)").find(stderr)?.groupValues?.get(1) ?: "?"
        val imported = Regex("imported: (\\d+)").find(stderr)?.groupValues?.get(1) ?: "0"
        val unchanged = Regex("unchanged: (\\d+)").find(stderr)?.groupValues?.get(1) ?: "0"
        return "Processed: $processed | Imported: $imported | Unchanged: $unchanged"
    }

    data class ProcessResult(val exitCode: Int, val stdout: String, val stderr: String)

    companion object {
        private const val TAG = "GpgExecutor"
    }
}
