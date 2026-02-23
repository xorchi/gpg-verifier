package com.gpgverifier.model

data class VerificationResult(
    val isValid: Boolean,
    val signedBy: String,
    val fingerprint: String,
    val timestamp: String,
    val trustLevel: String,
    val rawOutput: String,
    val errorMessage: String? = null
)

data class GpgKey(
    val keyId: String,
    val fingerprint: String,
    val uids: List<String>,
    val createdAt: String,
    val expiresAt: String?,
    val trustLevel: String,
    val type: KeyType
)

enum class KeyType { PUBLIC, SECRET }

enum class SignMode {
    DETACH_ARMOR,
    DETACH,
    CLEARSIGN,
    NORMAL_ARMOR,
    NORMAL
}

data class KeyGenParams(
    val name: String,
    val email: String,
    val comment: String = "",
    val keyType: String = "RSA",
    val keySize: Int = 4096,
    val expiry: Int = 0,
    val passphrase: String = ""
)

data class SignResult(
    val success: Boolean,
    val outputPath: String = "",
    val rawOutput: String = "",
    val errorMessage: String? = null
)

data class EncryptResult(
    val success: Boolean,
    val outputPath: String = "",
    val errorMessage: String? = null
)

data class DecryptResult(
    val success: Boolean,
    val outputPath: String = "",
    val verificationResult: VerificationResult? = null,
    val errorMessage: String? = null
)

sealed class GpgOperationResult {
    data class Success(val message: String) : GpgOperationResult()
    data class Failure(val error: String) : GpgOperationResult()
}
