package com.gpgverifier.model

data class VerificationResult(
    val isValid: Boolean,
    val signedBy: String,
    val fingerprint: String,
    val timestamp: String,
    val trustLevel: String,
    val rawOutput: String,
    val errorMessage: String? = null,
    val hashAlgorithm: String = ""   // hash algorithm auto-detected from the signature packet
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

enum class HashAlgorithm(val tag: Int, val headerName: String) {
    SHA256(org.bouncycastle.bcpg.HashAlgorithmTags.SHA256, "SHA256"),
    SHA512(org.bouncycastle.bcpg.HashAlgorithmTags.SHA512, "SHA512")
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
