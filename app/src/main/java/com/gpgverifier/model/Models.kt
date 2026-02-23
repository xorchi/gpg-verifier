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

enum class KeyType {
    PUBLIC, SECRET
}

sealed class GpgOperationResult {
    data class Success(val message: String) : GpgOperationResult()
    data class Failure(val error: String) : GpgOperationResult()
}
