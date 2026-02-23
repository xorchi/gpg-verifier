package com.gpgverifier.executor

import android.content.Context
import com.gpgverifier.model.GpgKey
import com.gpgverifier.model.GpgOperationResult
import com.gpgverifier.model.KeyType
import com.gpgverifier.model.VerificationResult
import com.gpgverifier.util.AppLogger
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.net.URL
import java.text.SimpleDateFormat
import java.util.*

class GpgExecutor(private val context: Context) {

    private val keyringDir: File by lazy {
        File(context.filesDir, "keyring").also { it.mkdirs() }
    }

    private val publicKeyringFile: File get() = File(keyringDir, "pubring.pgp")
    private val secretKeyringFile: File get() = File(keyringDir, "secring.pgp")
    private val trustFile: File get() = File(keyringDir, "trustdb.txt")

    // ── Verify ───────────────────────────────────────────────────────────────

    fun verify(dataFile: File, sigFile: File): VerificationResult {
        AppLogger.log("DEBUG: verify() dipanggil")
        return try {
            val sigCollection = loadSignatures(sigFile.inputStream())
            if (sigCollection.isEmpty()) {
                return VerificationResult(false, "", "", "", "", "File bukan signature GPG yang valid")
            }

            val pubRings = loadPublicKeyring() ?: return VerificationResult(
                false, "", "", "", "", "Keyring kosong — import public key terlebih dahulu"
            )

            var result: VerificationResult? = null
            outer@ for (sig in sigCollection) {
                val keyId = sig.keyID
                val pubKey = findPublicKey(pubRings, keyId) ?: continue
                sig.init(JcaPGPContentVerifierBuilderProvider(), pubKey)
                dataFile.inputStream().use { sig.update(it.readBytes()) }
                val valid = sig.verify()
                val fingerprint = bytesToHex(pubKey.fingerprint)
                val uid = (pubKey.userIDs.asSequence().firstOrNull() ?: "Unknown") as String
                val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                    .format(sig.creationTime)
                val trust = getTrustLevel(fingerprint)
                result = VerificationResult(
                    isValid = valid,
                    signedBy = uid,
                    fingerprint = fingerprint,
                    timestamp = ts,
                    trustLevel = trust,
                    rawOutput = if (valid) "Good signature from \"$uid\"" else "BAD signature",
                    errorMessage = if (!valid) "Signature tidak valid" else null
                )
                break@outer
            }

            result ?: VerificationResult(false, "", "", "", "", "No public key — key ID tidak ditemukan di keyring")
        } catch (e: Exception) {
            AppLogger.log("ERROR verify: ${e.message}")
            VerificationResult(false, "", "", "", "", e.message ?: "Verifikasi gagal")
        }
    }

    // ── List Keys ────────────────────────────────────────────────────────────

    fun listKeys(): List<GpgKey> {
        AppLogger.log("DEBUG: listKeys() dipanggil")
        val rings = loadPublicKeyring() ?: return emptyList()
        val keys = mutableListOf<GpgKey>()
        for (ring in rings) {
            val pub = ring.publicKey
            val fingerprint = bytesToHex(pub.fingerprint)
            keys.add(GpgKey(
                keyId = java.lang.Long.toHexString(pub.keyID).uppercase(),
                fingerprint = fingerprint,
                uids = pub.userIDs.asSequence().map { it as String }.toList(),
                createdAt = pub.creationTime.time.toString(),
                expiresAt = if (pub.validSeconds > 0)
                    (pub.creationTime.time + pub.validSeconds * 1000).toString() else null,
                trustLevel = getTrustLevel(fingerprint),
                type = KeyType.PUBLIC
            ))
        }
        return keys
    }

    fun listSecretKeys(): List<GpgKey> {
        val rings = loadSecretKeyring() ?: return emptyList()
        val keys = mutableListOf<GpgKey>()
        for (ring in rings) {
            val sec = ring.secretKey
            val fingerprint = bytesToHex(sec.publicKey.fingerprint)
            keys.add(GpgKey(
                keyId = java.lang.Long.toHexString(sec.keyID).uppercase(),
                fingerprint = fingerprint,
                uids = sec.userIDs.asSequence().map { it as String }.toList(),
                createdAt = sec.publicKey.creationTime.time.toString(),
                expiresAt = if (sec.publicKey.validSeconds > 0)
                    (sec.publicKey.creationTime.time + sec.publicKey.validSeconds * 1000).toString() else null,
                trustLevel = getTrustLevel(fingerprint),
                type = KeyType.SECRET
            ))
        }
        return keys
    }

    // ── Import Key ───────────────────────────────────────────────────────────

    fun importKey(keyFile: File): GpgOperationResult {
        AppLogger.log("DEBUG: importKey() dari ${keyFile.absolutePath}")
        return try {
            val imported = mergePublicKeys(keyFile.inputStream())
            GpgOperationResult.Success("$imported key berhasil diimport")
        } catch (e: Exception) {
            AppLogger.log("ERROR importKey: ${e.message}")
            GpgOperationResult.Failure(e.message ?: "Import gagal")
        }
    }

    fun importKeyFromKeyserver(keyId: String, keyserver: String): GpgOperationResult {
        AppLogger.log("DEBUG: importKeyFromKeyserver() keyId=$keyId ks=$keyserver")
        return try {
            val base = keyserver.trimEnd('/')
            val url = "$base/pks/lookup?op=get&search=0x$keyId&options=mr"
            AppLogger.log("DEBUG: Fetching $url")
            val stream = URL(url).openStream()
            val imported = mergePublicKeys(stream)
            GpgOperationResult.Success("$imported key berhasil diimport dari $keyserver")
        } catch (e: Exception) {
            AppLogger.log("ERROR importKeyFromKeyserver: ${e.message}")
            GpgOperationResult.Failure(e.message ?: "Import dari keyserver gagal")
        }
    }

    // ── Trust ────────────────────────────────────────────────────────────────

    fun trustKey(fingerprint: String, trustLevel: Int): GpgOperationResult {
        AppLogger.log("DEBUG: trustKey() fp=$fingerprint level=$trustLevel")
        return try {
            val lines = if (trustFile.exists())
                trustFile.readLines().filter { !it.startsWith(fingerprint) }.toMutableList()
            else mutableListOf()
            lines.add("$fingerprint:$trustLevel")
            trustFile.writeText(lines.joinToString("\n"))
            GpgOperationResult.Success("Trust level diset ke $trustLevel")
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Gagal set trust")
        }
    }

    // ── Delete ───────────────────────────────────────────────────────────────

    fun deleteKey(fingerprint: String): GpgOperationResult {
        AppLogger.log("DEBUG: deleteKey() fp=$fingerprint")
        return try {
            val rings = loadPublicKeyring()?.filter {
                bytesToHex(it.publicKey.fingerprint) != fingerprint.uppercase()
            } ?: emptyList()
            savePublicKeyring(rings)
            // Hapus trust entry
            if (trustFile.exists()) {
                val lines = trustFile.readLines().filter { !it.startsWith(fingerprint) }
                trustFile.writeText(lines.joinToString("\n"))
            }
            GpgOperationResult.Success("Key dihapus")
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Gagal hapus key")
        }
    }

    // ── Export ───────────────────────────────────────────────────────────────

    fun exportKey(fingerprint: String): GpgOperationResult {
        AppLogger.log("DEBUG: exportKey() fp=$fingerprint")
        return try {
            val ring = loadPublicKeyring()?.firstOrNull {
                bytesToHex(it.publicKey.fingerprint) == fingerprint.uppercase()
            } ?: return GpgOperationResult.Failure("Key tidak ditemukan")
            val out = java.io.ByteArrayOutputStream()
            val armored = org.bouncycastle.bcpg.ArmoredOutputStream(out)
            ring.encode(armored)
            armored.close()
            GpgOperationResult.Success(out.toString())
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Export gagal")
        }
    }

    // ── Private Helpers ──────────────────────────────────────────────────────

    private fun loadPublicKeyring(): List<PGPPublicKeyRing>? {
        if (!publicKeyringFile.exists()) return null
        return try {
            val rings = mutableListOf<PGPPublicKeyRing>()
            val col = PGPPublicKeyRingCollection(
                FileInputStream(publicKeyringFile),
                JcaKeyFingerprintCalculator()
            )
            col.keyRings.forEach { rings.add(it) }
            rings
        } catch (e: Exception) {
            AppLogger.log("ERROR loadPublicKeyring: ${e.message}")
            null
        }
    }

    private fun loadSecretKeyring(): List<PGPSecretKeyRing>? {
        if (!secretKeyringFile.exists()) return null
        return try {
            val rings = mutableListOf<PGPSecretKeyRing>()
            val col = PGPSecretKeyRingCollection(
                FileInputStream(secretKeyringFile),
                JcaKeyFingerprintCalculator()
            )
            col.keyRings.forEach { rings.add(it) }
            rings
        } catch (e: Exception) {
            AppLogger.log("ERROR loadSecretKeyring: ${e.message}")
            null
        }
    }

    private fun savePublicKeyring(rings: List<PGPPublicKeyRing>) {
        val col = PGPPublicKeyRingCollection(rings)
        FileOutputStream(publicKeyringFile).use { col.encode(it) }
    }

    private fun mergePublicKeys(input: InputStream): Int {
        val decoded: InputStream = try {
            PGPUtil.getDecoderStream(input)
        } catch (e: Exception) { input }

        val incoming = mutableListOf<PGPPublicKeyRing>()
        try {
            val col = PGPPublicKeyRingCollection(decoded, JcaKeyFingerprintCalculator())
            col.keyRings.forEach { incoming.add(it) }
        } catch (e: Exception) {
            AppLogger.log("ERROR mergePublicKeys parsing: ${e.message}")
            throw e
        }

        val existing = loadPublicKeyring()?.associateBy {
            bytesToHex(it.publicKey.fingerprint)
        }?.toMutableMap() ?: mutableMapOf()

        var count = 0
        for (ring in incoming) {
            val fp = bytesToHex(ring.publicKey.fingerprint)
            if (!existing.containsKey(fp)) count++
            existing[fp] = ring
        }
        savePublicKeyring(existing.values.toList())
        return count
    }

    private fun loadSignatures(input: InputStream): List<PGPSignature> {
        val sigs = mutableListOf<PGPSignature>()
        try {
            val decoded = PGPUtil.getDecoderStream(input)
            val factory = PGPObjectFactory(decoded, JcaKeyFingerprintCalculator())
            var obj = factory.nextObject()
            while (obj != null) {
                when (obj) {
                    is PGPSignatureList -> obj.forEach { sigs.add(it) }
                    is PGPSignature -> sigs.add(obj)
                }
                obj = factory.nextObject()
            }
        } catch (e: Exception) {
            AppLogger.log("ERROR loadSignatures: ${e.message}")
        }
        return sigs
    }

    private fun findPublicKey(rings: List<PGPPublicKeyRing>, keyId: Long): PGPPublicKey? {
        for (ring in rings) {
            for (key in ring.publicKeys) {
                if (key.keyID == keyId) return key
            }
        }
        return null
    }

    private fun getTrustLevel(fingerprint: String): String {
        if (!trustFile.exists()) return "Unknown"
        val line = trustFile.readLines().firstOrNull {
            it.startsWith(fingerprint.uppercase())
        } ?: return "Unknown"
        return when (line.substringAfter(":").trim()) {
            "2" -> "Undefined"
            "3" -> "Marginal"
            "4" -> "Full"
            "5" -> "Ultimate"
            else -> "Unknown"
        }
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02X".format(it) }
}
