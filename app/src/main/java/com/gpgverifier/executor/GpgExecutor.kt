package com.gpgverifier.executor

import android.content.Context
import com.gpgverifier.model.*
import com.gpgverifier.util.AppLogger
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.*
import java.io.*
import java.net.URL
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.*

class GpgExecutor(private val context: Context) {

    private fun armoredOut(out: OutputStream): ArmoredOutputStream =
        ArmoredOutputStream(out).also { it.setHeader("Version", null) }

    private val keyringDir: File by lazy {
        File(context.filesDir, "keyring").also { it.mkdirs() }
    }
    private val publicKeyringFile: File get() = File(keyringDir, "pubring.pgp")
    private val secretKeyringFile: File get() = File(keyringDir, "secring.pgp")
    private val trustFile: File get() = File(keyringDir, "trustdb.txt")
    private val digestCalcProvider = BcPGPDigestCalculatorProvider()
    private val fingerprintCalc = BcKeyFingerprintCalculator()

    // ── Verify ───────────────────────────────────────────────────────────────

    fun verify(dataFile: File, sigFile: File): VerificationResult {
        AppLogger.log("DEBUG: verify() called")
        return try {
            val sigs = loadSignatures(sigFile.inputStream())
            if (sigs.isEmpty())
                return VerificationResult(false, "", "", "", "", "File is not a valid GPG signature")
            val pubRings = loadPublicKeyring()
                ?: return VerificationResult(false, "", "", "", "", "Keyring is empty — import a public key first")
            for (sig in sigs) {
                val pubKey = findPublicKey(pubRings, sig.keyID) ?: continue
                sig.init(BcPGPContentVerifierBuilderProvider(), pubKey)
                sig.update(dataFile.readBytes())
                val valid = sig.verify()
                val fp = bytesToHex(pubKey.fingerprint)
                val uid = (pubKey.userIDs.asSequence().firstOrNull() ?: "Unknown") as String
                val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(sig.creationTime)
                return VerificationResult(
                    isValid = valid,
                    signedBy = uid,
                    fingerprint = fp,
                    timestamp = ts,
                    trustLevel = getTrustLevel(fp),
                    rawOutput = if (valid) "Good signature from \"$uid\"" else "BAD signature",
                    errorMessage = if (!valid) "Signature is not valid" else null
                )
            }
            VerificationResult(false, "", "", "", "", "No public key — key ID not found in keyring")
        } catch (e: Exception) {
            AppLogger.log("ERROR verify: ${e.message}\n${e.stackTraceToString()}")
            VerificationResult(false, "", "", "", "", e.message ?: "Verification failed")
        }
    }

    fun verifyClearSign(clearSignFile: File): VerificationResult {
        AppLogger.log("DEBUG: verifyClearSign() called file=${clearSignFile.name}")
        return try {
            val pubRings = loadPublicKeyring()
                ?: return VerificationResult(false, "", "", "", "", "Keyring is empty — import a public key first")
            val content = clearSignFile.readText()
            if (!content.contains("-----BEGIN PGP SIGNED MESSAGE-----"))
                return VerificationResult(false, "", "", "", "", "File is not a valid GPG clearsign format")
            val sigStart = content.indexOf("-----BEGIN PGP SIGNATURE-----")
            if (sigStart == -1)
                return VerificationResult(false, "", "", "", "", "Signature block not found in file")
            val headerEnd = content.indexOf("\n\n")
            if (headerEnd == -1)
                return VerificationResult(false, "", "", "", "", "Invalid clearsign format — header not found")
            val signedText = content.substring(headerEnd + 2, sigStart).trimEnd('\n')
            val sigBlock = content.substring(sigStart)
            val sigs = loadSignatures(sigBlock.toByteArray(Charsets.UTF_8).inputStream())
            if (sigs.isEmpty())
                return VerificationResult(false, "", "", "", "", "No parseable signature found")
            val canonicalText = signedText.lines().joinToString("\r\n")
            for (sig in sigs) {
                val pubKey = findPublicKey(pubRings, sig.keyID) ?: continue
                sig.init(BcPGPContentVerifierBuilderProvider(), pubKey)
                sig.update(canonicalText.toByteArray(Charsets.UTF_8))
                val valid = sig.verify()
                val fp = bytesToHex(pubKey.fingerprint)
                val uid = (pubKey.userIDs.asSequence().firstOrNull() ?: "Unknown") as String
                val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(sig.creationTime)
                AppLogger.log(if (valid) "INFO: ClearSign verification success" else "INFO: ClearSign verification failed")
                return VerificationResult(
                    isValid = valid,
                    signedBy = uid,
                    fingerprint = fp,
                    timestamp = ts,
                    trustLevel = getTrustLevel(fp),
                    rawOutput = if (valid) "Good signature from \"$uid\"" else "BAD signature",
                    errorMessage = if (!valid) "Signature is not valid" else null
                )
            }
            VerificationResult(false, "", "", "", "", "No public key — key ID not found in keyring")
        } catch (e: Exception) {
            AppLogger.log("ERROR verifyClearSign: ${e.message}\n${e.stackTraceToString()}")
            VerificationResult(false, "", "", "", "", e.message ?: "Clearsign verification failed")
        }
    }

    // ── Sign ─────────────────────────────────────────────────────────────────

    fun sign(dataFile: File, keyFingerprint: String, mode: SignMode, passphrase: String): SignResult {
        AppLogger.log("DEBUG: sign() fp=$keyFingerprint mode=$mode")
        return try {
            val secRing = findSecretKeyRing(keyFingerprint)
                ?: return SignResult(false, errorMessage = "Secret key not found")
            val secKey = secRing.secretKey
            val privateKey = secKey.extractPrivateKey(
                BcPBESecretKeyDecryptorBuilder(digestCalcProvider).build(passphrase.toCharArray())
            )
            val ext = when (mode) {
                SignMode.DETACH_ARMOR -> ".sig.asc"
                SignMode.DETACH -> ".sig"
                SignMode.CLEARSIGN -> ".asc"
                SignMode.NORMAL_ARMOR -> ".gpg.asc"
                SignMode.NORMAL -> ".gpg"
            }
            val outFile = File(context.cacheDir, dataFile.name + ext)
            val sigType = when (mode) {
                SignMode.CLEARSIGN, SignMode.NORMAL, SignMode.NORMAL_ARMOR -> PGPSignature.CANONICAL_TEXT_DOCUMENT
                else -> PGPSignature.BINARY_DOCUMENT
            }
            val sigGen = PGPSignatureGenerator(
                BcPGPContentSignerBuilder(secKey.publicKey.algorithm, HashAlgorithmTags.SHA256)
            ).apply {
                init(sigType, privateKey)
                val sub = PGPSignatureSubpacketGenerator()
                sub.addSignerUserID(false, (secKey.userIDs.asSequence().firstOrNull() ?: "") as String)
                setHashedSubpackets(sub.generate())
            }
            when (mode) {
                SignMode.DETACH_ARMOR -> {
                    armoredOut(outFile.outputStream()).use { out ->
                        sigGen.update(dataFile.readBytes())
                        sigGen.generate().encode(out)
                    }
                }
                SignMode.DETACH -> {
                    sigGen.update(dataFile.readBytes())
                    outFile.outputStream().use { sigGen.generate().encode(it) }
                }
                SignMode.CLEARSIGN -> {
                    val contentBytes = dataFile.readBytes()
                    val contentStr = contentBytes.toString(Charsets.UTF_8)
                    val canonical = contentStr.lines().joinToString("\r\n") { it.trimEnd() }
                    sigGen.update(canonical.toByteArray(Charsets.UTF_8))
                    val sig = sigGen.generate()
                    val sigBout = ByteArrayOutputStream()
                    armoredOut(sigBout).use { sig.encode(it) }
                    val sigArmored = sigBout.toString(Charsets.UTF_8)
                    outFile.bufferedWriter(Charsets.UTF_8).use { w ->
                        w.write("-----BEGIN PGP SIGNED MESSAGE-----\n")
                        w.write("Hash: SHA256\n")
                        w.write("\n")
                        w.write(contentStr)
                        if (!contentStr.endsWith("\n")) w.write("\n")
                        w.write(sigArmored)
                    }
                }
                SignMode.NORMAL_ARMOR -> {
                    val bout = ByteArrayOutputStream()
                    PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(bout).use { cos ->
                        PGPLiteralDataGenerator().open(cos, PGPLiteralData.BINARY,
                            dataFile.name, dataFile.length(), Date()).use { los ->
                            val content = dataFile.readBytes()
                            sigGen.update(content)
                            los.write(content)
                        }
                        sigGen.generate().encode(cos)
                    }
                    armoredOut(outFile.outputStream()).use { it.write(bout.toByteArray()) }
                }
                SignMode.NORMAL -> {
                    val content = dataFile.readBytes()
                    sigGen.update(content)
                    outFile.outputStream().use { sigGen.generate().encode(it) }
                }
            }
            AppLogger.log("DEBUG: sign() output=${outFile.absolutePath}")
            SignResult(success = true, outputPath = outFile.absolutePath)
        } catch (e: Exception) {
            AppLogger.log("ERROR sign: ${e.message}\n${e.stackTraceToString()}")
            SignResult(false, errorMessage = e.message ?: "Signing failed")
        }
    }

    // ── Encrypt ──────────────────────────────────────────────────────────────

    fun encrypt(dataFile: File, recipientFingerprints: List<String>, armor: Boolean): EncryptResult {
        AppLogger.log("DEBUG: encrypt() recipients=${recipientFingerprints.size} armor=$armor")
        return try {
            val pubRings = loadPublicKeyring()
                ?: return EncryptResult(false, errorMessage = "Keyring is empty")
            val encKeys = recipientFingerprints.map { fp ->
                findEncryptionKey(pubRings, fp)
                    ?: return EncryptResult(false, errorMessage = "Encryption key not found: $fp")
            }
            val ext = if (armor) ".asc" else ".gpg"
            val outFile = File(context.cacheDir, dataFile.name + ext)
            val rawOut: OutputStream = if (armor) armoredOut(outFile.outputStream()) else outFile.outputStream()
            val encGen = PGPEncryptedDataGenerator(
                BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(SecureRandom())
            ).apply {
                encKeys.forEach { addMethod(BcPublicKeyKeyEncryptionMethodGenerator(it)) }
            }
            encGen.open(rawOut, ByteArray(1 shl 16)).use { encOut ->
                PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(encOut).use { cos ->
                    PGPLiteralDataGenerator().open(cos, PGPLiteralData.BINARY,
                        dataFile.name, dataFile.length(), Date()).use { los ->
                        dataFile.inputStream().use { it.copyTo(los) }
                    }
                }
            }
            rawOut.close()
            AppLogger.log("DEBUG: encrypt() output=${outFile.absolutePath}")
            EncryptResult(success = true, outputPath = outFile.absolutePath)
        } catch (e: Exception) {
            AppLogger.log("ERROR encrypt: ${e.message}\n${e.stackTraceToString()}")
            EncryptResult(false, errorMessage = e.message ?: "Encryption failed")
        }
    }

    fun encryptSymmetric(dataFile: File, passphrase: String, armor: Boolean): EncryptResult {
        AppLogger.log("DEBUG: encryptSymmetric() file=${dataFile.name} armor=$armor")
        return try {
            val ext = if (armor) ".asc" else ".gpg"
            val outFile = File(context.cacheDir, dataFile.name + ext)
            val rawOut: OutputStream = if (armor) armoredOut(outFile.outputStream()) else outFile.outputStream()
            val encGen = PGPEncryptedDataGenerator(
                BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(SecureRandom())
            ).apply {
                addMethod(BcPBEKeyEncryptionMethodGenerator(passphrase.toCharArray(), HashAlgorithmTags.SHA256))
            }
            encGen.open(rawOut, ByteArray(1 shl 16)).use { encOut ->
                PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(encOut).use { cos ->
                    PGPLiteralDataGenerator().open(cos, PGPLiteralData.BINARY,
                        dataFile.name, dataFile.length(), Date()).use { los ->
                        dataFile.inputStream().use { it.copyTo(los) }
                    }
                }
            }
            rawOut.close()
            AppLogger.log("DEBUG: encryptSymmetric() output=${outFile.absolutePath}")
            EncryptResult(success = true, outputPath = outFile.absolutePath)
        } catch (e: Exception) {
            AppLogger.log("ERROR encryptSymmetric: ${e.message}\n${e.stackTraceToString()}")
            EncryptResult(false, errorMessage = e.message ?: "Symmetric encryption failed")
        }
    }

    // ── Decrypt ──────────────────────────────────────────────────────────────

    fun decrypt(dataFile: File, passphrase: String): DecryptResult {
        AppLogger.log("DEBUG: decrypt() file=${dataFile.name}")
        return try {
            val inputStream = try {
                PGPUtil.getDecoderStream(dataFile.inputStream())
            } catch (e: Exception) {
                dataFile.inputStream()
            }
            val factory = PGPObjectFactory(inputStream, fingerprintCalc)
            var encData: PGPEncryptedDataList? = null
            var nextObj: Any? = factory.nextObject()
            while (nextObj != null && encData == null) {
                encData = nextObj as? PGPEncryptedDataList
                if (encData == null) nextObj = factory.nextObject()
            }
            if (encData == null)
                return DecryptResult(false, errorMessage = "File is not GPG encrypted data")
            val secRings = loadSecretKeyring()
            var plainStream: InputStream? = null
            if (secRings != null) {
                outer@ for (enc in encData) {
                    if (enc !is PGPPublicKeyEncryptedData) continue
                    for (ring in secRings) {
                        val sec = ring.getSecretKey(enc.keyID) ?: continue
                        val privKey = try {
                            sec.extractPrivateKey(
                                BcPBESecretKeyDecryptorBuilder(digestCalcProvider).build(passphrase.toCharArray())
                            )
                        } catch (e: Exception) { continue }
                        plainStream = enc.getDataStream(BcPublicKeyDataDecryptorFactory(privKey))
                        break@outer
                    }
                }
            }
            if (plainStream == null && passphrase.isNotEmpty()) {
                for (enc in encData) {
                    if (enc !is PGPPBEEncryptedData) continue
                    plainStream = try {
                        enc.getDataStream(BcPBEDataDecryptorFactory(passphrase.toCharArray(), digestCalcProvider))
                    } catch (e: Exception) { null }
                    if (plainStream != null) break
                }
            }
            if (plainStream == null)
                return DecryptResult(false, errorMessage = if (secRings == null)
                    "No matching secret key in keyring and no matching symmetric passphrase"
                else
                    "No matching secret key or incorrect passphrase")
            val litData = unwrapToLiteralData(plainStream)
                ?: return DecryptResult(false, errorMessage = "Invalid GPG data structure")
            val outName = litData.fileName.ifBlank {
                dataFile.name.removeSuffix(".gpg").removeSuffix(".asc")
            }
            val outFile = File(context.cacheDir, "decrypted_$outName")
            outFile.outputStream().use { litData.inputStream.copyTo(it) }
            AppLogger.log("DEBUG: decrypt() output=${outFile.absolutePath}")
            DecryptResult(success = true, outputPath = outFile.absolutePath)
        } catch (e: Exception) {
            AppLogger.log("ERROR decrypt: ${e.message}\n${e.stackTraceToString()}")
            DecryptResult(false, errorMessage = e.message ?: "Decryption failed")
        }
    }

    // ── Generate Key ─────────────────────────────────────────────────────────

    fun generateKey(params: KeyGenParams): GpgOperationResult {
        AppLogger.log("DEBUG: generateKey() name=${params.name} email=${params.email} type=${params.keyType}")
        return try {
            val kpg = JcaPGPKeyPair(
                PGPPublicKey.RSA_GENERAL,
                java.security.KeyPairGenerator.getInstance("RSA").apply {
                    initialize(params.keySize, SecureRandom())
                }.generateKeyPair(),
                Date()
            )
            val uid = buildString {
                append(params.name)
                if (params.comment.isNotBlank()) append(" (${params.comment})")
                append(" <${params.email}>")
            }
            val subGen = PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA or
                        KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
                setPreferredSymmetricAlgorithms(false, intArrayOf(
                    SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_128))
                setPreferredHashAlgorithms(false, intArrayOf(
                    HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA1))
                if (params.expiry > 0) setKeyExpirationTime(false, params.expiry * 86400L)
            }
            val gen = PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION, kpg, uid,
                digestCalcProvider.get(HashAlgorithmTags.SHA1),
                subGen.generate(), null,
                BcPGPContentSignerBuilder(kpg.publicKey.algorithm, HashAlgorithmTags.SHA256),
                BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, digestCalcProvider)
                    .build(params.passphrase.toCharArray())
            )
            val pubs = loadPublicKeyring()?.toMutableList() ?: mutableListOf()
            pubs.add(gen.generatePublicKeyRing())
            savePublicKeyring(pubs)
            val secs = loadSecretKeyring()?.toMutableList() ?: mutableListOf()
            secs.add(gen.generateSecretKeyRing())
            saveSecretKeyring(secs)
            AppLogger.log("DEBUG: generateKey() success uid=$uid")
            GpgOperationResult.Success("Key generated: $uid")
        } catch (e: Exception) {
            AppLogger.log("ERROR generateKey: ${e.message}\n${e.stackTraceToString()}")
            GpgOperationResult.Failure(e.message ?: "Key generation failed")
        }
    }

    // ── List Keys ────────────────────────────────────────────────────────────

    fun listKeys(): List<GpgKey> {
        AppLogger.log("DEBUG: listKeys() called")
        return loadPublicKeyring()?.map { ring ->
            val pub = ring.publicKey
            val fp = bytesToHex(pub.fingerprint)
            GpgKey(
                keyId = java.lang.Long.toHexString(pub.keyID).uppercase(),
                fingerprint = fp,
                uids = pub.userIDs.asSequence().map { it as String }.toList(),
                createdAt = pub.creationTime.time.toString(),
                expiresAt = if (pub.validSeconds > 0)
                    (pub.creationTime.time + pub.validSeconds * 1000).toString() else null,
                trustLevel = getTrustLevel(fp),
                type = KeyType.PUBLIC
            )
        } ?: emptyList()
    }

    fun listSecretKeys(): List<GpgKey> {
        return loadSecretKeyring()?.map { ring ->
            val sec = ring.secretKey
            val fp = bytesToHex(sec.publicKey.fingerprint)
            GpgKey(
                keyId = java.lang.Long.toHexString(sec.keyID).uppercase(),
                fingerprint = fp,
                uids = sec.userIDs.asSequence().map { it as String }.toList(),
                createdAt = sec.publicKey.creationTime.time.toString(),
                expiresAt = if (sec.publicKey.validSeconds > 0)
                    (sec.publicKey.creationTime.time + sec.publicKey.validSeconds * 1000).toString() else null,
                trustLevel = getTrustLevel(fp),
                type = KeyType.SECRET
            )
        } ?: emptyList()
    }

    // ── Import ───────────────────────────────────────────────────────────────

    fun importKey(keyFile: File): GpgOperationResult {
        AppLogger.log("DEBUG: importKey() from ${keyFile.absolutePath}")
        return try {
            val pub = tryImportPublicKeys(keyFile.inputStream())
            val sec = tryImportSecretKeys(keyFile.inputStream())
            if (pub + sec == 0) GpgOperationResult.Failure("No valid key found")
            else GpgOperationResult.Success("$pub public, $sec secret key(s) imported")
        } catch (e: Exception) {
            AppLogger.log("ERROR importKey: ${e.message}\n${e.stackTraceToString()}")
            GpgOperationResult.Failure(e.message ?: "Import failed")
        }
    }

    fun importKeyFromKeyserver(keyId: String, keyserver: String): GpgOperationResult {
        AppLogger.log("DEBUG: importKeyFromKeyserver() keyId=$keyId ks=$keyserver")
        return try {
            val base = keyserver.trimEnd('/')
            val url = "$base/pks/lookup?op=get&search=0x$keyId&options=mr"
            AppLogger.log("DEBUG: Fetching $url")
            val count = tryImportPublicKeys(java.net.URL(url).openStream())
            GpgOperationResult.Success("$count key(s) imported from $keyserver")
        } catch (e: Exception) {
            AppLogger.log("ERROR importKeyFromKeyserver: ${e.message}\n${e.stackTraceToString()}")
            GpgOperationResult.Failure(e.message ?: "Keyserver import failed")
        }
    }

    // ── Trust ────────────────────────────────────────────────────────────────

    fun trustKey(fingerprint: String, trustLevel: Int): GpgOperationResult {
        AppLogger.log("DEBUG: trustKey() fp=$fingerprint level=$trustLevel")
        return try {
            val lines = if (trustFile.exists())
                trustFile.readLines().filter { !it.startsWith(fingerprint.uppercase()) }.toMutableList()
            else mutableListOf()
            lines.add("${fingerprint.uppercase()}:$trustLevel")
            trustFile.writeText(lines.joinToString("\n"))
            GpgOperationResult.Success("Trust level set to $trustLevel")
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Failed to set trust level")
        }
    }

    // ── Delete ───────────────────────────────────────────────────────────────

    fun deleteKey(fingerprint: String): GpgOperationResult {
        AppLogger.log("DEBUG: deleteKey() fp=$fingerprint")
        return try {
            val fp = fingerprint.uppercase()
            loadPublicKeyring()?.filter { bytesToHex(it.publicKey.fingerprint) != fp }
                ?.let { savePublicKeyring(it) }
            loadSecretKeyring()?.filter { bytesToHex(it.secretKey.publicKey.fingerprint) != fp }
                ?.let { saveSecretKeyring(it) }
            if (trustFile.exists())
                trustFile.writeText(trustFile.readLines().filter { !it.startsWith(fp) }.joinToString("\n"))
            GpgOperationResult.Success("Key deleted")
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Failed to delete key")
        }
    }

    // ── Export ───────────────────────────────────────────────────────────────

    fun exportKey(fingerprint: String, armor: Boolean = true, secret: Boolean = false): GpgOperationResult {
        AppLogger.log("DEBUG: exportKey() fp=$fingerprint armor=$armor secret=$secret")
        return try {
            val fp = fingerprint.uppercase()
            val bout = ByteArrayOutputStream()
            val out: OutputStream = if (armor) armoredOut(bout) else bout
            if (secret) {
                loadSecretKeyring()?.firstOrNull { bytesToHex(it.secretKey.publicKey.fingerprint) == fp }
                    ?.encode(out) ?: return GpgOperationResult.Failure("Secret key not found")
            } else {
                loadPublicKeyring()?.firstOrNull { bytesToHex(it.publicKey.fingerprint) == fp }
                    ?.encode(out) ?: return GpgOperationResult.Failure("Public key not found")
            }
            if (armor) (out as ArmoredOutputStream).close()
            GpgOperationResult.Success(bout.toString())
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Export failed")
        }
    }

    fun uploadKeyToKeyserver(fingerprint: String, keyserver: String): GpgOperationResult {
        AppLogger.log("DEBUG: uploadKeyToKeyserver() fp=$fingerprint ks=$keyserver")
        return try {
            val exportResult = exportKey(fingerprint, armor = true, secret = false)
            if (exportResult !is GpgOperationResult.Success)
                return GpgOperationResult.Failure("Export failed before upload")
            val armoredKey = exportResult.message
            val base = keyserver.trimEnd('/')
            val url = "$base/pks/add"
            val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            val body = "keytext=" + java.net.URLEncoder.encode(armoredKey, "UTF-8")
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val responseCode = conn.responseCode
            if (responseCode in 200..299)
                GpgOperationResult.Success("Key successfully uploaded to $keyserver")
            else {
                AppLogger.log("ERROR uploadKeyToKeyserver: HTTP $responseCode")
                GpgOperationResult.Failure("Keyserver HTTP error $responseCode — key not found")
            }
        } catch (e: Exception) {
            AppLogger.log("ERROR uploadKeyToKeyserver: ${e.message}\n${e.stackTraceToString()}")
            GpgOperationResult.Failure(e.message ?: "Keyserver upload failed")
        }
    }

    // ── Private Helpers ──────────────────────────────────────────────────────

    private fun loadPublicKeyring(): List<PGPPublicKeyRing>? {
        if (!publicKeyringFile.exists()) return null
        return try {
            PGPPublicKeyRingCollection(
                FileInputStream(publicKeyringFile), fingerprintCalc
            ).keyRings.asSequence().toList()
        } catch (e: Exception) {
            AppLogger.log("ERROR loadPublicKeyring: ${e.message}\n${e.stackTraceToString()}")
            null
        }
    }

    private fun loadSecretKeyring(): List<PGPSecretKeyRing>? {
        if (!secretKeyringFile.exists()) return null
        return try {
            PGPSecretKeyRingCollection(
                FileInputStream(secretKeyringFile), fingerprintCalc
            ).keyRings.asSequence().toList()
        } catch (e: Exception) {
            AppLogger.log("ERROR loadSecretKeyring: ${e.message}\n${e.stackTraceToString()}")
            null
        }
    }

    private fun savePublicKeyring(rings: List<PGPPublicKeyRing>) {
        PGPPublicKeyRingCollection(rings).encode(FileOutputStream(publicKeyringFile))
    }

    private fun saveSecretKeyring(rings: List<PGPSecretKeyRing>) {
        PGPSecretKeyRingCollection(rings).encode(FileOutputStream(secretKeyringFile))
    }

    private fun tryImportPublicKeys(input: InputStream): Int {
        return try {
            val col = PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), fingerprintCalc)
            val incoming = col.keyRings.asSequence().toList()
            val existing = loadPublicKeyring()?.associateBy { bytesToHex(it.publicKey.fingerprint) }
                ?.toMutableMap() ?: mutableMapOf()
            var count = 0
            for (ring in incoming) {
                val fp = bytesToHex(ring.publicKey.fingerprint)
                if (!existing.containsKey(fp)) count++
                existing[fp] = ring
            }
            savePublicKeyring(existing.values.toList())
            count
        } catch (e: Exception) {
            AppLogger.log("ERROR tryImportPublicKeys: ${e.message}\n${e.stackTraceToString()}")
            0
        }
    }

    private fun tryImportSecretKeys(input: InputStream): Int {
        return try {
            val col = PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), fingerprintCalc)
            val incoming = col.keyRings.asSequence().toList()
            val existing = loadSecretKeyring()?.associateBy { bytesToHex(it.secretKey.publicKey.fingerprint) }
                ?.toMutableMap() ?: mutableMapOf()
            var count = 0
            for (ring in incoming) {
                val fp = bytesToHex(ring.secretKey.publicKey.fingerprint)
                if (!existing.containsKey(fp)) count++
                existing[fp] = ring
            }
            saveSecretKeyring(existing.values.toList())
            count
        } catch (e: Exception) {
            AppLogger.log("ERROR tryImportSecretKeys: ${e.message}\n${e.stackTraceToString()}")
            0
        }
    }

    private fun loadSignatures(input: InputStream): List<PGPSignature> {
        val sigs = mutableListOf<PGPSignature>()
        return try {
            val factory = PGPObjectFactory(PGPUtil.getDecoderStream(input), fingerprintCalc)
            var obj = factory.nextObject()
            while (obj != null) {
                when (obj) {
                    is PGPSignatureList -> obj.forEach { sigs.add(it) }
                    is PGPSignature -> sigs.add(obj)
                }
                obj = factory.nextObject()
            }
            sigs
        } catch (e: Exception) {
            AppLogger.log("ERROR loadSignatures: ${e.message}\n${e.stackTraceToString()}")
            sigs
        }
    }

    private fun unwrapToLiteralData(stream: InputStream): PGPLiteralData? {
        val factory = PGPObjectFactory(stream, fingerprintCalc)
        var obj = factory.nextObject()
        while (obj != null) {
            when (obj) {
                is PGPLiteralData -> return obj
                is PGPCompressedData -> {
                    val inner = PGPObjectFactory(obj.dataStream, fingerprintCalc)
                    var innerObj = inner.nextObject()
                    while (innerObj != null) {
                        if (innerObj is PGPLiteralData) return innerObj
                        innerObj = inner.nextObject()
                    }
                }
                is PGPOnePassSignatureList, is PGPSignatureList -> { /* skip */ }
            }
            obj = factory.nextObject()
        }
        return null
    }

    private fun findPublicKey(rings: List<PGPPublicKeyRing>, keyId: Long): PGPPublicKey? {
        for (ring in rings) for (key in ring.publicKeys) if (key.keyID == keyId) return key
        return null
    }

    private fun findEncryptionKey(rings: List<PGPPublicKeyRing>, fingerprint: String): PGPPublicKey? {
        val fp = fingerprint.uppercase()
        for (ring in rings) {
            if (bytesToHex(ring.publicKey.fingerprint) != fp) continue
            for (key in ring.publicKeys) if (key.isEncryptionKey) return key
        }
        return null
    }

    private fun findSecretKeyRing(fingerprint: String): PGPSecretKeyRing? {
        val fp = fingerprint.uppercase()
        return loadSecretKeyring()?.firstOrNull { bytesToHex(it.secretKey.publicKey.fingerprint) == fp }
    }

    private fun getTrustLevel(fingerprint: String): String {
        if (!trustFile.exists()) return "Unknown"
        val line = trustFile.readLines().firstOrNull { it.startsWith(fingerprint.uppercase()) }
            ?: return "Unknown"
        return when (line.substringAfter(":").trim()) {
            "2" -> "Undefined"; "3" -> "Marginal"; "4" -> "Full"; "5" -> "Ultimate"
            else -> "Unknown"
        }
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02X".format(it) }
}
