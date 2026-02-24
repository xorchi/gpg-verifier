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
import java.io.InputStream
import java.io.*
import java.net.URL
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.*

class GpgExecutor(private val context: Context) {

    // Factory: buat ArmoredOutputStream tanpa version header (@RELEASE_NAME@ placeholder)
    private fun armoredOut(out: java.io.OutputStream): ArmoredOutputStream =
        ArmoredOutputStream(out).also { it.setHeader("Version", null) }


    private val keyringDir: File by lazy {
        File(context.filesDir, "keyring").also { it.mkdirs() }
    }
    private val publicKeyringFile: File get() = File(keyringDir, "pubring.pgp")
    private val secretKeyringFile: File get() = File(keyringDir, "secring.pgp")
    private val trustFile: File       get() = File(keyringDir, "trustdb.txt")

    // ── Verify (detached signature) ───────────────────────────────────────────

    fun verify(dataFile: File, sigFile: File): VerificationResult {
        AppLogger.log("DEBUG: verify() dipanggil")
        return try {
            val sigs = loadSignatures(sigFile.inputStream())
            if (sigs.isEmpty())
                return VerificationResult(false, "", "", "", "", "File bukan signature GPG yang valid")
            val pubRings = loadPublicKeyring()
                ?: return VerificationResult(false, "", "", "", "", "Keyring kosong — import public key terlebih dahulu")
            for (sig in sigs) {
                val pubKey = findPublicKey(pubRings, sig.keyID) ?: continue
                sig.init(BcPGPContentVerifierBuilderProvider(), pubKey)
                sig.update(dataFile.readBytes())
                val valid = sig.verify()
                val fp  = bytesToHex(pubKey.fingerprint)
                val uid = (pubKey.userIDs.asSequence().firstOrNull() ?: "Unknown") as String
                val ts  = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(sig.creationTime)
                return VerificationResult(
                    isValid      = valid,
                    signedBy     = uid,
                    fingerprint  = fp,
                    timestamp    = ts,
                    trustLevel   = getTrustLevel(fp),
                    rawOutput    = if (valid) "Good signature from \"$uid\"" else "BAD signature",
                    errorMessage = if (!valid) "Signature tidak valid" else null
                )
            }
            VerificationResult(false, "", "", "", "", "No public key — key ID tidak ditemukan di keyring")
        } catch (e: Exception) {
            AppLogger.log("ERROR verify: ${e.message}")
            VerificationResult(false, "", "", "", "", e.message ?: "Verifikasi gagal")
        }
    }

    // ── Verify ClearSign (single .asc file) ──────────────────────────────────

    fun verifyClearSign(clearSignFile: File): VerificationResult {
        AppLogger.log("DEBUG: verifyClearSign() dipanggil file=${clearSignFile.name}")
        return try {
            val pubRings = loadPublicKeyring()
                ?: return VerificationResult(false, "", "", "", "", "Keyring kosong — import public key terlebih dahulu")

            val content = clearSignFile.readText()

            // Validasi format clearsign
            if (!content.contains("-----BEGIN PGP SIGNED MESSAGE-----"))
                return VerificationResult(false, "", "", "", "", "File bukan format clearsign GPG yang valid")

            // Parsing manual: ambil bagian teks dan signature
            val sigStart = content.indexOf("-----BEGIN PGP SIGNATURE-----")
            if (sigStart == -1)
                return VerificationResult(false, "", "", "", "", "Blok signature tidak ditemukan dalam file")

            // Ambil body teks (antara header + blank line dan -----BEGIN PGP SIGNATURE-----)
            val headerEnd = content.indexOf("\n\n")
            if (headerEnd == -1)
                return VerificationResult(false, "", "", "", "", "Format clearsign tidak valid — header tidak ditemukan")

            val signedText = content.substring(headerEnd + 2, sigStart).trimEnd('\n')
            val sigBlock   = content.substring(sigStart)

            // Parse signature block
            val sigBytes  = sigBlock.toByteArray(Charsets.UTF_8)
            val sigs      = loadSignatures(sigBytes.inputStream())
            if (sigs.isEmpty())
                return VerificationResult(false, "", "", "", "", "Tidak ada signature yang dapat diparse")

            // Clearsign menggunakan canonical line ending (\r\n) untuk verifikasi
            val canonicalText = signedText.lines().joinToString("\r\n")

            for (sig in sigs) {
                val pubKey = findPublicKey(pubRings, sig.keyID) ?: continue
                sig.init(BcPGPContentVerifierBuilderProvider(), pubKey)
                sig.update(canonicalText.toByteArray(Charsets.UTF_8))
                val valid = sig.verify()
                val fp  = bytesToHex(pubKey.fingerprint)
                val uid = (pubKey.userIDs.asSequence().firstOrNull() ?: "Unknown") as String
                val ts  = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(sig.creationTime)
                return VerificationResult(
                    isValid      = valid,
                    signedBy     = uid,
                    fingerprint  = fp,
                    timestamp    = ts,
                    trustLevel   = getTrustLevel(fp),
                    rawOutput    = if (valid) "Good signature from \"$uid\"" else "BAD signature",
                    errorMessage = if (!valid) "Signature tidak valid" else null
                )
            }
            VerificationResult(false, "", "", "", "", "No public key — key ID tidak ditemukan di keyring")
        } catch (e: Exception) {
            AppLogger.log("ERROR verifyClearSign: ${e.message}")
            VerificationResult(false, "", "", "", "", e.message ?: "Verifikasi clearsign gagal")
        }
    }

    // ── Sign ─────────────────────────────────────────────────────────────────

    fun sign(dataFile: File, keyFingerprint: String, mode: SignMode, passphrase: String): SignResult {
        AppLogger.log("DEBUG: sign() fp=$keyFingerprint mode=$mode")
        return try {
            val secRing = findSecretKeyRing(keyFingerprint)
                ?: return SignResult(false, errorMessage = "Secret key tidak ditemukan")
            val secKey = secRing.secretKey
            val privateKey = secKey.extractPrivateKey(
                org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()).build(passphrase.toCharArray())
            )
            val ext = when (mode) {
                SignMode.DETACH_ARMOR -> ".sig.asc"
                SignMode.DETACH       -> ".sig"
                SignMode.CLEARSIGN    -> ".asc"
                SignMode.NORMAL_ARMOR -> ".gpg.asc"
                SignMode.NORMAL       -> ".gpg"
            }
            val outFile = File(context.cacheDir, dataFile.name + ext)
            val sigType = when (mode) {
                SignMode.CLEARSIGN, SignMode.NORMAL, SignMode.NORMAL_ARMOR ->
                    PGPSignature.CANONICAL_TEXT_DOCUMENT
                else -> PGPSignature.BINARY_DOCUMENT
            }
            val sigGen = PGPSignatureGenerator(
                org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(
                    secKey.publicKey.algorithm, HashAlgorithmTags.SHA256)
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
                    // ClearSign TIDAK boleh pakai ArmoredOutputStream untuk header+body
                    // Format: plain text header → plain text body → armored signature block
                    val content = dataFile.readBytes()
                    val contentStr = content.toString(Charsets.UTF_8)
                    // Canonical text untuk signing: trailing whitespace di-strip per baris, CRLF line ending
                    val canonical = contentStr.lines()
                        .joinToString("\r\n") { it.trimEnd() }
                    sigGen.update(canonical.toByteArray(Charsets.UTF_8))
                    val sig = sigGen.generate()

                    // Tulis signature block ke ByteArray via ArmoredOutputStream
                    val sigBout = ByteArrayOutputStream()
                    armoredOut(sigBout).use { sig.encode(it) }
                    val sigArmored = sigBout.toString(Charsets.UTF_8)

                    // Tulis seluruh clearsign file sebagai plain text
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
            AppLogger.log("ERROR sign: ${e.message}")
            SignResult(false, errorMessage = e.message ?: "Sign gagal")
        }
    }

    // ── Encrypt ──────────────────────────────────────────────────────────────

    fun encrypt(dataFile: File, recipientFingerprints: List<String>, armor: Boolean): EncryptResult {
        AppLogger.log("DEBUG: encrypt() recipients=${recipientFingerprints.size} armor=$armor")
        return try {
            val pubRings = loadPublicKeyring()
                ?: return EncryptResult(false, errorMessage = "Keyring kosong")
            val encKeys = recipientFingerprints.map { fp ->
                findEncryptionKey(pubRings, fp)
                    ?: return EncryptResult(false, errorMessage = "Encryption key tidak ditemukan: $fp")
            }
            val ext = if (armor) ".asc" else ".gpg"
            val outFile = File(context.cacheDir, dataFile.name + ext)
            val rawOut: OutputStream =
                if (armor) armoredOut(outFile.outputStream()) else outFile.outputStream()

            val encGen = PGPEncryptedDataGenerator(
                org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(SecureRandom())
            ).apply { encKeys.forEach { addMethod(org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator(it)) } }

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
            AppLogger.log("ERROR encrypt: ${e.message}")
            EncryptResult(false, errorMessage = e.message ?: "Encrypt gagal")
        }
    }

    // ── Encrypt Symmetric ────────────────────────────────────────────────────

    fun encryptSymmetric(dataFile: File, passphrase: String, armor: Boolean): EncryptResult {
        AppLogger.log("DEBUG: encryptSymmetric() file=${dataFile.name} armor=$armor")
        return try {
            val ext = if (armor) ".asc" else ".gpg"
            val outFile = File(context.cacheDir, dataFile.name + ext)
            val rawOut: OutputStream =
                if (armor) armoredOut(outFile.outputStream()) else outFile.outputStream()

            val encGen = PGPEncryptedDataGenerator(
                org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(SecureRandom())
            ).apply {
                addMethod(org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator(
                    passphrase.toCharArray(),
                    HashAlgorithmTags.SHA256
                ))
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
            AppLogger.log("ERROR encryptSymmetric: ${e.message}")
            EncryptResult(false, errorMessage = e.message ?: "Encrypt simetris gagal")
        }
    }

    // ── Decrypt ──────────────────────────────────────────────────────────────

    fun decrypt(dataFile: File, passphrase: String): DecryptResult {
        AppLogger.log("DEBUG: decrypt() file=${dataFile.name}")
        return try {
            val rawBytes = PGPUtil.getDecoderStream(dataFile.inputStream()).readBytes()

            val factory = PGPObjectFactory(rawBytes.inputStream(), BcKeyFingerprintCalculator())
            var encData: PGPEncryptedDataList? = null
            var nextObj: Any? = factory.nextObject()
            while (nextObj != null && encData == null) {
                encData = nextObj as? PGPEncryptedDataList
                if (encData == null) nextObj = factory.nextObject()
            }
            if (encData == null)
                return DecryptResult(false, errorMessage = "File bukan data terenkripsi GPG")

            val secRings = loadSecretKeyring()
            var plainStream: InputStream? = null

            if (secRings != null) {
                outer@ for (enc in encData) {
                    if (enc !is PGPPublicKeyEncryptedData) continue
                    for (ring in secRings) {
                        val sec = ring.getSecretKey(enc.keyID) ?: continue
                        val privKey = try {
                            sec.extractPrivateKey(
                                org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                                    org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                                ).build(passphrase.toCharArray())
                            )
                        } catch (e: Exception) { continue }
                        plainStream = enc.getDataStream(
                            org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory(privKey)
                        )
                        break@outer
                    }
                }
            }

            if (plainStream == null && passphrase.isNotEmpty()) {
                for (enc in encData) {
                    if (enc !is PGPPBEEncryptedData) continue
                    plainStream = try {
                        enc.getDataStream(
                            org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory(
                                passphrase.toCharArray(),
                                org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                            )
                        )
                    } catch (e: Exception) { null }
                    if (plainStream != null) break
                }
            }

            if (plainStream == null)
                return DecryptResult(
                    false,
                    errorMessage = if (secRings == null)
                        "Tidak ada secret key di keyring dan tidak ada passphrase simetris yang cocok"
                    else
                        "Tidak ada secret key yang cocok atau passphrase salah"
                )

            val litData = unwrapToLiteralData(plainStream)
                ?: return DecryptResult(false, errorMessage = "Struktur data GPG tidak valid")

            val outName = litData.fileName.ifBlank {
                dataFile.name.removeSuffix(".gpg").removeSuffix(".asc")
            }
            val outFile = File(context.cacheDir, "decrypted_$outName")
            outFile.outputStream().use { litData.inputStream.copyTo(it) }
            AppLogger.log("DEBUG: decrypt() output=${outFile.absolutePath}")
            DecryptResult(success = true, outputPath = outFile.absolutePath)
        } catch (e: Exception) {
            AppLogger.log("ERROR decrypt: ${e.message}")
            DecryptResult(false, errorMessage = e.message ?: "Decrypt gagal")
        }
    }

    private fun unwrapToLiteralData(stream: InputStream): PGPLiteralData? {
        val factory = PGPObjectFactory(stream, BcKeyFingerprintCalculator())
        var obj = factory.nextObject()
        while (obj != null) {
            when (obj) {
                is PGPLiteralData    -> return obj
                is PGPCompressedData -> return unwrapToLiteralData(obj.dataStream)
                is PGPOnePassSignatureList,
                is PGPSignatureList  -> { /* lewati */ }
            }
            obj = factory.nextObject()
        }
        return null
    }

    // ── Generate Key ─────────────────────────────────────────────────────────

    fun generateKey(params: KeyGenParams): GpgOperationResult {
        AppLogger.log("DEBUG: generateKey() name=${params.name} email=${params.email} type=${params.keyType}")
        return try {
            val now = Date()
            val bcDigestProvider = org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
            val sha1Calc = bcDigestProvider.get(HashAlgorithmTags.SHA1)

            val primaryKpg: org.bouncycastle.openpgp.PGPKeyPair
            val encryptKpg: org.bouncycastle.openpgp.PGPKeyPair

            if (params.keyType.uppercase() == "ED25519") {
                // Ed25519 primary (sign) + Curve25519 subkey (encrypt)
                val edKpg = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator().apply {
                    init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
                }.generateKeyPair()
                primaryKpg = org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair(
                    PGPPublicKey.EDDSA, edKpg, now)

                val x25519Kpg = org.bouncycastle.crypto.generators.X25519KeyPairGenerator().apply {
                    init(org.bouncycastle.crypto.params.X25519KeyGenerationParameters(SecureRandom()))
                }.generateKeyPair()
                encryptKpg = org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair(
                    PGPPublicKey.ECDH, x25519Kpg, now)
            } else {
                // RSA primary (sign) + RSA subkey (encrypt)
                val rsaKeyGen = org.bouncycastle.crypto.generators.RSAKeyPairGenerator()
                rsaKeyGen.init(org.bouncycastle.crypto.params.RSAKeyGenerationParameters(
                    java.math.BigInteger.valueOf(65537),
                    SecureRandom(),
                    params.keySize,
                    12
                ))
                primaryKpg = org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair(
                    PGPPublicKey.RSA_SIGN, rsaKeyGen.generateKeyPair(), now)
                encryptKpg = org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair(
                    PGPPublicKey.RSA_ENCRYPT, rsaKeyGen.generateKeyPair(), now)
            }

            val uid = buildString {
                append(params.name)
                if (params.comment.isNotBlank()) append(" (${params.comment})")
                append(" <${params.email}>")
            }

            val encryptor = org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256)).build(params.passphrase.toCharArray())

            val primarySubGen = PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
                setPreferredSymmetricAlgorithms(false, intArrayOf(
                    SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_128))
                setPreferredHashAlgorithms(false, intArrayOf(
                    HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA512))
                if (params.expiry > 0) setKeyExpirationTime(false, params.expiry * 86400L)
            }

            val encSubGen = PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
                if (params.expiry > 0) setKeyExpirationTime(false, params.expiry * 86400L)
            }

            val gen = PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION, primaryKpg, uid,
                sha1Calc,
                primarySubGen.generate(), null,
                org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(primaryKpg.publicKey.algorithm, HashAlgorithmTags.SHA256),
                encryptor
            ).apply {
                addSubKey(encryptKpg, encSubGen.generate(), null,
                    org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(primaryKpg.publicKey.algorithm, HashAlgorithmTags.SHA256))
            }

            val pubs = loadPublicKeyring()?.toMutableList() ?: mutableListOf()
            pubs.add(gen.generatePublicKeyRing())
            savePublicKeyring(pubs)
            val secs = loadSecretKeyring()?.toMutableList() ?: mutableListOf()
            secs.add(gen.generateSecretKeyRing())
            saveSecretKeyring(secs)
            AppLogger.log("DEBUG: generateKey() success uid=$uid")
            GpgOperationResult.Success("Key generated: $uid")
        } catch (e: Exception) {
            AppLogger.log("ERROR generateKey: ${e.message}")
            AppLogger.log("ERROR generateKey cause: ${e.cause?.message}")
            AppLogger.log("ERROR generateKey class: ${e.javaClass.name}")
            AppLogger.log("ERROR generateKey stack: ${e.stackTrace.take(5).joinToString(" | ") { "${it.className}.${it.methodName}:${it.lineNumber}" }}")
            GpgOperationResult.Failure(e.message ?: "Key generation gagal")
        }
    }

    // ── List Keys ────────────────────────────────────────────────────────────

    fun listKeys(): List<GpgKey> {
        AppLogger.log("DEBUG: listKeys() dipanggil")
        return loadPublicKeyring()?.map { ring ->
            val pub = ring.publicKey
            val fp  = bytesToHex(pub.fingerprint)
            GpgKey(
                keyId       = java.lang.Long.toHexString(pub.keyID).uppercase(),
                fingerprint = fp,
                uids        = pub.userIDs.asSequence().map { it as String }.toList(),
                createdAt   = pub.creationTime.time.toString(),
                expiresAt   = if (pub.validSeconds > 0)
                    (pub.creationTime.time + pub.validSeconds * 1000).toString() else null,
                trustLevel  = getTrustLevel(fp),
                type        = KeyType.PUBLIC
            )
        } ?: emptyList()
    }

    fun listSecretKeys(): List<GpgKey> {
        return loadSecretKeyring()?.map { ring ->
            val sec = ring.secretKey
            val fp  = bytesToHex(sec.publicKey.fingerprint)
            GpgKey(
                keyId       = java.lang.Long.toHexString(sec.keyID).uppercase(),
                fingerprint = fp,
                uids        = sec.userIDs.asSequence().map { it as String }.toList(),
                createdAt   = sec.publicKey.creationTime.time.toString(),
                expiresAt   = if (sec.publicKey.validSeconds > 0)
                    (sec.publicKey.creationTime.time + sec.publicKey.validSeconds * 1000).toString() else null,
                trustLevel  = getTrustLevel(fp),
                type        = KeyType.SECRET
            )
        } ?: emptyList()
    }

    // ── Import ───────────────────────────────────────────────────────────────

    fun importKey(keyFile: File): GpgOperationResult {
        AppLogger.log("DEBUG: importKey() dari ${keyFile.absolutePath}")
        return try {
            val pub = tryImportPublicKeys(keyFile.inputStream())
            val sec = tryImportSecretKeys(keyFile.inputStream())
            if (pub + sec == 0) GpgOperationResult.Failure("Tidak ada key yang valid ditemukan")
            else GpgOperationResult.Success("$pub public, $sec secret key diimport")
        } catch (e: Exception) {
            AppLogger.log("ERROR importKey: ${e.message}")
            GpgOperationResult.Failure(e.message ?: "Import gagal")
        }
    }

    fun exportKeyToKeyserver(fingerprint: String, keyserver: String): GpgOperationResult {
        AppLogger.log("DEBUG: exportKeyToKeyserver() fp=$fingerprint ks=$keyserver")
        return try {
            // Export public key sebagai armored string
            val exportResult = exportKey(fingerprint, armor = true, secret = false)
            val armoredKey = when (exportResult) {
                is GpgOperationResult.Success -> exportResult.message
                is GpgOperationResult.Failure -> return exportResult
            }

            val base = keyserver.trimEnd('/').replace("hkps://", "https://").replace("hkp://", "http://")
            val url  = "$base/pks/add"
            AppLogger.log("DEBUG: Uploading ke $url")

            val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = 10000
            conn.readTimeout = 15000
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            conn.setRequestProperty("User-Agent", "GPGVerifier/1.0")

            val body = "keytext=" + java.net.URLEncoder.encode(armoredKey, "UTF-8")
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }

            val responseCode = conn.responseCode
            AppLogger.log("DEBUG: Keyserver upload response: $responseCode")

            if (responseCode in 200..299) {
                GpgOperationResult.Success("Key berhasil diupload ke $keyserver")
            } else {
                GpgOperationResult.Failure("Keyserver error HTTP $responseCode")
            }
        } catch (e: Exception) {
            AppLogger.log("ERROR exportKeyToKeyserver: ${e.message}")
            GpgOperationResult.Failure(e.message ?: "Upload ke keyserver gagal")
        }
    }

    fun importKeyFromKeyserver(keyId: String, keyserver: String): GpgOperationResult {
        AppLogger.log("DEBUG: importKeyFromKeyserver() keyId=$keyId ks=$keyserver")
        return try {
            val base   = keyserver.trimEnd('/').replace("hkps://", "https://").replace("hkp://", "http://")
            val search = if (keyId.contains("@")) keyId else "0x$keyId"
            val url    = "$base/pks/lookup?op=get&search=$search&options=mr"
            AppLogger.log("DEBUG: Fetching $url")
            val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 10000
            conn.readTimeout    = 15000
            conn.setRequestProperty("User-Agent", "GPGVerifier/1.0")
            val responseCode = conn.responseCode
            if (responseCode != 200)
                return GpgOperationResult.Failure("Keyserver error HTTP $responseCode — key tidak ditemukan")
            val count = tryImportPublicKeys(conn.inputStream)
            GpgOperationResult.Success("$count key diimport dari $keyserver")
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
                trustFile.readLines().filter { !it.startsWith(fingerprint.uppercase()) }.toMutableList()
            else mutableListOf()
            lines.add("${fingerprint.uppercase()}:$trustLevel")
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
            val fp = fingerprint.uppercase()
            loadPublicKeyring()?.filter { bytesToHex(it.publicKey.fingerprint) != fp }
                ?.let { savePublicKeyring(it) }
            loadSecretKeyring()?.filter { bytesToHex(it.secretKey.publicKey.fingerprint) != fp }
                ?.let { saveSecretKeyring(it) }
            if (trustFile.exists())
                trustFile.writeText(trustFile.readLines().filter { !it.startsWith(fp) }.joinToString("\n"))
            GpgOperationResult.Success("Key dihapus")
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Gagal hapus key")
        }
    }

    // ── Export ───────────────────────────────────────────────────────────────

    fun exportKey(fingerprint: String, armor: Boolean = true, secret: Boolean = false): GpgOperationResult {
        AppLogger.log("DEBUG: exportKey() fp=$fingerprint armor=$armor secret=$secret")
        return try {
            val fp   = fingerprint.uppercase()
            val bout = ByteArrayOutputStream()
            val out: OutputStream = if (armor) armoredOut(bout) else bout
            if (secret) {
                loadSecretKeyring()?.firstOrNull { bytesToHex(it.secretKey.publicKey.fingerprint) == fp }
                    ?.encode(out) ?: return GpgOperationResult.Failure("Secret key tidak ditemukan")
            } else {
                loadPublicKeyring()?.firstOrNull { bytesToHex(it.publicKey.fingerprint) == fp }
                    ?.encode(out) ?: return GpgOperationResult.Failure("Public key tidak ditemukan")
            }
            if (armor) (out as ArmoredOutputStream).close()
            GpgOperationResult.Success(bout.toString())
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Export gagal")
        }
    }

    // ── Private Helpers ──────────────────────────────────────────────────────

    private fun loadPublicKeyring(): List<PGPPublicKeyRing>? {
        if (!publicKeyringFile.exists()) return null
        return try {
            PGPPublicKeyRingCollection(
                FileInputStream(publicKeyringFile), BcKeyFingerprintCalculator()
            ).keyRings.asSequence().toList()
        } catch (e: Exception) { AppLogger.log("ERROR loadPublicKeyring: ${e.message}"); null }
    }

    private fun loadSecretKeyring(): List<PGPSecretKeyRing>? {
        if (!secretKeyringFile.exists()) return null
        return try {
            PGPSecretKeyRingCollection(
                FileInputStream(secretKeyringFile), BcKeyFingerprintCalculator()
            ).keyRings.asSequence().toList()
        } catch (e: Exception) { AppLogger.log("ERROR loadSecretKeyring: ${e.message}"); null }
    }

    private fun savePublicKeyring(rings: List<PGPPublicKeyRing>) {
        PGPPublicKeyRingCollection(rings).encode(FileOutputStream(publicKeyringFile))
    }

    private fun saveSecretKeyring(rings: List<PGPSecretKeyRing>) {
        PGPSecretKeyRingCollection(rings).encode(FileOutputStream(secretKeyringFile))
    }

    private fun tryImportPublicKeys(input: InputStream): Int {
        return try {
            val col = PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), BcKeyFingerprintCalculator())
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
        } catch (e: Exception) { 0 }
    }

    private fun tryImportSecretKeys(input: InputStream): Int {
        return try {
            val col = PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), BcKeyFingerprintCalculator())
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
        } catch (e: Exception) { 0 }
    }

    private fun loadSignatures(input: InputStream): List<PGPSignature> {
        val sigs = mutableListOf<PGPSignature>()
        return try {
            val factory = PGPObjectFactory(PGPUtil.getDecoderStream(input), BcKeyFingerprintCalculator())
            var obj = factory.nextObject()
            while (obj != null) {
                when (obj) {
                    is PGPSignatureList -> obj.forEach { sigs.add(it) }
                    is PGPSignature     -> sigs.add(obj)
                }
                obj = factory.nextObject()
            }
            sigs
        } catch (e: Exception) { AppLogger.log("ERROR loadSignatures: ${e.message}"); sigs }
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
            "2"  -> "Undefined"; "3" -> "Marginal"; "4" -> "Full"; "5" -> "Ultimate"
            else -> "Unknown"
        }
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02X".format(it) }
}
