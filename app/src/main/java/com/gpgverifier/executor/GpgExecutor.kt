package com.gpgverifier.executor

import android.content.Context
import com.gpgverifier.model.*
import com.gpgverifier.util.AppLogger
import org.bouncycastle.bcpg.ArmoredOutputStream

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.jcajce.*
import java.io.InputStream
import java.io.*
import java.net.URL
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.*

private fun armoredOut(out: java.io.OutputStream): ArmoredOutputStream {
    val aos = ArmoredOutputStream(out)
    aos.setHeader("Version", null)   // strip Version header from armored output
    return aos
}


class GpgExecutor(private val context: Context) {

    private val keyringDir: File by lazy {
        File(context.filesDir, "keyring").also { it.mkdirs() }
    }
    private val publicKeyringFile: File get() = File(keyringDir, "pubring.pgp")
    private val secretKeyringFile: File get() = File(keyringDir, "secring.pgp")
    private val trustFile: File       get() = File(keyringDir, "trustdb.txt")

    // ── Output file naming helpers ────────────────────────────────────────────

    /**
     * Mengembalikan File dengan nama unik di [dir].
     * If [name] already exists, appends suffix -1, -2, etc. before the leading extension.
     * Example: "file.txt" → "file-1.txt" → "file-2.txt"
     */
    // Save directly to Downloads; fall back to cacheDir on failure
    private fun saveToDownloads(name: String): File {
        // Avoid double extension: strip trailing .asc/.gpg/.sig if already present
        val cleanName = if (name.endsWith(".asc.asc") || name.endsWith(".gpg.asc") ||
                            name.endsWith(".sig.asc") || name.endsWith(".asc.gpg") ||
                            name.endsWith(".gpg.gpg") || name.endsWith(".asc.sig")) {
            name.substringBeforeLast('.')
        } else name
        return try {
            val dir = android.os.Environment.getExternalStoragePublicDirectory(
                android.os.Environment.DIRECTORY_DOWNLOADS)
            dir.mkdirs()
            uniqueFile(dir, cleanName)
        } catch (e: Exception) {
            uniqueFile(context.cacheDir, cleanName)
        }
    }

    private fun uniqueFile(dir: File, name: String): File {
        val target = File(dir, name)
        if (!target.exists()) return target

        // Split base name and leading extension
        // "file.txt.asc" → base="file", ext=".txt.asc"
        val dotIdx = name.indexOf('.')
        val base   = if (dotIdx != -1) name.substring(0, dotIdx) else name
        val ext    = if (dotIdx != -1) name.substring(dotIdx) else ""

        var counter = 1
        while (true) {
            val candidate = File(dir, "$base-$counter$ext")
            if (!candidate.exists()) return candidate
            counter++
        }
    }

    /**
     * Generates the output filename for decrypt operations:
     * strips the last extension from [name]. If no extension, name is unchanged.
     * Example: "file.txt.gpg" → "file.txt", "file.gpg" → "file"
     */
    private fun decryptedName(name: String): String {
        val lastDot = name.lastIndexOf('.')
        return if (lastDot != -1) name.substring(0, lastDot) else name
    }


    // ── Hash algorithm helpers ────────────────────────────────────────────────

    /**
     * Returns the hash algorithm name for the given signature packet tag.
     * The tag is read directly from [PGPSignature.hashAlgorithm] —
     * no user input required; auto-detected from the packet.
     */
    private fun hashAlgorithmName(tag: Int): String = when (tag) {
        org.bouncycastle.bcpg.HashAlgorithmTags.MD5      -> "MD5"
        org.bouncycastle.bcpg.HashAlgorithmTags.SHA1     -> "SHA-1"
        org.bouncycastle.bcpg.HashAlgorithmTags.SHA224   -> "SHA-224"
        org.bouncycastle.bcpg.HashAlgorithmTags.SHA256   -> "SHA-256"
        org.bouncycastle.bcpg.HashAlgorithmTags.SHA384   -> "SHA-384"
        org.bouncycastle.bcpg.HashAlgorithmTags.SHA512   -> "SHA-512"
        org.bouncycastle.bcpg.HashAlgorithmTags.SHA3_256 -> "SHA3-256"
        org.bouncycastle.bcpg.HashAlgorithmTags.SHA3_512 -> "SHA3-512"
        else                                             -> "Unknown ($tag)"
    }

    /**
     * Selects the verifier provider based on BOTH the key algorithm and hash algorithm.
     *
     * Rules:
     *  - EdDSA (Ed25519, algo 22) and ECDSA (algo 19) MUST use JCA provider.
     *    The lightweight Bc provider does not implement these curves on Android.
     *  - DSA (algo 17) requires JCA for SHA-256+ hashes.
     *  - RSA with SHA-1 or SHA-256 can use the lightweight Bc provider.
     *  - Everything else defaults to JCA (full bcprov) for maximum compatibility.
     */
    private fun resolveVerifierProvider(
        hashAlgTag: Int,
        keyAlgTag: Int = -1
    ): org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider {
        // EdDSA (22) and ECDSA (19) always require JCA — no exceptions
        val isEdDsaOrEcdsa = keyAlgTag == org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EDDSA ||
                             keyAlgTag == org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ECDSA ||
                             keyAlgTag == 22 // Ed25519 literal constant for older bcpg versions

        if (isEdDsaOrEcdsa) {
            AppLogger.d("resolveVerifierProvider: keyAlg=$keyAlgTag → JCA (EdDSA/ECDSA)", AppLogger.TAG_CRYPTO)
            return org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider()
                .setProvider(BC_PROVIDER)
        }

        return when (hashAlgTag) {
            org.bouncycastle.bcpg.HashAlgorithmTags.SHA1,
            org.bouncycastle.bcpg.HashAlgorithmTags.SHA256 ->
                // RSA + SHA-1/256: lightweight Bc is sufficient
                org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider()
            else ->
                // SHA-384, SHA-512, SHA-224, SHA3-* → use JCA (full bcprov)
                org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider()
                    .setProvider(BC_PROVIDER)
        }
    }

    companion object {
        /** Singleton BouncyCastleProvider — avoid re-instantiation on every verify call */
        val BC_PROVIDER by lazy {
            org.bouncycastle.jce.provider.BouncyCastleProvider().also { provider ->
                if (java.security.Security.getProvider("BC") == null) {
                    java.security.Security.addProvider(provider)
                }
            }
        }
    }

    init {
        // Ensure BC provider is registered when GpgExecutor is first instantiated
        BC_PROVIDER
    }

    // ── Verify (detached signature) ───────────────────────────────────────────

    fun verify(dataFile: File, sigFile: File): VerificationResult {
        AppLogger.d("verify() called", AppLogger.TAG_CRYPTO)
        return try {
            val sigs = loadSignatures(sigFile.inputStream())
            if (sigs.isEmpty())
                return VerificationResult(false, "", "", "", "", "Not a valid GPG signature file")
            val pubRings = loadPublicKeyring()
                ?: return VerificationResult(false, "", "", "", "", "Keyring is empty — import a public key first")
            for (sig in sigs) {
                val pubKey = findPublicKey(pubRings, sig.keyID) ?: continue
                // Auto-detected: sig.hashAlgorithm is read directly from the signature packet
                val algTag  = sig.hashAlgorithm
                val dataBytes = dataFile.readBytes()
                AppLogger.d("verify: hashAlg=${hashAlgorithmName(algTag)} keyID=0x${sig.keyID.let { java.lang.Long.toUnsignedString(it, 16).uppercase() }} dataSize=${dataBytes.size}B uid=${(pubKey.userIDs.asSequence().firstOrNull() ?: "?")} keyAlg=${pubKey.algorithm}", AppLogger.TAG_CRYPTO)
                sig.init(resolveVerifierProvider(algTag, pubKey.algorithm), pubKey)
                sig.update(dataBytes)
                val valid = sig.verify()
                AppLogger.d("verify: cryptographic check result=${if (valid) "PASS" else "FAIL"}", AppLogger.TAG_CRYPTO)
                val fp  = bytesToHex(pubKey.fingerprint)
                val uid = (pubKey.userIDs.asSequence().firstOrNull() ?: "Unknown") as String
                val ts  = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(sig.creationTime)
                return VerificationResult(
                    isValid       = valid,
                    signedBy      = uid,
                    fingerprint   = fp,
                    timestamp     = ts,
                    trustLevel    = getTrustLevel(fp),
                    hashAlgorithm = hashAlgorithmName(algTag),
                    rawOutput     = if (valid) "Good signature from \"$uid\"" else "BAD signature",
                    errorMessage  = if (!valid) "Invalid signature" else null
                )
            }
            VerificationResult(false, "", "", "", "", "No public key — key ID not found in keyring")
        } catch (e: Exception) {
            AppLogger.e("verify() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            VerificationResult(false, "", "", "", "", e.message ?: "Verification failed")
        }
    }

    // ── Verify ClearSign (single .asc file) ──────────────────────────────────

    fun verifyClearSign(clearSignFile: File): VerificationResult {
        AppLogger.d("verifyClearSign() called file=${clearSignFile.name}", AppLogger.TAG_CRYPTO)
        return try {
            val pubRings = loadPublicKeyring()
                ?: return VerificationResult(false, "", "", "", "", "Keyring is empty — import a public key first")

            val content = clearSignFile.readText(Charsets.UTF_8)

            // Validasi format clearsign
            val msgHeader = "-----BEGIN PGP SIGNED MESSAGE-----"
            val sigHeader = "-----BEGIN PGP SIGNATURE-----"
            val sigFooter = "-----END PGP SIGNATURE-----"

            if (!content.contains(msgHeader))
                return VerificationResult(false, "", "", "", "", "File is not a valid GPG clearsign format")

            val sigStart = content.indexOf(sigHeader)
            if (sigStart == -1)
                return VerificationResult(false, "", "", "", "", "Signature block not found in file")

            val sigEnd = content.indexOf(sigFooter)
            if (sigEnd == -1)
                return VerificationResult(false, "", "", "", "", "Signature footer not found in file")

            // Find the first blank line AFTER the PGP header block (Hash: ...)
            // PGP header ends at the first blank line after "-----BEGIN PGP SIGNED MESSAGE-----"
            // Strategy: scan line-by-line so we are immune to mixed \r\n / \n in the header.
            val msgHeaderEnd = content.indexOf(msgHeader) + msgHeader.length
            val afterHeader  = content.substring(msgHeaderEnd)

            // Find the blank line that separates PGP headers from the signed body.
            // A blank line is \n\n or \r\n\r\n (or the header ends right at a \n\n).
            val blankLF   = afterHeader.indexOf("\n\n")
            val blankCRLF = afterHeader.indexOf("\r\n\r\n")

            // Pick whichever blank-line marker appears first.
            val (headerBodySep, sepLen) = when {
                blankCRLF != -1 && (blankLF == -1 || blankCRLF <= blankLF) ->
                    Pair(msgHeaderEnd + blankCRLF, 4)
                blankLF != -1 ->
                    Pair(msgHeaderEnd + blankLF, 2)
                else -> return VerificationResult(false, "", "", "", "", "Invalid clearsign format — header not found")
            }
            val headerEnd = headerBodySep + sepLen

            // Signed text: between end-of-header blank line and start of signature block
            val signedText = content.substring(headerEnd, sigStart)
                .trimEnd('\r', '\n')

            // Parse signature block directly via ArmoredInputStream instead of PGPUtil.getDecoderStream
            // to tolerate custom headers such as "Version: GPGVerifier"
            val sigBlock = content.substring(sigStart, sigEnd + sigFooter.length)
            val sigs = parseClearSignSignatureBlock(sigBlock)
            AppLogger.d("verifyClearSign: parsedSigs=${sigs.size} sigBlockLen=${sigBlock.length}B", AppLogger.TAG_CRYPTO)
            if (sigs.isEmpty())
                return VerificationResult(false, "", "", "", "", "No parseable signature found")

            // RFC 4880 §7.1: strip trailing whitespace; every line (incl. last) ends with \r\n.
            // Normalise to \n first so split("\n") is deterministic regardless of
            // whether the file came from GPG/Termux (\n) or a Windows tool (\r\n).
            val normalised = signedText.replace("\r\n", "\n").replace("\r", "\n")
            val lines = normalised.split("\n").map { it.trimEnd() }
            val lastNonEmpty = lines.indexOfLast { it.isNotEmpty() }
            val canonicalText = if (lastNonEmpty == -1) "" else
                lines.subList(0, lastNonEmpty + 1).joinToString("\r\n")

            for (sig in sigs) {
                val pubKey = findPublicKey(pubRings, sig.keyID) ?: continue
                val algTag  = sig.hashAlgorithm
                val canonicalBytes = canonicalText.toByteArray(Charsets.UTF_8)
                AppLogger.d("verifyClearSign: hashAlg=${hashAlgorithmName(algTag)} keyID=0x${sig.keyID.let { java.lang.Long.toUnsignedString(it, 16).uppercase() }} canonicalLen=${canonicalBytes.size}B uid=${(pubKey.userIDs.asSequence().firstOrNull() ?: "?")} keyAlg=${pubKey.algorithm}", AppLogger.TAG_CRYPTO)
                sig.init(resolveVerifierProvider(algTag, pubKey.algorithm), pubKey)
                sig.update(canonicalBytes)
                val valid = sig.verify()
                AppLogger.d("verifyClearSign: cryptographic check result=${if (valid) "PASS" else "FAIL"}", AppLogger.TAG_CRYPTO)
                val fp  = bytesToHex(pubKey.fingerprint)
                val uid = (pubKey.userIDs.asSequence().firstOrNull() ?: "Unknown") as String
                val ts  = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(sig.creationTime)
                return VerificationResult(
                    isValid       = valid,
                    signedBy      = uid,
                    fingerprint   = fp,
                    timestamp     = ts,
                    trustLevel    = getTrustLevel(fp),
                    hashAlgorithm = hashAlgorithmName(algTag),
                    rawOutput     = if (valid) "Good signature from \"$uid\"" else "BAD signature",
                    errorMessage  = if (!valid) "Invalid signature" else null
                )
            }
            VerificationResult(false, "", "", "", "", "No public key — key ID not found in keyring")
        } catch (e: Exception) {
            AppLogger.e("verifyClearSign() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            VerificationResult(false, "", "", "", "", e.message ?: "ClearSign verification failed")
        }
    }

    /**
     * Fix for "invalid armor header":
     * Parse the PGP SIGNATURE block directly via ArmoredInputStream,
     * which tolerates extra headers such as "Version: GPGVerifier".
     */
    private fun parseClearSignSignatureBlock(sigBlock: String): List<PGPSignature> {
        val sigs = mutableListOf<PGPSignature>()
        return try {
            val armoredIn = org.bouncycastle.bcpg.ArmoredInputStream(
                sigBlock.byteInputStream(Charsets.UTF_8)
            )
            val factory = PGPObjectFactory(
                armoredIn,
                org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()
            )
            var obj = factory.nextObject()
            while (obj != null) {
                when (obj) {
                    is PGPSignatureList -> obj.forEach { sigs.add(it) }
                    is PGPSignature     -> sigs.add(obj)
                }
                obj = factory.nextObject()
            }
            sigs
        } catch (e: Exception) {
            AppLogger.e("parseClearSignSignatureBlock() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            sigs
        }
    }

    // ── Sign ─────────────────────────────────────────────────────────────────

    fun sign(dataFile: File, keyFingerprint: String, mode: SignMode, passphrase: String, originalName: String = dataFile.name, hashAlgorithm: com.gpgverifier.model.HashAlgorithm = com.gpgverifier.model.HashAlgorithm.SHA256): SignResult {
        val tSign = System.currentTimeMillis()
        AppLogger.d("sign() fp=$keyFingerprint mode=$mode hashAlg=${hashAlgorithm.headerName} inputSize=${dataFile.length()}B", AppLogger.TAG_CRYPTO)
        return try {
            val secRing = findSecretKeyRing(keyFingerprint)
                ?: return SignResult(false, errorMessage = "Secret key not found")
            val secKey = secRing.secretKey
            // EdDSA/ECDSA secret keys must be decrypted via JCA provider on Android
            val keyAlgForDecrypt = secKey.publicKey.algorithm
            val isEdDsaOrEcdsaKey = keyAlgForDecrypt == org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EDDSA ||
                                     keyAlgForDecrypt == org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ECDSA ||
                                     keyAlgForDecrypt == 22
            val privateKey = if (isEdDsaOrEcdsaKey) {
                secKey.extractPrivateKey(
                    org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder()
                        .setProvider(BC_PROVIDER).build(passphrase.toCharArray())
                )
            } else {
                secKey.extractPrivateKey(
                    org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                        org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                    ).build(passphrase.toCharArray())
                )
            }
            val ext = when (mode) {
                SignMode.DETACH_ARMOR -> ".asc"
                SignMode.DETACH       -> ".sig"
                SignMode.CLEARSIGN    -> ".asc"
                SignMode.NORMAL_ARMOR -> ".gpg.asc"
                SignMode.NORMAL       -> ".gpg"
            }
            val outFile = saveToDownloads(originalName + ext)

            // sigType: NORMAL and NORMAL_ARMOR are binary signed documents
            val sigType = when (mode) {
                SignMode.CLEARSIGN -> PGPSignature.CANONICAL_TEXT_DOCUMENT
                else               -> PGPSignature.BINARY_DOCUMENT
            }
            // For EdDSA (22) and ECDSA (19), BcPGPContentSignerBuilder does not work on Android.
            // JcaPGPContentSignerBuilder via full bcprov is required.
            val keyAlgorithm = secKey.publicKey.algorithm
            val isEdDsaOrEcdsa = keyAlgorithm == org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EDDSA ||
                                  keyAlgorithm == org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ECDSA ||
                                  keyAlgorithm == 22
            val contentSignerBuilder = if (isEdDsaOrEcdsa) {
                AppLogger.d("sign(): keyAlg=$keyAlgorithm → JcaPGPContentSignerBuilder (EdDSA/ECDSA)", AppLogger.TAG_CRYPTO)
                org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder(
                    keyAlgorithm, hashAlgorithm.tag).setProvider(BC_PROVIDER)
            } else {
                org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder(
                    keyAlgorithm, hashAlgorithm.tag)
            }
            val sigGen = PGPSignatureGenerator(contentSignerBuilder).apply {
                init(sigType, privateKey)
                // Embed signer's User ID in the hashed subpackets so verifiers
                // (including GnuPG --verify -v) can display identity without a
                // full key lookup. RFC 4880 §5.2.3.22 — optional but recommended.
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
                    // ClearSign must NOT use ArmoredOutputStream for header+body.
                    // Format: plain text header → plain text body → armored signature block.
                    //
                    // RFC 4880 §7.1 canonicalization rules:
                    //   1. Strip trailing whitespace from every line.
                    //   2. Line endings are \r\n for the data fed to the signature engine.
                    //   3. The body written into the clearsign file uses \n (LF only) —
                    //      GPG normalises to CRLF internally when it verifies.
                    //      Writing \r\n into the file body would cause double-CRLF
                    //      when GPG reads it back, breaking cross-tool verification.

                    val contentStr = dataFile.readBytes().toString(Charsets.UTF_8)

                    // Strip \r so we always work with \n-only lines internally.
                    val linesLF = contentStr.replace("\r\n", "\n").replace("\r", "\n")

                    // Canonical form fed to the signature engine: trailing whitespace
                    // stripped per line, joined with \r\n, terminated with \r\n.
                    // RFC 4880 §7.1: strip trailing whitespace per line, strip trailing
                    // blank lines, join with \r\n. NO trailing \r\n on last line —
                    // GnuPG hashes body without terminal line ending.
                    val splitLines = linesLF.split("\n").map { it.trimEnd() }
                    val lastNonEmpty = splitLines.indexOfLast { it.isNotEmpty() }
                    val canonical = if (lastNonEmpty == -1) "" else
                        splitLines.subList(0, lastNonEmpty + 1).joinToString("\r\n")

                    val canonBytes = canonical.toByteArray(Charsets.UTF_8)
                    AppLogger.d("sign(CLEARSIGN): canonicalLen=${canonBytes.size}B bodyLines=${linesLF.split("\n").size}", AppLogger.TAG_CRYPTO)
                    sigGen.update(canonBytes)
                    val sig = sigGen.generate()

                    // Write signature block to ByteArray via ArmoredOutputStream.
                    val sigBout = ByteArrayOutputStream()
                    armoredOut(sigBout).use { sig.encode(it) }
                    val sigArmored = sigBout.toString(Charsets.UTF_8)

                    // Body written to file: LF line endings, trailing whitespace stripped,
                    // no trailing newline on the last line (GPG standard).
                    val bodyForFile = linesLF.split("\n")
                        .joinToString("\n") { it.trimEnd() }
                        .trimEnd('\n')

                    outFile.bufferedWriter(Charsets.UTF_8).use { w ->
                        w.write("-----BEGIN PGP SIGNED MESSAGE-----\n")
                        w.write("Hash: ${hashAlgorithm.headerName}\n")
                        w.write("\n")
                        w.write(bodyForFile)
                        w.write("\n")
                        w.write(sigArmored)
                    }
                }
                SignMode.NORMAL_ARMOR -> {
                    val bout = ByteArrayOutputStream()
                    PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(bout).use { cos ->
                        val content = dataFile.readBytes()
                        sigGen.generateOnePassVersion(false).encode(cos)
                        PGPLiteralDataGenerator().open(cos, PGPLiteralData.BINARY,
                            originalName, content.size.toLong(), Date()).use { los ->
                            los.write(content)
                            sigGen.update(content)
                        }
                        sigGen.generate().encode(cos)
                    }
                    armoredOut(outFile.outputStream()).use { it.write(bout.toByteArray()) }
                }
                SignMode.NORMAL -> {
                    val bout = ByteArrayOutputStream()
                    PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(bout).use { cos ->
                        val content = dataFile.readBytes()
                        sigGen.generateOnePassVersion(false).encode(cos)
                        PGPLiteralDataGenerator().open(cos, PGPLiteralData.BINARY,
                            originalName, content.size.toLong(), Date()).use { los ->
                            los.write(content)
                            sigGen.update(content)
                        }
                        sigGen.generate().encode(cos)
                    }
                    outFile.outputStream().use { it.write(bout.toByteArray()) }
                }
            }
            AppLogger.i("sign() output=${outFile.absolutePath} size=${outFile.length()}B duration=${System.currentTimeMillis()-tSign}ms", AppLogger.TAG_CRYPTO)
            SignResult(success = true, outputPath = outFile.absolutePath)
        } catch (e: Exception) {
            AppLogger.e("sign() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            SignResult(false, errorMessage = e.message ?: "Signing failed")
        }
    }

    // ── Encrypt ──────────────────────────────────────────────────────────────

    fun encrypt(dataFile: File, recipientFingerprints: List<String>, armor: Boolean, originalName: String = dataFile.name): EncryptResult {
        val tEncrypt = System.currentTimeMillis()
        AppLogger.d("encrypt() recipients=${recipientFingerprints.size} armor=$armor inputSize=${dataFile.length()}B", AppLogger.TAG_CRYPTO)
        return try {
            val pubRings = loadPublicKeyring()
                ?: return EncryptResult(false, errorMessage = "Keyring is empty")
            val encKeys = recipientFingerprints.map { fp ->
                findEncryptionKey(pubRings, fp)
                    ?: return EncryptResult(false, errorMessage = "Encryption key not found: $fp")
            }
            val ext = if (armor) ".asc" else ".gpg"
            // Output file: original name + extension, with collision handling
            val outFile = saveToDownloads(originalName + ext)
            val encGen = PGPEncryptedDataGenerator(
                org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(SecureRandom())
            ).apply { encKeys.forEach { addMethod(org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator(it)) } }

            (if (armor) armoredOut(outFile.outputStream()) else outFile.outputStream()).use { rawOut ->
                encGen.open(rawOut, ByteArray(1 shl 16)).use { encOut ->
                    PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(encOut).use { cos ->
                        val content = dataFile.readBytes()
                        PGPLiteralDataGenerator().open(cos, PGPLiteralData.BINARY,
                            originalName, content.size.toLong(), Date()).use { los ->
                            los.write(content)
                        }
                    }
                }
            }
            AppLogger.i("encrypt() output=${outFile.absolutePath} size=${outFile.length()}B duration=${System.currentTimeMillis()-tEncrypt}ms", AppLogger.TAG_CRYPTO)
            EncryptResult(success = true, outputPath = outFile.absolutePath)
        } catch (e: Exception) {
            AppLogger.e("encrypt() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            EncryptResult(false, errorMessage = e.message ?: "Encryption failed")
        }
    }

    // ── Encrypt Symmetric ────────────────────────────────────────────────────

    fun encryptSymmetric(dataFile: File, passphrase: String, armor: Boolean, originalName: String = dataFile.name): EncryptResult {
        val tEncSym = System.currentTimeMillis()
        AppLogger.d("encryptSymmetric() file=${dataFile.name} size=${dataFile.length()}B armor=$armor", AppLogger.TAG_CRYPTO)
        return try {
            val ext = if (armor) ".asc" else ".gpg"
            val outFile = saveToDownloads(originalName + ext)
            val encGen = PGPEncryptedDataGenerator(
                org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(SecureRandom())
            ).apply {
                addMethod(org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator(
                    passphrase.toCharArray(), HashAlgorithmTags.SHA256))
            }

            (if (armor) armoredOut(outFile.outputStream()) else outFile.outputStream()).use { rawOut ->
                encGen.open(rawOut, ByteArray(1 shl 16)).use { encOut ->
                    PGPCompressedDataGenerator(PGPCompressedData.ZIP).open(encOut).use { cos ->
                        val content = dataFile.readBytes()
                        PGPLiteralDataGenerator().open(cos, PGPLiteralData.BINARY,
                            originalName, content.size.toLong(), Date()).use { los ->
                            los.write(content)
                        }
                    }
                }
            }
            AppLogger.i("encryptSymmetric() output=${outFile.absolutePath} size=${outFile.length()}B duration=${System.currentTimeMillis()-tEncSym}ms", AppLogger.TAG_CRYPTO)
            EncryptResult(success = true, outputPath = outFile.absolutePath)
        } catch (e: Exception) {
            AppLogger.e("encryptSymmetric() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            EncryptResult(false, errorMessage = e.message ?: "Symmetric encryption failed")
        }
    }

    // ── Decrypt ──────────────────────────────────────────────────────────────

    fun decrypt(dataFile: File, passphrase: String): DecryptResult {
        val tDecrypt = System.currentTimeMillis()
        AppLogger.d("decrypt() file=${dataFile.name} size=${dataFile.length()}B", AppLogger.TAG_CRYPTO)
        return try {
            val inputStream = try {
                PGPUtil.getDecoderStream(dataFile.inputStream())
            } catch (e: Exception) {
                dataFile.inputStream()
            }
            val factory = PGPObjectFactory(inputStream, org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator())
            var encData: PGPEncryptedDataList? = null
            var nextObj: Any? = factory.nextObject()
            while (nextObj != null && encData == null) {
                encData = nextObj as? PGPEncryptedDataList
                if (encData == null) nextObj = factory.nextObject()
            }
            if (encData == null)
                return DecryptResult(false, errorMessage = "File is not GPG-encrypted data")

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
                        AppLogger.d("decrypt() method=PUBKEY keyID=0x${java.lang.Long.toUnsignedString(enc.keyID, 16).uppercase()}", AppLogger.TAG_CRYPTO)
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
                    if (plainStream != null) {
                        AppLogger.d("decrypt() method=SYMMETRIC", AppLogger.TAG_CRYPTO)
                        break
                    }
                }
            }

            if (plainStream == null)
                return DecryptResult(
                    false,
                    errorMessage = if (secRings == null)
                        "No secret key in keyring and no matching symmetric passphrase"
                    else
                        "No matching secret key or incorrect passphrase"
                )

            val litData = unwrapToLiteralData(plainStream)
                ?: return DecryptResult(false, errorMessage = "Invalid GPG data structure")

            // Decrypt naming: strip last extension, no "decrypted_" prefix
            // If LiteralData carries the original filename (our encrypt output), use it directly.
            // decryptedName() is used only as fallback when fileName is empty.
            val outName = litData.fileName.ifBlank { decryptedName(dataFile.name) }
            val outFile = saveToDownloads(outName)
            outFile.outputStream().use { litData.inputStream.copyTo(it) }
            AppLogger.i("decrypt() output=${outFile.absolutePath} size=${outFile.length()}B duration=${System.currentTimeMillis()-tDecrypt}ms", AppLogger.TAG_CRYPTO)
            DecryptResult(success = true, outputPath = outFile.absolutePath)
        } catch (e: Exception) {
            AppLogger.e("decrypt() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            DecryptResult(false, errorMessage = e.message ?: "Decryption failed")
        }
    }

    private fun unwrapToLiteralData(stream: InputStream): PGPLiteralData? {
        val factory = PGPObjectFactory(stream, org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator())
        var obj = factory.nextObject()
        while (obj != null) {
            when (obj) {
                is PGPLiteralData    -> return obj
                is PGPCompressedData -> return unwrapToLiteralData(obj.dataStream)
                is PGPOnePassSignatureList,
                is PGPSignatureList  -> { /* skip */ }
            }
            obj = factory.nextObject()
        }
        return null
    }

    // ── Generate Key ─────────────────────────────────────────────────────────

    fun generateKey(params: KeyGenParams): GpgOperationResult {
        val tGenKey = System.currentTimeMillis()
        AppLogger.d("generateKey() name=${params.name} email=${params.email} keySize=${params.keySize} expiry=${params.expiry}d", AppLogger.TAG_CRYPTO)
        return try {
            val now = Date()
            val bcDigestProvider = org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
            val sha1Calc = bcDigestProvider.get(HashAlgorithmTags.SHA1)

            val rsaKeyGen = org.bouncycastle.crypto.generators.RSAKeyPairGenerator()
            rsaKeyGen.init(org.bouncycastle.crypto.params.RSAKeyGenerationParameters(
                java.math.BigInteger.valueOf(65537),
                SecureRandom(),
                params.keySize,
                12
            ))

            val primaryKpg = org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair(
                PGPPublicKey.RSA_SIGN, rsaKeyGen.generateKeyPair(), now
            )
            val encryptKpg = org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair(
                PGPPublicKey.RSA_ENCRYPT, rsaKeyGen.generateKeyPair(), now
            )

            val uid = buildString {
                append(params.name)
                if (params.comment.isNotBlank()) append(" (${params.comment})")
                append(" <${params.email}>")
            }

            val passphraseChars = params.passphrase.toCharArray()
            val encryptor = org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256)).build(passphraseChars)

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
            val genFp = bytesToHex(gen.generatePublicKeyRing().publicKey.fingerprint)
            AppLogger.i("generateKey() success uid=$uid fp=$genFp duration=${System.currentTimeMillis()-tGenKey}ms", AppLogger.TAG_CRYPTO)
            GpgOperationResult.Success("Key generated: $uid")
        } catch (e: Exception) {
            AppLogger.e("generateKey() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            AppLogger.e("generateKey() cause: ${e.cause?.message}", AppLogger.TAG_CRYPTO)
            AppLogger.e("generateKey() exceptionClass: ${e.javaClass.name}", AppLogger.TAG_CRYPTO)
            AppLogger.e("generateKey() stack: ${e.stackTrace.take(8).joinToString(" ↳ ") { "${it.className.substringAfterLast('.')}.${it.methodName}:${it.lineNumber}" }}", AppLogger.TAG_CRYPTO)
            GpgOperationResult.Failure(e.message ?: "Key generation failed")
        }
    }

    // ── List Keys ────────────────────────────────────────────────────────────

    fun listKeys(): List<GpgKey> {
        AppLogger.d("listKeys() called", AppLogger.TAG_CRYPTO)
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
        AppLogger.d("importKey() path=${keyFile.absolutePath} size=${keyFile.length()}B", AppLogger.TAG_CRYPTO)
        return try {
            val bytes = keyFile.readBytes()

            // Try armored first
            var pub = tryImportPublicKeys(bytes.inputStream())
            var sec = tryImportSecretKeys(bytes.inputStream())

            // Fallback: if no armor block found, attempt binary parsing
            if (pub + sec == 0) {
                val result = tryImportBinary(bytes)
                pub = result.first
                sec = result.second
            }

            val alreadyExists = pub + sec == 0
            if (alreadyExists) {
                // Check whether the file actually contains a key already in the keyring
                val hasAnyKey = tryImportPublicKeys(bytes.inputStream()) >= 0 ||
                                tryImportSecretKeys(bytes.inputStream()) >= 0
                GpgOperationResult.Failure("Key already in keyring — no new key was imported")
            } else {
                AppLogger.i("importKey() imported pub=$pub sec=$sec", AppLogger.TAG_CRYPTO)
                GpgOperationResult.Success("Imported $pub public, $sec secret key(s)")
            }
        } catch (e: Exception) {
            AppLogger.e("importKey() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            GpgOperationResult.Failure(e.message ?: "Import failed")
        }
    }

    private fun tryImportBinary(bytes: ByteArray): Pair<Int, Int> {
        return try {
            val calc = org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()
            val existingPub = loadPublicKeyring()
                ?.associateBy { bytesToHex(it.publicKey.fingerprint) }
                ?.toMutableMap() ?: mutableMapOf()
            val existingSec = loadSecretKeyring()
                ?.associateBy { bytesToHex(it.secretKey.publicKey.fingerprint) }
                ?.toMutableMap() ?: mutableMapOf()

            val pubCount = importPublicRingsFromStream(
                PGPUtil.getDecoderStream(bytes.inputStream()), existingPub
            )
            val secCount = importSecretRingsFromStream(
                PGPUtil.getDecoderStream(bytes.inputStream()), existingSec
            )

            if (existingPub.isNotEmpty()) savePublicKeyring(existingPub.values.toList())
            if (existingSec.isNotEmpty()) saveSecretKeyring(existingSec.values.toList())
            AppLogger.d("tryImportBinary() pub=$pubCount sec=$secCount", AppLogger.TAG_CRYPTO)
            Pair(pubCount, secCount)
        } catch (e: Exception) {
            AppLogger.w("tryImportBinary() warn: ${e.message}", AppLogger.TAG_CRYPTO)
            Pair(0, 0)
        }
    }

    fun exportKeyToKeyserver(fingerprint: String, keyserver: String): GpgOperationResult {
        AppLogger.d("exportKeyToKeyserver() fp=$fingerprint keyserver=$keyserver", AppLogger.TAG_NET)
        return try {
            val exportResult = exportKey(fingerprint, armor = true, secret = false)
            val armoredKey = when (exportResult) {
                is GpgOperationResult.Success -> exportResult.message
                is GpgOperationResult.Failure -> return exportResult
            }

            val base = keyserver.trimEnd('/').replace("hkps://", "https://").replace("hkp://", "http://")
            val url  = "$base/pks/add"
            AppLogger.d("exportKeyToKeyserver() uploading to $url", AppLogger.TAG_NET)

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
            AppLogger.d("exportKeyToKeyserver() HTTP response=$responseCode", AppLogger.TAG_NET)

            if (responseCode in 200..299) {
                GpgOperationResult.Success("Key successfully uploaded to $keyserver")
            } else {
                GpgOperationResult.Failure("Keyserver error HTTP $responseCode")
            }
        } catch (e: Exception) {
            AppLogger.e("exportKeyToKeyserver() failed: ${e.message}", AppLogger.TAG_NET)
            GpgOperationResult.Failure(e.message ?: "Keyserver upload failed")
        }
    }

    fun importKeyFromKeyserver(keyId: String, keyserver: String): GpgOperationResult {
        AppLogger.d("importKeyFromKeyserver() keyId=$keyId keyserver=$keyserver", AppLogger.TAG_NET)
        return try {
            val base   = keyserver.trimEnd('/').replace("hkps://", "https://").replace("hkp://", "http://")
            val search = when {
                keyId.contains("@")        -> keyId          // email
                keyId.startsWith("0x") ||
                keyId.startsWith("0X")     -> keyId          // sudah hex dengan prefix
                keyId.all { it.isLetterOrDigit() } &&
                keyId.length >= 8          -> "0x$keyId"     // hex tanpa prefix
                else                       -> keyId          // let the keyserver validate
            }
            val url    = "$base/pks/lookup?op=get&search=$search&options=mr"
            AppLogger.d("importKeyFromKeyserver() fetching $url", AppLogger.TAG_NET)
            val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 10000
            conn.readTimeout    = 15000
            conn.setRequestProperty("User-Agent", "GPGVerifier/1.0")
            val responseCode = conn.responseCode
            if (responseCode != 200)
                return GpgOperationResult.Failure("Keyserver error HTTP $responseCode — key not found")
            val count = tryImportPublicKeys(conn.inputStream)
            val msg = if (count == 0) "Key already in keyring (no new key imported)" else "$count key(s) imported from $keyserver"
            GpgOperationResult.Success(msg)
        } catch (e: Exception) {
            AppLogger.e("importKeyFromKeyserver() failed: ${e.message}", AppLogger.TAG_NET)
            GpgOperationResult.Failure(e.message ?: "Keyserver import failed")
        }
    }

    // ── Trust ────────────────────────────────────────────────────────────────

    fun trustKey(fingerprint: String, trustLevel: Int): GpgOperationResult {
        AppLogger.d("trustKey() fp=$fingerprint level=$trustLevel", AppLogger.TAG_CRYPTO)
        return try {
            val lines = if (trustFile.exists())
                trustFile.readLines().filter { !it.startsWith(fingerprint.uppercase()) }.toMutableList()
            else mutableListOf()
            lines.add("${fingerprint.uppercase()}:$trustLevel")
            trustFile.writeText(lines.joinToString("\n"))
            GpgOperationResult.Success("Trust level set to $trustLevel")
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Failed to set trust")
        }
    }

    // ── Delete ───────────────────────────────────────────────────────────────

    fun deleteKey(fingerprint: String): GpgOperationResult {
        AppLogger.d("deleteKey() fp=$fingerprint", AppLogger.TAG_CRYPTO)
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
        AppLogger.d("exportKey() fp=$fingerprint armor=$armor secret=$secret", AppLogger.TAG_CRYPTO)
        return try {
            val fp   = fingerprint.uppercase()
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

    // ── Private Helpers ──────────────────────────────────────────────────────

    private fun loadPublicKeyring(): List<PGPPublicKeyRing>? {
        if (!publicKeyringFile.exists()) return null
        return try {
            val rings = PGPPublicKeyRingCollection(
                FileInputStream(publicKeyringFile), org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()
            ).keyRings.asSequence().toList()
            AppLogger.d("loadPublicKeyring() rings=${rings.size} file=${publicKeyringFile.length()}B", AppLogger.TAG_IO)
            rings
        } catch (e: Exception) { AppLogger.e("loadPublicKeyring() failed: ${e.message}", AppLogger.TAG_IO); null }
    }

    private fun loadSecretKeyring(): List<PGPSecretKeyRing>? {
        if (!secretKeyringFile.exists()) return null
        return try {
            val rings = PGPSecretKeyRingCollection(
                FileInputStream(secretKeyringFile), org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()
            ).keyRings.asSequence().toList()
            AppLogger.d("loadSecretKeyring() rings=${rings.size} file=${secretKeyringFile.length()}B", AppLogger.TAG_IO)
            rings
        } catch (e: Exception) { AppLogger.e("loadSecretKeyring() failed: ${e.message}", AppLogger.TAG_IO); null }
    }

    private fun savePublicKeyring(rings: List<PGPPublicKeyRing>) {
        PGPPublicKeyRingCollection(rings).encode(FileOutputStream(publicKeyringFile))
    }

    private fun saveSecretKeyring(rings: List<PGPSecretKeyRing>) {
        PGPSecretKeyRingCollection(rings).encode(FileOutputStream(secretKeyringFile))
    }

    private fun extractArmorBlocks(text: String): List<String> {
        val blocks = mutableListOf<String>()
        val sb = StringBuilder()
        var inBlock = false
        for (line in text.lines()) {
            if (line.startsWith("-----BEGIN PGP")) { inBlock = true; sb.clear() }
            if (inBlock) {
                sb.append(line).append("\n")
                if (line.startsWith("-----END PGP")) { blocks.add(sb.toString()); inBlock = false }
            }
        }
        return blocks
    }

    private fun tryImportPublicKeys(input: InputStream): Int {
        return try {
            val text = input.readBytes().toString(Charsets.UTF_8)
            val blocks = extractArmorBlocks(text)
                .filter { it.contains("PUBLIC KEY") }
            val existing = loadPublicKeyring()
                ?.associateBy { bytesToHex(it.publicKey.fingerprint) }
                ?.toMutableMap() ?: mutableMapOf()
            var count = 0
            for (block in blocks) {
                try {
                    count += importPublicRingsFromStream(
                        PGPUtil.getDecoderStream(block.byteInputStream(Charsets.UTF_8)),
                        existing
                    )
                } catch (e: Exception) {
                    AppLogger.w("tryImportPublicKeys block warn: ${e.message}", AppLogger.TAG_CRYPTO)
                }
            }
            if (existing.isNotEmpty()) savePublicKeyring(existing.values.toList())
            count
        } catch (e: Exception) {
            AppLogger.e("tryImportPublicKeys() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            0
        }
    }

    private fun importPublicRingsFromStream(
        stream: InputStream,
        existing: MutableMap<String, PGPPublicKeyRing>
    ): Int {
        var count = 0
        val calc = org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()
        val bytes = stream.readBytes()

        // Attempt 1: PGPPublicKeyRingCollection constructor
        try {
            val col = PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(bytes.inputStream()), calc
            )
            for (ring in col.keyRings) {
                val fp = bytesToHex(ring.publicKey.fingerprint)
                if (!existing.containsKey(fp)) count++
                existing[fp] = ring
            }
            if (count > 0) {
                AppLogger.d("importPublicRings via Collection — imported=$count rings", AppLogger.TAG_CRYPTO)
                return count
            }
        } catch (e: Exception) {
            AppLogger.w("importPublicRings Collection warn: ${e.message}", AppLogger.TAG_CRYPTO)
        }

        // Attempt 2: PGPObjectFactory + re-parse via getEncoded()
        // Avoid classloader mismatch — avoid 'is' type check
        try {
            val factory = PGPObjectFactory(PGPUtil.getDecoderStream(bytes.inputStream()), calc)
            var obj = factory.nextObject()
            while (obj != null) {
                try {
                    val encoded = obj.javaClass.getMethod("getEncoded").invoke(obj) as? ByteArray
                    if (encoded != null) {
                        val ring = PGPPublicKeyRing(encoded.inputStream(), calc)
                        val fp = bytesToHex(ring.publicKey.fingerprint)
                        if (!existing.containsKey(fp)) count++
                        existing[fp] = ring
                        AppLogger.d("importPublicRings re-parse OK fp=...${fp.takeLast(8)}", AppLogger.TAG_CRYPTO)
                    }
                } catch (e: Exception) { /* not a PGPPublicKeyRing — skip */ }
                obj = try { factory.nextObject() } catch (e: Exception) { null }
            }
        } catch (e: Exception) {
            AppLogger.w("importPublicRings factory warn: ${e.message}", AppLogger.TAG_CRYPTO)
        }

        AppLogger.d("importPublicRingsFromStream total=$count", AppLogger.TAG_CRYPTO)
        return count
    }

    private fun tryImportSecretKeys(input: InputStream): Int {
        return try {
            val text = input.readBytes().toString(Charsets.UTF_8)
            val blocks = extractArmorBlocks(text)
                .filter { it.contains("PRIVATE KEY") || it.contains("SECRET KEY") }
            val existing = loadSecretKeyring()
                ?.associateBy { bytesToHex(it.secretKey.publicKey.fingerprint) }
                ?.toMutableMap() ?: mutableMapOf()
            var count = 0
            for (block in blocks) {
                try {
                    count += importSecretRingsFromStream(
                        PGPUtil.getDecoderStream(block.byteInputStream(Charsets.UTF_8)),
                        existing
                    )
                } catch (e: Exception) {
                    AppLogger.w("tryImportSecretKeys block warn: ${e.message}", AppLogger.TAG_CRYPTO)
                }
            }
            if (existing.isNotEmpty()) {
                saveSecretKeyring(existing.values.toList())
                if (count > 0) extractPublicKeysFromSecretRings(existing.values.toList())
            }
            count
        } catch (e: Exception) {
            AppLogger.e("tryImportSecretKeys() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            0
        }
    }

    private fun importSecretRingsFromStream(
        stream: InputStream,
        existing: MutableMap<String, PGPSecretKeyRing>
    ): Int {
        var count = 0
        val calc = org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()
        // Read bytes once; reuse for multiple parse attempts
        val bytes = stream.readBytes()

        // Attempt 1: PGPSecretKeyRingCollection constructor — most reliable for multi-ring
        try {
            val col = PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(bytes.inputStream()), calc
            )
            for (ring in col.keyRings) {
                val fp = bytesToHex(ring.secretKey.publicKey.fingerprint)
                if (!existing.containsKey(fp)) count++
                existing[fp] = ring
            }
            if (count > 0) {
                AppLogger.d("importSecretRings via Collection — imported=$count rings", AppLogger.TAG_CRYPTO)
                extractPublicKeysFromSecretRings(existing.values.toList())
                return count
            }
        } catch (e: Exception) {
            AppLogger.w("importSecretRings Collection warn: ${e.message}", AppLogger.TAG_CRYPTO)
        }

        // Attempt 2: PGPObjectFactory + re-parse via getEncoded()
        // Avoid classloader mismatch — avoid 'is' type check
        try {
            val factory = PGPObjectFactory(PGPUtil.getDecoderStream(bytes.inputStream()), calc)
            var obj = factory.nextObject()
            while (obj != null) {
                try {
                    val encoded = obj.javaClass.getMethod("getEncoded").invoke(obj) as? ByteArray
                    if (encoded != null) {
                        val ring = PGPSecretKeyRing(encoded.inputStream(), calc)
                        val fp = bytesToHex(ring.secretKey.publicKey.fingerprint)
                        if (!existing.containsKey(fp)) count++
                        existing[fp] = ring
                        AppLogger.d("importSecretRings re-parse OK fp=...${fp.takeLast(8)}", AppLogger.TAG_CRYPTO)
                    }
                } catch (e: Exception) { /* not a PGPSecretKeyRing — skip */ }
                obj = try { factory.nextObject() } catch (e: Exception) { null }
            }
        } catch (e: Exception) {
            AppLogger.w("importSecretRings factory warn: ${e.message}", AppLogger.TAG_CRYPTO)
        }

        if (count > 0) extractPublicKeysFromSecretRings(existing.values.toList())
        AppLogger.d("importSecretRingsFromStream total=$count", AppLogger.TAG_CRYPTO)
        return count
    }

    // Extract public key from each secret key ring and add to pubring
    private fun extractPublicKeysFromSecretRings(secretRings: List<PGPSecretKeyRing>) {
        try {
            val calc = org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()
            val existingPub = loadPublicKeyring()
                ?.associateBy { bytesToHex(it.publicKey.fingerprint) }
                ?.toMutableMap() ?: mutableMapOf()
            var added = 0
            for (secRing in secretRings) {
                val fp = bytesToHex(secRing.secretKey.publicKey.fingerprint)
                if (!existingPub.containsKey(fp)) {
                    // Collect all public keys from secret ring
                    val pubKeys = mutableListOf<org.bouncycastle.openpgp.PGPPublicKey>()
                    for (secKey in secRing.secretKeys) {
                        pubKeys.add(secKey.publicKey)
                    }
                    val pubRing = PGPPublicKeyRing(pubKeys)
                    existingPub[fp] = pubRing
                    added++
                }
            }
            if (added > 0) {
                savePublicKeyring(existingPub.values.toList())
                AppLogger.d("extractPublicKeysFromSecretRings — added $added pub ring(s) to pubring", AppLogger.TAG_CRYPTO)
            }
        } catch (e: Exception) {
            AppLogger.w("extractPublicKeysFromSecretRings warn: ${e.message}", AppLogger.TAG_CRYPTO)
        }
    }

    private fun loadSignatures(input: InputStream): List<PGPSignature> {
        val sigs = mutableListOf<PGPSignature>()
        return try {
            val factory = PGPObjectFactory(PGPUtil.getDecoderStream(input), org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator())
            var obj = factory.nextObject()
            while (obj != null) {
                when (obj) {
                    is PGPSignatureList -> obj.forEach { sigs.add(it) }
                    is PGPSignature     -> sigs.add(obj)
                }
                obj = factory.nextObject()
            }
            sigs
        } catch (e: Exception) { AppLogger.e("loadSignatures() failed: ${e.message}", AppLogger.TAG_CRYPTO); sigs }
    }

    private fun findPublicKey(rings: List<PGPPublicKeyRing>, keyId: Long): PGPPublicKey? {
        for (ring in rings) for (key in ring.publicKeys) if (key.keyID == keyId) return key
        return null
    }

    // ── Backup ───────────────────────────────────────────────────────────────

    fun backupPublicKey(fingerprint: String): GpgOperationResult {
        return try {
            val fp = fingerprint.uppercase()
            val uid = loadPublicKeyring()
                ?.firstOrNull { bytesToHex(it.publicKey.fingerprint) == fp }
                ?.publicKey?.userIDs?.asSequence()?.firstOrNull() as? String
                ?: fp.takeLast(8)
            val safeName = uid.replace(Regex("[^a-zA-Z0-9_\\-@.]"), "_")
            val pubRing = loadPublicKeyring()?.firstOrNull { bytesToHex(it.publicKey.fingerprint) == fp }
                ?: return GpgOperationResult.Failure("Public key not found")
            val out = java.io.ByteArrayOutputStream()
            val armor = armoredOut(out)
            pubRing.encode(armor)
            armor.close()
            val file = saveToDownloads("${safeName}_pub.asc")
            file.writeBytes(out.toByteArray())
            GpgOperationResult.Success("Public key saved: ${file.name}")
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Export failed")
        }
    }

    fun backupSecretKey(fingerprint: String): GpgOperationResult {
        return try {
            val fp = fingerprint.uppercase()
            val uid = loadPublicKeyring()
                ?.firstOrNull { bytesToHex(it.publicKey.fingerprint) == fp }
                ?.publicKey?.userIDs?.asSequence()?.firstOrNull() as? String
                ?: fp.takeLast(8)
            val safeName = uid.replace(Regex("[^a-zA-Z0-9_\\-@.]"), "_")
            val secRing = loadSecretKeyring()?.firstOrNull { bytesToHex(it.secretKey.publicKey.fingerprint) == fp }
                ?: return GpgOperationResult.Failure("No secret key found for this key")
            val pubRing = loadPublicKeyring()?.firstOrNull { bytesToHex(it.publicKey.fingerprint) == fp }
            val out = java.io.ByteArrayOutputStream()
            // Include pubkey first so restore shows 1 pub + 1 priv
            if (pubRing != null) {
                val pubArmor = armoredOut(out)
                pubRing.encode(pubArmor)
                pubArmor.close()
            }
            val secArmor = armoredOut(out)
            secRing.encode(secArmor)
            secArmor.close()
            val file = saveToDownloads("${safeName}_priv.asc")
            file.writeBytes(out.toByteArray())
            GpgOperationResult.Success("Secret key saved: ${file.name}")
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Export failed")
        }
    }

    fun backupAllPublicKeys(): GpgOperationResult {
        return try {
            val rings = loadPublicKeyring() ?: return GpgOperationResult.Failure("Keyring is empty")
            val out = java.io.ByteArrayOutputStream()
            val armor = armoredOut(out)
            rings.forEach { it.encode(armor) }
            armor.close()
            val file = saveToDownloads("all-pub.asc")
            file.writeBytes(out.toByteArray())
            GpgOperationResult.Success("${rings.size} public key(s) saved to ${file.name}")
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Backup failed")
        }
    }

    fun backupAllSecretKeys(): GpgOperationResult {
        return try {
            val rings = loadSecretKeyring() ?: return GpgOperationResult.Failure("Secret keyring is empty")
            val out = java.io.ByteArrayOutputStream()
            val armor = armoredOut(out)
            rings.forEach { it.encode(armor) }
            armor.close()
            val file = saveToDownloads("all-priv.asc")
            file.writeBytes(out.toByteArray())
            GpgOperationResult.Success("${rings.size} secret key(s) saved to ${file.name}")
        } catch (e: Exception) {
            GpgOperationResult.Failure(e.message ?: "Backup failed")
        }
    }

    // ── Verify Embedded Sign ─────────────────────────────────────────────────

    fun verifyEmbedded(signedFile: File): VerificationResult {
        AppLogger.d("verifyEmbedded() file=${signedFile.name} size=${signedFile.length()}B", AppLogger.TAG_CRYPTO)
        return try {
            val pubRings = loadPublicKeyring()
                ?: return VerificationResult(false, "", "", "", "", "Keyring is empty")
            val calc = org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()

            // Decode armor if present; fall back to binary
            val rawBytes = signedFile.readBytes()
            val decodedBytes = try {
                PGPUtil.getDecoderStream(rawBytes.inputStream()).readBytes()
            } catch (e: Exception) { rawBytes }

            // Decompress if needed — all 3 passes must operate on the same (decompressed) level
            val innerBytes: ByteArray
            val topObj = PGPObjectFactory(decodedBytes.inputStream(), calc).nextObject()
            innerBytes = if (topObj is PGPCompressedData) {
                topObj.dataStream.readBytes()
            } else {
                decodedBytes
            }

            fun nextFrom(b: ByteArray) = PGPObjectFactory(b.inputStream(), calc)

            // Pass 1: locate OnePassSignatureList and initialise the verifier
            val onePassList = nextFrom(innerBytes).nextObject() as? PGPOnePassSignatureList
                ?: return VerificationResult(false, "", "", "", "", "File is not an embedded signed document")
            val ops = onePassList[0]
            val pubKey = findPublicKey(pubRings, ops.keyID)
                ?: return VerificationResult(false, "", "", "", "", "Public key not found in keyring")
            val algTag = ops.hashAlgorithm
            AppLogger.d("verifyEmbedded: hashAlg=${hashAlgorithmName(algTag)} keyID=0x${ops.keyID.let { java.lang.Long.toUnsignedString(it, 16).uppercase() }} keyAlg=${pubKey.algorithm}", AppLogger.TAG_CRYPTO)
            ops.init(resolveVerifierProvider(algTag, pubKey.algorithm), pubKey)

            // Pass 2: read literal data and feed it to the verifier
            val factory2 = nextFrom(innerBytes)
            factory2.nextObject() // skip OnePassSignatureList
            val litData = factory2.nextObject() as? PGPLiteralData
                ?: return VerificationResult(false, "", "", "", "", "Literal data not found")
            var embeddedDataSize = 0L
            val buf = ByteArray(8192); var n: Int
            while (litData.inputStream.read(buf).also { n = it } >= 0) { ops.update(buf, 0, n); embeddedDataSize += n }
            AppLogger.d("verifyEmbedded: literalDataSize=${embeddedDataSize}B filename=${litData.fileName}", AppLogger.TAG_CRYPTO)

            // Pass 3: read signature list and verify
            val factory3 = nextFrom(innerBytes)
            factory3.nextObject() // skip OnePassSignatureList
            factory3.nextObject() // skip LiteralData
            val sigList = factory3.nextObject() as? PGPSignatureList
                ?: return VerificationResult(false, "", "", "", "", "Signature list not found")
            val sig = sigList[0]
            val valid = ops.verify(sig)
            val fp  = bytesToHex(pubKey.fingerprint)
            val uid = (pubKey.userIDs.asSequence().firstOrNull() ?: "Unknown") as String
            val ts  = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(sig.creationTime)
            VerificationResult(
                isValid       = valid,
                signedBy      = uid,
                fingerprint   = fp,
                timestamp     = ts,
                trustLevel    = getTrustLevel(fp),
                hashAlgorithm = hashAlgorithmName(sig.hashAlgorithm),
                rawOutput     = if (valid) "Good signature from \"$uid\"" else "BAD signature",
                errorMessage  = if (!valid) "Invalid signature" else null
            )
        } catch (e: Exception) {
            AppLogger.e("verifyEmbedded() failed: ${e.message}", AppLogger.TAG_CRYPTO)
            VerificationResult(false, "", "", "", "", e.message ?: "Embedded verification failed")
        }
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
