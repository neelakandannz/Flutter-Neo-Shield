package com.neelakandan.flutter_neo_shield.rasp

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Detects APK repackaging by verifying the signing certificate hash
 * and checking classes.dex integrity.
 *
 * When an attacker decompiles an APK with apktool/jadx, modifies code,
 * and re-signs with their own key, the signing certificate changes.
 * This detector catches that.
 */
class SignatureDetector {

    /**
     * Checks APK signature integrity.
     *
     * Returns a map with:
     *   "signatureTampered" -> Boolean (true if signature mismatch or anomaly)
     *   "dexTampered"       -> Boolean (true if classes.dex hash mismatch)
     *   "detected"          -> Boolean (true if ANY tampering found)
     *
     * @param context Android context
     * @param expectedSignatureHash Optional SHA-256 of the expected signing certificate.
     *        If null, performs heuristic checks only (multiple signers, debuggable cert).
     * @param expectedDexHashes Optional list of SHA-256 hashes for classes.dex, classes2.dex, etc.
     *        If null, DEX integrity check is skipped.
     */
    fun check(
        context: Context,
        expectedSignatureHash: String? = null,
        expectedDexHashes: List<String>? = null
    ): Map<String, Any> {
        val result = mutableMapOf<String, Any>(
            "signatureTampered" to false,
            "dexTampered" to false,
            "detected" to false
        )

        try {
            val signatureTampered = checkSignature(context, expectedSignatureHash)
            result["signatureTampered"] = signatureTampered

            val dexTampered = if (expectedDexHashes != null) {
                checkDexIntegrity(context, expectedDexHashes)
            } else {
                false
            }
            result["dexTampered"] = dexTampered

            result["detected"] = signatureTampered || dexTampered
        } catch (e: Exception) {
            // Fail closed: if we can't verify, assume tampered
            result["signatureTampered"] = true
            result["detected"] = true
        }

        return result
    }

    /**
     * Simple boolean check: returns true if any signature anomaly is found.
     */
    fun checkSimple(context: Context): Boolean {
        return try {
            checkSignature(context, null)
        } catch (e: Exception) {
            true // fail closed
        }
    }

    @Suppress("DEPRECATION")
    private fun checkSignature(context: Context, expectedHash: String?): Boolean {
        val pm = context.packageManager

        // Get signing info
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            // API 28+: Use SigningInfo
            val packageInfo = pm.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
            )
            val signingInfo = packageInfo.signingInfo ?: return true // fail closed

            val signers = if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }

            if (signers == null || signers.isEmpty()) {
                return true // No signers = tampered
            }

            // Multiple signers is suspicious for most apps
            if (signingInfo.hasMultipleSigners() && signers.size > 1) {
                return true
            }

            // If expected hash provided, verify it
            if (expectedHash != null) {
                val currentHash = sha256Hex(signers[0].toByteArray())
                if (!currentHash.equals(expectedHash, ignoreCase = true)) {
                    return true // Certificate mismatch!
                }
            }

            // Heuristic: check if signed with a debug/test certificate
            val certBytes = signers[0].toByteArray()
            if (isDebugCertificate(certBytes)) {
                return true
            }

        } else {
            // API < 28: Use deprecated GET_SIGNATURES
            val packageInfo = pm.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )
            val signatures = packageInfo.signatures

            if (signatures == null || signatures.isEmpty()) {
                return true
            }

            if (signatures.size > 1) {
                return true // Multiple signers
            }

            if (expectedHash != null) {
                val currentHash = sha256Hex(signatures[0].toByteArray())
                if (!currentHash.equals(expectedHash, ignoreCase = true)) {
                    return true
                }
            }

            if (isDebugCertificate(signatures[0].toByteArray())) {
                return true
            }
        }

        return false
    }

    private fun checkDexIntegrity(context: Context, expectedHashes: List<String>): Boolean {
        try {
            val apkPath = context.applicationInfo.sourceDir
            ZipFile(apkPath).use { zipFile ->
                // Check each DEX file
                for (i in expectedHashes.indices) {
                    val dexName = if (i == 0) "classes.dex" else "classes${i + 1}.dex"
                    val entry = zipFile.getEntry(dexName) ?: return true // Missing DEX

                    zipFile.getInputStream(entry).use { inputStream ->
                        val md = MessageDigest.getInstance("SHA-256")
                        val buffer = ByteArray(8192)
                        var bytesRead: Int
                        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                            md.update(buffer, 0, bytesRead)
                        }

                        val currentHash = md.digest().joinToString("") { "%02x".format(it) }
                        if (!currentHash.equals(expectedHashes[i], ignoreCase = true)) {
                            return true // DEX hash mismatch
                        }
                    }
                }
            }
        } catch (e: Exception) {
            return true // fail closed
        }
        return false
    }

    /**
     * Heuristic: debug certificates typically use CN=Android Debug.
     */
    private fun isDebugCertificate(certBytes: ByteArray): Boolean {
        try {
            val certFactory = java.security.cert.CertificateFactory.getInstance("X.509")
            val cert = certFactory.generateCertificate(certBytes.inputStream()) as java.security.cert.X509Certificate
            val issuer = cert.issuerDN.name
            // Common debug cert patterns
            if (issuer.contains("CN=Android Debug", ignoreCase = true) ||
                issuer.contains("C=US,O=Android,CN=Android Debug", ignoreCase = true)) {
                return true
            }
        } catch (e: Exception) {
            // If we can't parse the cert, don't flag this specific check
        }
        return false
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    /**
     * Returns the SHA-256 hash of the current APK signing certificate.
     * Useful for the developer to obtain the expected hash during development.
     */
    @Suppress("DEPRECATION")
    fun getCurrentSignatureHash(context: Context): String? {
        return try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signers = if (packageInfo.signingInfo.hasMultipleSigners()) {
                    packageInfo.signingInfo.apkContentsSigners
                } else {
                    packageInfo.signingInfo.signingCertificateHistory
                }
                if (signers != null && signers.isNotEmpty()) {
                    sha256Hex(signers[0].toByteArray())
                } else null
            } else {
                val packageInfo = pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
                if (packageInfo.signatures != null && packageInfo.signatures.isNotEmpty()) {
                    sha256Hex(packageInfo.signatures[0].toByteArray())
                } else null
            }
        } catch (e: Exception) {
            null
        }
    }
}
