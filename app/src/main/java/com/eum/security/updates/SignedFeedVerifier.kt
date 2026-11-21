package com.eum.security.updates

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.security.MessageDigest

/**
 * Verifies a detached Ed25519 signature over the exact downloaded feed bytes.
 * Caller must pin the public key in the application and enforce monotonic feed versions.
 * Android 10 crypto provider support must be checked before production use.
 */
object SignedFeedVerifier {
    fun verify(data: ByteArray, signature: ByteArray, publicKeyX509: ByteArray): Boolean {
        return try {
            val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(publicKeyX509))
            val verifier = Signature.getInstance("Ed25519")
            verifier.initVerify(key)
            verifier.update(data)
            verifier.verify(signature)
        } catch (_: Exception) {
            false
        }
    }

    fun sha256(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
}
