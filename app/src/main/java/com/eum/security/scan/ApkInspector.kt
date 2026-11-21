package com.eum.security.scan

import android.content.Context
import android.net.Uri
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

data class ApkReport(
    val sha256: String,
    val packageName: String?,
    val permissions: List<String>,
    val matchedThreat: Boolean,
    val notes: String,
    val versionName: String? = null,
    val signingCertificateSha256: List<String> = emptyList()
)

class ApkInspector(private val context: Context) {
    fun inspect(uri: Uri, knownMaliciousHashes: Set<String> = emptySet()): ApkReport {
        val digest = MessageDigest.getInstance("SHA-256")
        val tmp = File.createTempFile("eum_scan_", ".apk", context.cacheDir)
        try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                tmp.outputStream().buffered().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        require(total <= 512L * 1024 * 1024) { "File exceeds 512 MiB inspection limit" }
                        digest.update(buffer, 0, count)
                        output.write(buffer, 0, count)
                    }
                }
            } ?: error("Cannot open selected file")
            val hash = digest.digest().joinToString("") { "%02x".format(it) }
            val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
            @Suppress("DEPRECATION")
            val info = if (Build.VERSION.SDK_INT >= 33) {
                context.packageManager.getPackageArchiveInfo(tmp.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else context.packageManager.getPackageArchiveInfo(tmp.absolutePath, flags)
            val certs = info?.signingInfo?.apkContentsSigners?.map { cert ->
                MessageDigest.getInstance("SHA-256").digest(cert.toByteArray()).joinToString("") { "%02x".format(it) }
            } ?: emptyList()
            return ApkReport(hash, info?.packageName, info?.requestedPermissions?.toList() ?: emptyList(),
                hash.lowercase() in knownMaliciousHashes.map { it.lowercase() }.toSet(),
                if (info == null) "Archive metadata unavailable; SHA-256 only. No production threat feed."
                else "PackageManager metadata only; DEX and YARA not analyzed. No production threat feed.",
                info?.versionName, certs)
        } finally { tmp.delete() }
    }
}
