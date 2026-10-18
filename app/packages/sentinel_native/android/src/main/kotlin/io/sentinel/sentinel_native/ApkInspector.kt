package io.sentinel.sentinel_native

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

/**
 * Parses an APK the user explicitly selected. The archive is never installed or executed:
 * PackageManager only reads its manifest and signing block.
 */
class ApkInspector(private val context: Context) {

    fun inspect(file: File): Map<String, Any?> {
        require(file.isFile) { "File not found" }
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or PackageManager.GET_ACTIVITIES or PackageManager.GET_SIGNING_CERTIFICATES
        val info: PackageInfo? = if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageArchiveInfo(file.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION") pm.getPackageArchiveInfo(file.absolutePath, flags)
        }

        val base = mapOf(
            "sha256" to sha256(file),
            "sizeBytes" to file.length(),
        )
        if (info == null) return base + mapOf("parsed" to false)

        info.applicationInfo?.let {
            it.sourceDir = file.absolutePath
            it.publicSourceDir = file.absolutePath
        }
        val label = info.applicationInfo?.let { runCatching { pm.getApplicationLabel(it).toString() }.getOrNull() }
        val signers = info.signingInfo?.let { si ->
            (if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory)
                .orEmpty().map { DeviceInspector.sha256Hex(it.toByteArray()) }
        } ?: emptyList()

        val installedSame = runCatching { pm.getPackageInfo(info.packageName, 0); true }.getOrDefault(false)

        return base + mapOf(
            "parsed" to true,
            "package" to info.packageName,
            "label" to label,
            "versionName" to info.versionName,
            "minSdk" to (if (Build.VERSION.SDK_INT >= 24) info.applicationInfo?.minSdkVersion else null),
            "targetSdk" to info.applicationInfo?.targetSdkVersion,
            "debuggable" to ((info.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0),
            "requestedPermissions" to (info.requestedPermissions?.toList() ?: emptyList<String>()),
            "boundServicePermissions" to info.services.orEmpty().mapNotNull { it.permission }.distinct(),
            "receiverPermissions" to info.receivers.orEmpty().mapNotNull { it.permission }.distinct(),
            "activityCount" to (info.activities?.size ?: 0),
            "serviceCount" to (info.services?.size ?: 0),
            "signingSha256" to signers,
            "alreadyInstalled" to installedSame,
        )
    }

    private fun sha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(1 shl 16)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
