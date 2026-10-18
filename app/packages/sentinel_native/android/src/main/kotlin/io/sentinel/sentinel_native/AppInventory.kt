package io.sentinel.sentinel_native

import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build

/**
 * Enumerates installed packages through PackageManager (requires QUERY_ALL_PACKAGES,
 * which Google Play permits for device-security apps). Only metadata is read: no app data,
 * no files belonging to other apps.
 */
class AppInventory(private val context: Context) {

    private val pm: PackageManager = context.packageManager
    private val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager

    fun listApps(): Map<String, Any?> {
        val launchable = pm.queryIntentActivities(
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0
        ).map { it.activityInfo.packageName }.toSet()

        val packages = installedPackages(PackageManager.GET_PERMISSIONS.toLong())
        val apps = packages.filter { it.packageName != context.packageName }.map { describe(it, launchable) }
        return mapOf(
            "apps" to apps,
            "visibleCount" to packages.size,
            // If package visibility is restricted, very few packages are returned.
            "limitedVisibility" to (packages.size < 15),
        )
    }

    private fun installedPackages(flags: Long): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags))
        else @Suppress("DEPRECATION") pm.getInstalledPackages(flags.toInt())

    private fun detailed(pkg: String): PackageInfo? {
        val flags = (PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_SIGNING_CERTIFICATES).toLong()
        return try {
            if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags))
            else @Suppress("DEPRECATION") pm.getPackageInfo(pkg, flags.toInt())
        } catch (e: Exception) {
            null
        }
    }

    private fun describe(info: PackageInfo, launchable: Set<String>): Map<String, Any?> {
        val ai: ApplicationInfo? = info.applicationInfo
        val requested = info.requestedPermissions?.toList() ?: emptyList()
        val flags = info.requestedPermissionsFlags
        val granted = requested.filterIndexed { i, _ ->
            flags != null && i < flags.size && (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        }
        val details = detailed(info.packageName)
        val boundServices = details?.services.orEmpty().mapNotNull { it.permission }.distinct()
        val receiverPerms = details?.receivers.orEmpty().mapNotNull { it.permission }.distinct()

        return mapOf(
            "package" to info.packageName,
            "label" to (ai?.let { runCatching { pm.getApplicationLabel(it).toString() }.getOrNull() } ?: info.packageName),
            "versionName" to info.versionName,
            "versionCode" to (if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()),
            "firstInstall" to info.firstInstallTime,
            "lastUpdate" to info.lastUpdateTime,
            "isSystem" to ((ai?.flags ?: 0) and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0),
            "debuggable" to ((ai?.flags ?: 0) and ApplicationInfo.FLAG_DEBUGGABLE != 0),
            "enabled" to (ai?.enabled ?: true),
            "targetSdk" to ai?.targetSdkVersion,
            "hasLauncher" to launchable.contains(info.packageName),
            "installer" to installer(info.packageName),
            "requestedPermissions" to requested,
            "grantedPermissions" to granted,
            "boundServicePermissions" to boundServices,
            "receiverPermissions" to receiverPerms,
            "signingSha256" to signingDigests(details),
            "appOps" to appOpsFor(ai),
        )
    }

    private fun installer(pkg: String): Map<String, String?> = try {
        if (Build.VERSION.SDK_INT >= 30) {
            val src = pm.getInstallSourceInfo(pkg)
            mapOf("installing" to src.installingPackageName, "initiating" to src.initiatingPackageName)
        } else {
            @Suppress("DEPRECATION")
            mapOf("installing" to pm.getInstallerPackageName(pkg), "initiating" to null)
        }
    } catch (e: Exception) {
        mapOf("installing" to null, "initiating" to null)
    }

    private fun signingDigests(info: PackageInfo?): List<String> {
        val si = info?.signingInfo ?: return emptyList()
        val sigs = if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
        return sigs.orEmpty().map { DeviceInspector.sha256Hex(it.toByteArray()) }
    }

    /**
     * Special-access app-ops. Reading another package's mode may be refused on some builds; the
     * value is then "unknown" and the engine treats it as unverified, never as granted.
     */
    private fun appOpsFor(ai: ApplicationInfo?): Map<String, String> {
        if (ai == null) return emptyMap()
        val ops = mutableMapOf(
            "overlay" to AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
            "usageStats" to AppOpsManager.OPSTR_GET_USAGE_STATS,
        )
        if (Build.VERSION.SDK_INT >= 30) ops["manageStorage"] = "android:manage_external_storage"
        if (Build.VERSION.SDK_INT >= 26) ops["installPackages"] = "android:request_install_packages"
        return ops.mapValues { (_, op) ->
            try {
                val mode = if (Build.VERSION.SDK_INT >= 29) appOps.unsafeCheckOpNoThrow(op, ai.uid, ai.packageName)
                else @Suppress("DEPRECATION") appOps.checkOpNoThrow(op, ai.uid, ai.packageName)
                when (mode) {
                    AppOpsManager.MODE_ALLOWED -> "allowed"
                    AppOpsManager.MODE_IGNORED, AppOpsManager.MODE_ERRORED -> "denied"
                    else -> "default"
                }
            } catch (e: Exception) {
                "unknown"
            }
        }
    }
}
