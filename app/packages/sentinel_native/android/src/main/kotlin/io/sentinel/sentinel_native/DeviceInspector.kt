package io.sentinel.sentinel_native

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.hardware.SensorPrivacyManager
import android.os.Build
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import android.view.inputmethod.InputMethodManager
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit

/**
 * Collects device posture observations from documented, unprivileged APIs.
 * Each probe records whether it was available so the UI can show coverage
 * honestly instead of implying a check happened.
 */
class DeviceInspector(private val context: Context) {

    private val unavailable = mutableListOf<String>()

    fun platformInfo(): Map<String, Any?> = mapOf(
        "platform" to "android",
        "osVersion" to Build.VERSION.RELEASE,
        "sdkInt" to Build.VERSION.SDK_INT,
        "manufacturer" to Build.MANUFACTURER,
        "model" to Build.MODEL,
        "securityPatch" to Build.VERSION.SECURITY_PATCH,
    )

    fun snapshot(): Map<String, Any?> {
        val cr = context.contentResolver
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

        val out = HashMap<String, Any?>()
        out.putAll(platformInfo())
        out["collectedAt"] = System.currentTimeMillis()
        out["deviceSecure"] = km.isDeviceSecure
        out["encryptionStatus"] = when (dpm.storageEncryptionStatus) {
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER -> "active"
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> "defaultKey"
            DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> "inactive"
            DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED -> "unsupported"
            else -> "unknown"
        }
        out["adbEnabled"] = globalInt(cr, Settings.Global.ADB_ENABLED)?.let { it == 1 }
        out["developerOptions"] = globalInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)?.let { it == 1 }
        out["autoTime"] = globalInt(cr, Settings.Global.AUTO_TIME)?.let { it == 1 }
        out["buildTags"] = Build.TAGS
        out["fingerprint"] = Build.FINGERPRINT
        out["isEmulator"] = isEmulator()
        out["accessibilityServices"] = accessibilityServices()
        out["deviceAdmins"] = deviceAdmins(dpm)
        out["notificationListeners"] = componentList(cr, "enabled_notification_listeners")
        out["inputMethods"] = inputMethods()
        out["defaultInputMethod"] = secureString(cr, Settings.Secure.DEFAULT_INPUT_METHOD)
        out["userCaCertificates"] = userCaCertificates()
        out["root"] = rootIndicators()
        out["bootProps"] = bootProperties()
        out["micToggleSupported"] = micToggleSupported()
        out["locationEnabled"] = locationEnabled()
        out["unavailableProbes"] = unavailable.toList()
        return out
    }

    private fun globalInt(cr: android.content.ContentResolver, key: String): Int? = try {
        Settings.Global.getInt(cr, key)
    } catch (e: Exception) {
        unavailable.add("global:$key"); null
    }

    private fun secureString(cr: android.content.ContentResolver, key: String): String? = try {
        Settings.Secure.getString(cr, key)
    } catch (e: Exception) {
        unavailable.add("secure:$key"); null
    }

    private fun componentList(cr: android.content.ContentResolver, key: String): List<String>? {
        val raw = try {
            Settings.Secure.getString(cr, key)
        } catch (e: SecurityException) {
            unavailable.add("secure:$key"); return null
        }
        return raw?.split(':')?.filter { it.isNotBlank() } ?: emptyList()
    }

    private fun accessibilityServices(): List<Map<String, Any?>> {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        return am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).map { info ->
            val si = info.resolveInfo?.serviceInfo
            mapOf(
                "id" to info.id,
                "package" to si?.packageName,
                "isSystem" to ((si?.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0),
                "canRetrieveWindowContent" to (info.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0),
                "canPerformGestures" to (info.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES != 0),
            )
        }
    }

    private fun deviceAdmins(dpm: DevicePolicyManager): List<Map<String, Any?>> =
        (dpm.activeAdmins ?: emptyList()).map { cn ->
            mapOf(
                "package" to cn.packageName,
                "component" to cn.flattenToShortString(),
                "isDeviceOwner" to safeBool { dpm.isDeviceOwnerApp(cn.packageName) },
                "isProfileOwner" to safeBool { dpm.isProfileOwnerApp(cn.packageName) },
            )
        }

    private fun inputMethods(): List<Map<String, Any?>> {
        val imm = context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
        return imm.enabledInputMethodList.map {
            mapOf(
                "id" to it.id,
                "package" to it.packageName,
                "isSystem" to ((it.serviceInfo.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0),
            )
        }
    }

    /** User-installed CA certificates can enable interception of TLS traffic for apps that trust them. */
    private fun userCaCertificates(): List<Map<String, Any?>>? = try {
        val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        ks.aliases().toList().filter { it.startsWith("user:") }.mapNotNull { alias ->
            val cert = ks.getCertificate(alias) as? X509Certificate ?: return@mapNotNull null
            mapOf(
                "alias" to alias,
                "subject" to cert.subjectX500Principal.name,
                "issuer" to cert.issuerX500Principal.name,
                "notAfter" to cert.notAfter.time,
                "sha256" to sha256Hex(cert.encoded),
            )
        }
    } catch (e: Exception) {
        unavailable.add("userCaStore"); null
    }

    private fun rootIndicators(): Map<String, Any?> {
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/xbin/su",
            "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
            "/system/app/Superuser.apk", "/system/xbin/daemonsu",
        )
        val found = suPaths.filter { runCatching { File(it).exists() }.getOrDefault(false) }
        val managers = listOf(
            "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser",
            "com.noshufou.android.su", "me.weishu.kernelsu", "com.kingroot.kinguser", "me.bmax.apatch",
        )
        val pm = context.packageManager
        val installedManagers = managers.filter { pkg ->
            runCatching { pm.getPackageInfo(pkg, 0); true }.getOrDefault(false)
        }
        return mapOf(
            "suPaths" to found,
            "rootManagers" to installedManagers,
            "testKeys" to (Build.TAGS?.contains("test-keys") == true),
        )
    }

    /**
     * Boot state is read with the shell `getprop` command, which is available to normal apps on
     * most builds; vendors may block it, in which case the values are reported as unknown.
     */
    private fun bootProperties(): Map<String, String?> {
        val keys = listOf("ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.debuggable", "ro.secure", "ro.boot.vbmeta.device_state")
        return keys.associateWith { key ->
            try {
                val p = ProcessBuilder("getprop", key).redirectErrorStream(true).start()
                val value = p.inputStream.bufferedReader().readText().trim()
                p.waitFor(2, TimeUnit.SECONDS)
                value.ifBlank { null }
            } catch (e: Exception) {
                null
            }
        }.also { if (it.values.all { v -> v == null }) unavailable.add("bootProps") }
    }

    private fun micToggleSupported(): Boolean? = if (Build.VERSION.SDK_INT >= 31) {
        runCatching {
            context.getSystemService(SensorPrivacyManager::class.java)
                ?.supportsSensorToggle(SensorPrivacyManager.Sensors.MICROPHONE)
        }.getOrNull()
    } else false

    private fun locationEnabled(): Boolean? = runCatching {
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as android.location.LocationManager
        if (Build.VERSION.SDK_INT >= 28) lm.isLocationEnabled else null
    }.getOrNull()

    private fun isEmulator(): Boolean =
        Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.contains("emulator") ||
            Build.HARDWARE.contains("goldfish") || Build.HARDWARE.contains("ranchu") ||
            Build.PRODUCT.contains("sdk_gphone") || Build.MODEL.contains("Android SDK built for")

    private fun safeBool(block: () -> Boolean): Boolean? = try { block() } catch (e: Exception) { null }

    companion object {
        fun sha256Hex(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
