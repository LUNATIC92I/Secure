package io.sentinel.sentinel_native

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry
import java.io.File
import java.util.concurrent.Executors

/**
 * Bridge between the Dart detection engine and documented Android APIs.
 *
 * Every method returns raw observations only; classification and scoring
 * happen in Dart so that both platforms share one auditable engine.
 * Nothing here uses root, hidden APIs or privileged permissions.
 */
class SentinelNativePlugin :
    FlutterPlugin,
    MethodCallHandler,
    ActivityAware,
    PluginRegistry.ActivityResultListener,
    PluginRegistry.RequestPermissionsResultListener,
    PluginRegistry.NewIntentListener {

    private lateinit var channel: MethodChannel
    private lateinit var context: Context
    private var binding: ActivityPluginBinding? = null
    private val activity: Activity? get() = binding?.activity
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    private var pendingPick: Result? = null
    private var pendingPermission: Result? = null
    private var pendingSharedText: String? = null

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        context = flutterPluginBinding.applicationContext
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "io.sentinel/native")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "platformInfo" -> result.success(DeviceInspector(context).platformInfo())
            "deviceSnapshot" -> background(result) { DeviceInspector(context).snapshot() }
            "installedApps" -> background(result) { AppInventory(context).listApps() }
            "networkSnapshot" -> background(result) { NetworkInspector(context).snapshot() }
            "analyzeApk" -> {
                val path = call.argument<String>("path")
                if (path == null) result.error("bad_args", "path required", null)
                else background(result) { ApkInspector(context).inspect(File(path)) }
            }
            "pickApk" -> pickApk(result)
            "permissionStatus" -> result.success(permissionStatus(call.argument<String>("permission")))
            "requestPermission" -> requestPermission(call.argument<String>("permission"), result)
            "openSettings" -> result.success(
                openSettings(call.argument<String>("target") ?: "app", call.argument<String>("package"))
            )
            "requestUninstall" -> result.success(requestUninstall(call.argument<String>("package")))
            "openDialer" -> result.success(openDialer(call.argument<String>("code")))
            "bleTrackerScan" -> {
                val seconds = call.argument<Int>("seconds") ?: 10
                BleTrackerScanner(context).scan(seconds) { scan -> main.post { result.success(scan) } }
            }
            "consumeSharedText" -> {
                val text = pendingSharedText
                pendingSharedText = null
                result.success(text)
            }
            else -> result.notImplemented()
        }
    }

    private fun background(result: Result, block: () -> Any?) {
        io.execute {
            try {
                val value = block()
                main.post { result.success(value) }
            } catch (e: Exception) {
                main.post { result.error("native_error", e.javaClass.simpleName + ": " + (e.message ?: ""), null) }
            }
        }
    }

    // ---- APK selection through the Storage Access Framework (no storage permission needed).

    private fun pickApk(result: Result) {
        val act = activity ?: return result.error("no_activity", "UI not attached", null)
        if (pendingPick != null) return result.error("busy", "A file picker is already open", null)
        pendingPick = result
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("application/vnd.android.package-archive", "application/octet-stream"))
        }
        try {
            act.startActivityForResult(intent, REQ_PICK_APK)
        } catch (e: ActivityNotFoundException) {
            pendingPick = null
            result.error("no_picker", "No document picker available", null)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != REQ_PICK_APK) return false
        val result = pendingPick ?: return true
        pendingPick = null
        val uri = data?.data
        if (resultCode != Activity.RESULT_OK || uri == null) {
            result.success(null)
            return true
        }
        io.execute {
            try {
                // Copy into the app-private cache so it can be parsed; deleted after analysis by Dart.
                val dir = File(context.cacheDir, "apk_import").apply { mkdirs() }
                val target = File(dir, "import_${System.currentTimeMillis()}.apk")
                context.contentResolver.openInputStream(uri).use { input ->
                    requireNotNull(input) { "Unable to open selected file" }
                    target.outputStream().use { input.copyTo(it) }
                }
                val name = uri.lastPathSegment ?: target.name
                main.post { result.success(mapOf("path" to target.absolutePath, "displayName" to name)) }
            } catch (e: Exception) {
                main.post { result.error("copy_failed", e.message, null) }
            }
        }
        return true
    }

    // ---- Progressive runtime permissions.

    private fun permissionStatus(name: String?): String {
        val perm = mapPermission(name) ?: return "notRequired"
        return if (ContextCompat.checkSelfPermission(context, perm) == PackageManager.PERMISSION_GRANTED) "granted" else "denied"
    }

    private fun mapPermission(name: String?): String? = when (name) {
        "bluetoothScan" -> if (Build.VERSION.SDK_INT >= 31) android.Manifest.permission.BLUETOOTH_SCAN
        else android.Manifest.permission.ACCESS_FINE_LOCATION
        "notifications" -> if (Build.VERSION.SDK_INT >= 33) android.Manifest.permission.POST_NOTIFICATIONS else null
        else -> null
    }

    private fun requestPermission(name: String?, result: Result) {
        val perm = mapPermission(name) ?: return result.success("notRequired")
        if (ContextCompat.checkSelfPermission(context, perm) == PackageManager.PERMISSION_GRANTED) {
            return result.success("granted")
        }
        val act = activity ?: return result.error("no_activity", "UI not attached", null)
        if (pendingPermission != null) return result.error("busy", "Permission request in progress", null)
        pendingPermission = result
        ActivityCompat.requestPermissions(act, arrayOf(perm), REQ_PERMISSION)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray): Boolean {
        if (requestCode != REQ_PERMISSION) return false
        val granted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
        pendingPermission?.success(if (granted) "granted" else "denied")
        pendingPermission = null
        return true
    }

    // ---- Remediation helpers: they only open system UI, the user decides.

    private fun openSettings(target: String, pkg: String?): Boolean {
        val intent = when (target) {
            "appDetails" -> Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + (pkg ?: context.packageName)))
            "accessibility" -> Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            "deviceAdmin" -> Intent().setClassName("com.android.settings", "com.android.settings.DeviceAdminSettings")
            "security" -> Intent(Settings.ACTION_SECURITY_SETTINGS)
            "privacyDashboard" -> if (Build.VERSION.SDK_INT >= 31) Intent("android.intent.action.REVIEW_PERMISSION_USAGE") else Intent(Settings.ACTION_PRIVACY_SETTINGS)
            "privacy" -> Intent(Settings.ACTION_PRIVACY_SETTINGS)
            "vpn" -> Intent(Settings.ACTION_VPN_SETTINGS)
            "wifi" -> Intent(Settings.ACTION_WIFI_SETTINGS)
            "developer" -> Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
            "location" -> Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS)
            "bluetooth" -> Intent(Settings.ACTION_BLUETOOTH_SETTINGS)
            "notificationListeners" -> Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            "inputMethods" -> Intent(Settings.ACTION_INPUT_METHOD_SETTINGS)
            "unknownSources" -> Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
            "overlay" -> Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION)
            "usageAccess" -> Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
            "date" -> Intent(Settings.ACTION_DATE_SETTINGS)
            "systemUpdate" -> Intent("android.settings.SYSTEM_UPDATE_SETTINGS")
            "safetyCenter" -> Intent("android.settings.SAFETY_CENTER")
            "credentials" -> Intent("com.android.settings.TRUSTED_CREDENTIALS_USER")
            "notifications" -> Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
            else -> Intent(Settings.ACTION_SETTINGS)
        }
        return launch(intent) || launch(Intent(Settings.ACTION_SETTINGS))
    }

    private fun requestUninstall(pkg: String?): Boolean {
        if (pkg.isNullOrBlank()) return false
        // ACTION_DELETE shows the system confirmation dialog; nothing is removed without the user's tap.
        return launch(Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))
    }

    private fun openDialer(code: String?): Boolean {
        if (code.isNullOrBlank() || !Regex("^[*#0-9]{2,12}$").matches(code)) return false
        // ACTION_DIAL only pre-fills the dialer; the user must press call.
        return launch(Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + Uri.encode(code))))
    }

    private fun launch(intent: Intent): Boolean {
        val act = activity
        return try {
            if (act != null) act.startActivity(intent)
            else context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            true
        } catch (e: Exception) {
            false
        }
    }

    // ---- Share sheet: URLs shared to the app are queued for the phishing scanner.

    private fun captureShare(intent: Intent?) {
        if (intent?.action == Intent.ACTION_SEND && intent.type?.startsWith("text/") == true) {
            pendingSharedText = intent.getStringExtra(Intent.EXTRA_TEXT)?.take(4096)
            main.post { channel.invokeMethod("sharedText", null) }
        }
    }

    override fun onNewIntent(intent: Intent): Boolean {
        captureShare(intent)
        return false
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        this.binding = binding
        binding.addActivityResultListener(this)
        binding.addRequestPermissionsResultListener(this)
        binding.addOnNewIntentListener(this)
        captureShare(binding.activity.intent)
    }

    override fun onDetachedFromActivity() {
        binding?.removeActivityResultListener(this)
        binding?.removeRequestPermissionsResultListener(this)
        binding?.removeOnNewIntentListener(this)
        binding = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) = onAttachedToActivity(binding)

    override fun onDetachedFromActivityForConfigChanges() = onDetachedFromActivity()

    companion object {
        private const val REQ_PICK_APK = 0x5E01
        private const val REQ_PERMISSION = 0x5E02
    }
}
