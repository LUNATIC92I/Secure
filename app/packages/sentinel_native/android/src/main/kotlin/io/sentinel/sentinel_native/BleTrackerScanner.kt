package io.sentinel.sentinel_native

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid

/**
 * Short, foreground-only BLE scan looking for advertisement formats used by item trackers.
 * Trackers rotate their addresses, so results are a hint to cross-check with the OS's
 * native unknown-tracker alerts, never proof of tracking.
 */
class BleTrackerScanner(private val context: Context) {

    private val samsung = ParcelUuid.fromString("0000FD5A-0000-1000-8000-00805F9B34FB")
    private val tile = ParcelUuid.fromString("0000FEED-0000-1000-8000-00805F9B34FB")
    private val googleFmdn = ParcelUuid.fromString("0000FEAA-0000-1000-8000-00805F9B34FB")

    @SuppressLint("MissingPermission") // Permission is checked by the caller before scanning.
    fun scan(seconds: Int, done: (Map<String, Any?>) -> Unit) {
        val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
        if (adapter == null) return done(mapOf("status" to "unsupported"))
        if (!adapter.isEnabled) return done(mapOf("status" to "bluetoothOff"))
        val scanner = adapter.bluetoothLeScanner ?: return done(mapOf("status" to "unsupported"))

        val seen = LinkedHashMap<String, MutableMap<String, Any?>>()
        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val kind = classify(result) ?: return
                val addr = result.device.address
                val entry = seen.getOrPut(addr) {
                    mutableMapOf("address" to addr, "kind" to kind, "firstSeen" to System.currentTimeMillis(), "count" to 0)
                }
                entry["rssi"] = result.rssi
                entry["lastSeen"] = System.currentTimeMillis()
                entry["count"] = (entry["count"] as Int) + 1
            }

            override fun onScanFailed(errorCode: Int) {
                seen["__error"] = mutableMapOf("error" to errorCode)
            }
        }
        try {
            scanner.startScan(null, ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), callback)
        } catch (e: SecurityException) {
            return done(mapOf("status" to "permissionDenied"))
        }
        Handler(Looper.getMainLooper()).postDelayed({
            try { scanner.stopScan(callback) } catch (_: Exception) {}
            val error = seen.remove("__error")
            done(
                mapOf(
                    "status" to if (error != null) "failed" else "ok",
                    "durationSeconds" to seconds,
                    "devices" to seen.values.toList(),
                )
            )
        }, seconds.coerceIn(3, 30) * 1000L)
    }

    private fun classify(r: ScanResult): String? {
        val record = r.scanRecord ?: return null
        // Apple manufacturer data, type 0x12 = Find My "offline finding" (AirTag & accessories separated from owner).
        record.getManufacturerSpecificData(0x004C)?.let { data ->
            if (data.isNotEmpty() && data[0].toInt() == 0x12) return "apple_findmy"
        }
        val uuids = record.serviceUuids.orEmpty() + record.serviceData.keys
        if (uuids.contains(samsung)) return "samsung_smarttag"
        if (uuids.contains(tile)) return "tile"
        record.getServiceData(googleFmdn)?.let { d ->
            if (d.isNotEmpty() && (d[0].toInt() == 0x40 || d[0].toInt() == 0x41)) return "google_fmdn"
        }
        return null
    }
}
