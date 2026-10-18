import AVFoundation
import CoreBluetooth
import CoreLocation
import Flutter
import LocalAuthentication
import MachO
import Network
import UIKit

/// iOS side of the Sentinel bridge.
///
/// A standard App Store app is sandboxed: it cannot list installed apps, read configuration
/// profiles, or see other apps' microphone use. This plugin only reports what public APIs
/// expose and marks everything else as unsupported so the UI can say so.
public class SentinelNativePlugin: NSObject, FlutterPlugin {
    private var channel: FlutterMethodChannel?
    private var pendingSharedText: String?
    private var bleScanner: TrackerScanner?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "io.sentinel/native", binaryMessenger: registrar.messenger())
        let instance = SentinelNativePlugin()
        instance.channel = channel
        registrar.addMethodCallDelegate(instance, channel: channel)
        registrar.addApplicationDelegate(instance)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any]
        switch call.method {
        case "platformInfo":
            result(platformInfo())
        case "deviceSnapshot":
            result(deviceSnapshot())
        case "installedApps":
            result(["supported": false, "apps": [], "reason": "iOS sandbox does not allow enumerating installed apps"])
        case "networkSnapshot":
            networkSnapshot(result)
        case "analyzeApk", "pickApk", "requestUninstall":
            result(FlutterError(code: "unsupported", message: "Not available on iOS", details: nil))
        case "permissionStatus":
            result(permissionStatus(args?["permission"] as? String))
        case "requestPermission":
            requestPermission(args?["permission"] as? String, result)
        case "openSettings":
            // Only the app's own settings page has a public URL; other panes need manual navigation.
            if let url = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(url) { ok in result(ok) }
            } else {
                result(false)
            }
        case "openDialer":
            // iOS refuses tel: links that contain * or #, so carrier codes must be typed by the user.
            result(false)
        case "bleTrackerScan":
            let seconds = args?["seconds"] as? Int ?? 10
            let scanner = TrackerScanner()
            bleScanner = scanner
            scanner.scan(seconds: seconds) { [weak self] map in
                self?.bleScanner = nil
                result(map)
            }
        case "consumeSharedText":
            result(pendingSharedText)
            pendingSharedText = nil
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - URL scheme hand-off: sentinel://scan?url=<encoded>

    public func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        guard url.scheme == "sentinel",
              let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let target = comps.queryItems?.first(where: { $0.name == "url" })?.value
        else { return false }
        pendingSharedText = String(target.prefix(4096))
        channel?.invokeMethod("sharedText", arguments: nil)
        return true
    }

    // MARK: - Device posture

    private func platformInfo() -> [String: Any?] {
        var sys = utsname()
        uname(&sys)
        let machine = withUnsafePointer(to: &sys.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
        }
        return [
            "platform": "ios",
            "osVersion": UIDevice.current.systemVersion,
            "model": machine,
            "manufacturer": "Apple",
        ]
    }

    private func deviceSnapshot() -> [String: Any?] {
        var out = platformInfo()
        let ctx = LAContext()
        var err: NSError?
        out["collectedAt"] = Int(Date().timeIntervalSince1970 * 1000)
        out["deviceSecure"] = ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err)
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch ctx.biometryType {
        case .faceID: out["biometry"] = "faceID"
        case .touchID: out["biometry"] = "touchID"
        default: out["biometry"] = "none"
        }
        out["isSimulator"] = isSimulator()
        out["debuggerAttached"] = debuggerAttached()
        out["jailbreak"] = jailbreakIndicators()
        out["proxy"] = proxySettings()
        out["vpnActive"] = vpnActive()
        out["lowPowerMode"] = ProcessInfo.processInfo.isLowPowerModeEnabled
        out["micPermission"] = micPermission()
        out["locationPermission"] = locationPermission()
        out["bluetoothPermission"] = bluetoothPermission()
        out["unavailableProbes"] = [
            "installedApps", "configurationProfiles", "otherAppsMicrophoneUse", "userCaCertificates",
            "accessibilityServices", "deviceAdmins", "carrierCallForwarding",
        ]
        return out
    }

    private func isSimulator() -> Bool {
        #if targetEnvironment(simulator)
            return true
        #else
            return false
        #endif
    }

    private func debuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let rc = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        return rc == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
    }

    /// Jailbreak artefacts. Absence proves nothing (modern jailbreaks hide them); presence is a strong hint.
    private func jailbreakIndicators() -> [String: Any] {
        if isSimulator() { return ["paths": [], "schemes": [], "dylibs": [], "sandboxWritable": false] }
        let paths = [
            "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib", "/bin/bash", "/usr/sbin/sshd",
            "/etc/apt", "/private/var/lib/apt/", "/var/jb", "/usr/bin/ssh",
        ].filter { FileManager.default.fileExists(atPath: $0) }

        let schemes = ["cydia://", "sileo://", "zbra://", "filza://"].filter { s in
            guard let u = URL(string: s) else { return false }
            return UIApplication.shared.canOpenURL(u)
        }

        var dylibs: [String] = []
        let markers = ["mobilesubstrate", "substitute", "libhooker", "tweakinject", "frida", "cycript", "ellekit"]
        for i in 0..<_dyld_image_count() {
            guard let name = _dyld_get_image_name(i) else { continue }
            let lower = String(cString: name).lowercased()
            if markers.contains(where: { lower.contains($0) }) { dylibs.append(String(cString: name)) }
        }

        var writable = false
        let probe = "/private/sentinel_probe_\(UUID().uuidString)"
        if (try? "x".write(toFile: probe, atomically: true, encoding: .utf8)) != nil {
            writable = true
            try? FileManager.default.removeItem(atPath: probe)
        }
        return ["paths": paths, "schemes": schemes, "dylibs": dylibs, "sandboxWritable": writable]
    }

    private func proxySettings() -> [String: Any?]? {
        guard let dict = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else { return nil }
        let httpOn = (dict["HTTPEnable"] as? Int ?? 0) == 1
        let pacOn = (dict["ProxyAutoConfigEnable"] as? Int ?? 0) == 1
        if !httpOn && !pacOn { return nil }
        return [
            "host": dict["HTTPProxy"] as? String,
            "port": dict["HTTPPort"] as? Int,
            "pacUrl": dict["ProxyAutoConfigURLString"] as? String,
        ]
    }

    private func vpnActive() -> Bool {
        guard let dict = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
              let scoped = dict["__SCOPED__"] as? [String: Any] else { return false }
        return scoped.keys.contains { key in
            ["tap", "tun", "ppp", "ipsec", "utun"].contains { key.hasPrefix($0) }
        }
    }

    private func micPermission() -> String {
        if #available(iOS 17.0, *) {
            switch AVAudioApplication.shared.recordPermission {
            case .granted: return "granted"
            case .denied: return "denied"
            default: return "undetermined"
            }
        }
        switch AVAudioSession.sharedInstance().recordPermission {
        case .granted: return "granted"
        case .denied: return "denied"
        default: return "undetermined"
        }
    }

    private func locationPermission() -> String {
        switch CLLocationManager().authorizationStatus {
        case .authorizedAlways: return "always"
        case .authorizedWhenInUse: return "whenInUse"
        case .denied, .restricted: return "denied"
        default: return "undetermined"
        }
    }

    private func bluetoothPermission() -> String {
        switch CBManager.authorization {
        case .allowedAlways: return "granted"
        case .denied, .restricted: return "denied"
        default: return "undetermined"
        }
    }

    private func permissionStatus(_ name: String?) -> String {
        switch name {
        case "bluetoothScan": return bluetoothPermission()
        default: return "notRequired"
        }
    }

    private func requestPermission(_ name: String?, _ result: @escaping FlutterResult) {
        guard name == "bluetoothScan" else { return result("notRequired") }
        if CBManager.authorization != .notDetermined { return result(bluetoothPermission()) }
        // Creating a central manager triggers the system prompt; the scan helper waits for the answer.
        let scanner = TrackerScanner()
        bleScanner = scanner
        scanner.waitForAuthorization { [weak self] in
            self?.bleScanner = nil
            result(self?.bluetoothPermission() ?? "denied")
        }
    }

    // MARK: - Network

    private func networkSnapshot(_ result: @escaping FlutterResult) {
        let monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "io.sentinel.path")
        var delivered = false
        monitor.pathUpdateHandler = { [weak self] path in
            guard !delivered else { return }
            delivered = true
            monitor.cancel()
            var transport = "other"
            if path.status != .satisfied { transport = "none" }
            else if path.usesInterfaceType(.wifi) { transport = "wifi" }
            else if path.usesInterfaceType(.cellular) { transport = "cellular" }
            else if path.usesInterfaceType(.wiredEthernet) { transport = "ethernet" }
            let map: [String: Any?] = [
                "connected": path.status == .satisfied,
                "transport": transport,
                "vpnActive": self?.vpnActive() ?? false,
                "metered": path.isExpensive,
                "constrained": path.isConstrained,
                "proxy": self?.proxySettings() ?? nil,
                "wifiSecurity": nil, // Not exposed to apps without the hotspot entitlement.
                "privateDnsActive": nil,
            ]
            DispatchQueue.main.async { result(map) }
        }
        monitor.start(queue: queue)
    }
}

/// CoreBluetooth cannot see Apple Find My advertisements (iOS filters them), so only
/// third-party tracker service UUIDs are scanned. Native "Unwanted tracker" alerts remain
/// the primary mechanism on iOS.
final class TrackerScanner: NSObject, CBCentralManagerDelegate {
    private var central: CBCentralManager?
    private var onReady: (() -> Void)?
    private var devices: [String: [String: Any]] = [:]
    private let services: [CBUUID: String] = [
        CBUUID(string: "FD5A"): "samsung_smarttag",
        CBUUID(string: "FEED"): "tile",
        CBUUID(string: "FEAA"): "google_fmdn",
    ]

    func waitForAuthorization(_ done: @escaping () -> Void) {
        onReady = done
        central = CBCentralManager(delegate: self, queue: .main)
    }

    func scan(seconds: Int, done: @escaping ([String: Any]) -> Void) {
        onReady = { [weak self] in
            guard let self = self, let central = self.central else { return }
            switch central.state {
            case .poweredOn:
                central.scanForPeripherals(withServices: Array(self.services.keys), options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
                DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(max(3, min(seconds, 30)))) {
                    central.stopScan()
                    done(["status": "ok", "durationSeconds": seconds, "devices": Array(self.devices.values)])
                }
            case .poweredOff: done(["status": "bluetoothOff"])
            case .unauthorized: done(["status": "permissionDenied"])
            default: done(["status": "unsupported"])
            }
        }
        central = CBCentralManager(delegate: self, queue: .main)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state != .unknown && central.state != .resetting else { return }
        let ready = onReady
        onReady = nil
        ready?()
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let uuids = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] ?? [])
            + ((advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data])?.keys.map { $0 } ?? [])
        guard let kind = uuids.compactMap({ services[$0] }).first else { return }
        let id = peripheral.identifier.uuidString
        let now = Int(Date().timeIntervalSince1970 * 1000)
        var entry = devices[id] ?? ["address": id, "kind": kind, "firstSeen": now, "count": 0]
        entry["rssi"] = RSSI.intValue
        entry["lastSeen"] = now
        entry["count"] = (entry["count"] as? Int ?? 0) + 1
        devices[id] = entry
    }
}
