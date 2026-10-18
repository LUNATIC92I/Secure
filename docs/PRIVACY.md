# Privacy policy (template for Sentinel Mobile SOC)

_Adapt the controller name and contact before publishing on a store._

**Default: nothing leaves your device.** Sentinel Mobile SOC analyses your phone locally. Scan reports, incidents, tracker sightings and settings are stored on the device only, encrypted (AES-256-GCM) with a key held in the Android Keystore / iOS Keychain, and excluded from cloud backups.

**What the app reads (locally):** device security settings, the list of installed apps with their permissions, install source and signing certificate (Android), network properties (connection type, VPN/proxy, Wi-Fi security type), Bluetooth advertisements of item trackers during a scan you start, files you explicitly select for APK analysis, links you type, paste or share to it.

**What the app never collects:** call contents or recordings, microphone audio, SMS, contacts, call log, passwords, photos, location history. The app contains no advertising or analytics SDK.

**Optional network features (off by default):**
- *Network integrity check*: TLS connections to google.com, cloudflare.com and apple.com to verify certificates; no personal data is sent.
- *Redirect analysis*: when you enable it for a link, the app requests that link's headers from the site.
- *Cloud reputation* (requires configuring your own backend and an explicit switch): the app sends SHA-256 hashes of files and of domain names; full URLs only if you enable "send full URLs". Files are never uploaded. The backend may query Google Web Risk or VirusTotal with those values under their terms.
- *Incident sync* (backend API, opt-in): incidents you choose to sync are stored server-side under an anonymous device identifier; `DELETE /v1/me` erases them.

**Retention:** configurable (7/30/90/365 days). "Delete history" and "Erase all data and keys" are available in Privacy controls.

**Exports:** reports leave the device only when you use the share sheet.

**Children / safety:** the app must not be used to monitor another person. It does not reveal anyone's location.
