package io.sentinel.sentinel_native

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.os.Build

/**
 * Reports the active network's properties. It does not see other apps' traffic; it only
 * describes transports, proxy, DNS and the Wi-Fi security type when the OS exposes it.
 */
class NetworkInspector(private val context: Context) {

    fun snapshot(): Map<String, Any?> {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val active = cm.activeNetwork
        val caps = active?.let { cm.getNetworkCapabilities(it) }
        val link = active?.let { cm.getLinkProperties(it) }

        @Suppress("DEPRECATION")
        val vpnAnyNetwork = cm.allNetworks.any { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }

        val proxy = link?.httpProxy
        return mapOf(
            "connected" to (caps != null),
            "transport" to when {
                caps == null -> "none"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
                else -> "other"
            },
            "vpnActive" to (vpnAnyNetwork || caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true),
            "validated" to caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            "captivePortal" to caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            "metered" to caps?.let { !it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) },
            "proxy" to proxy?.let {
                mapOf("host" to it.host, "port" to it.port, "pacUrl" to it.pacFileUrl?.toString()?.takeIf { u -> u.isNotBlank() && u != "about:blank" })
            },
            "privateDnsActive" to (if (Build.VERSION.SDK_INT >= 28) link?.isPrivateDnsActive else null),
            "privateDnsServer" to (if (Build.VERSION.SDK_INT >= 28) link?.privateDnsServerName else null),
            "dnsServers" to link?.dnsServers?.map { it.hostAddress },
            "wifiSecurity" to wifiSecurity(caps),
        )
    }

    /** WifiInfo#getCurrentSecurityType exists from API 31; earlier versions report null (unknown). */
    private fun wifiSecurity(caps: NetworkCapabilities?): String? {
        if (Build.VERSION.SDK_INT < 31 || caps == null) return null
        val info = caps.transportInfo as? WifiInfo ?: return null
        return when (info.currentSecurityType) {
            WifiInfo.SECURITY_TYPE_OPEN -> "open"
            WifiInfo.SECURITY_TYPE_WEP -> "wep"
            WifiInfo.SECURITY_TYPE_PSK -> "wpa2-psk"
            WifiInfo.SECURITY_TYPE_EAP -> "wpa-enterprise"
            WifiInfo.SECURITY_TYPE_SAE -> "wpa3-sae"
            WifiInfo.SECURITY_TYPE_OWE -> "owe"
            WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE, WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT -> "wpa3-enterprise"
            WifiInfo.SECURITY_TYPE_UNKNOWN -> null
            else -> "other"
        }
    }
}
