package com.neelakandan.flutter_neo_shield.rasp

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import java.net.NetworkInterface

/**
 * Detects network-level threats used during APK reverse engineering from desktop:
 *
 * 1. HTTP Proxy — Burp Suite, mitmproxy, Charles Proxy running on desktop
 * 2. VPN — VPN tunnels routing traffic through desktop interceptors
 *
 * These are the primary tools attackers use to intercept HTTPS traffic
 * after decompiling and repackaging an APK.
 */
class NetworkThreatDetector {

    /**
     * Returns a map with:
     *   "proxyDetected" -> Boolean
     *   "vpnDetected"   -> Boolean
     *   "detected"      -> Boolean (true if ANY threat found)
     */
    fun check(context: Context): Map<String, Any> {
        val proxyDetected = checkProxy(context)
        val vpnDetected = checkVpn(context)

        return mapOf(
            "proxyDetected" to proxyDetected,
            "vpnDetected" to vpnDetected,
            "detected" to (proxyDetected || vpnDetected)
        )
    }

    /**
     * Simple boolean: returns true if proxy or VPN detected.
     */
    fun checkSimple(context: Context): Boolean {
        return checkProxy(context) || checkVpn(context)
    }

    /**
     * Detects HTTP/HTTPS proxy configuration.
     *
     * Attackers configure proxy settings on the device/emulator to route
     * traffic through Burp Suite or mitmproxy on their desktop.
     */
    private fun checkProxy(context: Context): Boolean {
        // Method 1: System property check
        try {
            val httpProxy = System.getProperty("http.proxyHost")
            if (!httpProxy.isNullOrEmpty()) {
                return true
            }

            val httpsProxy = System.getProperty("https.proxyHost")
            if (!httpsProxy.isNullOrEmpty()) {
                return true
            }
        } catch (e: Exception) {
            // Ignore
        }

        // Method 2: ConnectivityManager proxy info (API 23+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                val network = cm?.activeNetwork
                val linkProperties = cm?.getLinkProperties(network)
                val proxyInfo = linkProperties?.httpProxy
                if (proxyInfo != null && proxyInfo.host != null) {
                    return true
                }
            } catch (e: Exception) {
                // Ignore
            }
        }

        // Method 3: Global proxy setting
        try {
            val globalProxy = android.provider.Settings.Global.getString(
                context.contentResolver,
                android.provider.Settings.Global.HTTP_PROXY
            )
            if (!globalProxy.isNullOrEmpty() && globalProxy != ":0") {
                return true
            }
        } catch (e: Exception) {
            // Ignore
        }

        return false
    }

    /**
     * Detects active VPN connections.
     *
     * VPN tunnels are used to route all device traffic through a desktop
     * machine running an intercepting proxy.
     */
    private fun checkVpn(context: Context): Boolean {
        // Method 1: ConnectivityManager network capabilities (API 23+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                val activeNetwork = cm?.activeNetwork
                if (activeNetwork != null) {
                    val caps = cm.getNetworkCapabilities(activeNetwork)
                    if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        return true
                    }
                }
            } catch (e: Exception) {
                // Ignore
            }
        }

        // Method 2: Check for tun/ppp/tap network interfaces
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (!iface.isUp) continue
                val name = iface.name.lowercase()
                if (name.startsWith("tun") ||
                    name.startsWith("ppp") ||
                    name.startsWith("tap") ||
                    name.startsWith("utun") ||
                    name.startsWith("ipsec")) {
                    return true
                }
            }
        } catch (e: Exception) {
            // Ignore
        }

        return false
    }
}
