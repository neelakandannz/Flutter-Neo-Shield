import Foundation
import Darwin

/// Detects network-level threats used during reverse engineering from desktop:
///
/// 1. HTTP Proxy — Burp Suite, mitmproxy, Charles Proxy
/// 2. VPN — VPN tunnels routing traffic through interceptors
///
/// These detect MITM (Man-in-the-Middle) attack setups commonly used
/// alongside APK/IPA reverse engineering.
public class NetworkThreatDetector {

    /// Returns a dictionary with detection results:
    ///   "proxyDetected" -> Bool
    ///   "vpnDetected"   -> Bool
    ///   "detected"      -> Bool (true if ANY threat)
    public static func check() -> [String: Any] {
        let proxyDetected = checkProxy()
        let vpnDetected = checkVpn()

        return [
            "proxyDetected": proxyDetected,
            "vpnDetected": vpnDetected,
            "detected": proxyDetected || vpnDetected
        ]
    }

    /// Simple boolean: true if proxy or VPN detected.
    public static func checkSimple() -> Bool {
        return checkProxy() || checkVpn()
    }

    /// Detects HTTP/HTTPS proxy configuration.
    ///
    /// Attackers configure proxy on the device to route traffic through
    /// Burp Suite, mitmproxy, or Charles Proxy on their desktop.
    private static func checkProxy() -> Bool {
        // Method 1: CFNetwork proxy settings
        guard let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return false
        }

        // Check HTTP proxy
        if let httpProxy = proxySettings[kCFNetworkProxiesHTTPProxy as String] as? String,
           !httpProxy.isEmpty {
            if let httpEnabled = proxySettings[kCFNetworkProxiesHTTPEnable as String] as? Int,
               httpEnabled == 1 {
                return true
            }
        }

        // Check HTTPS proxy
        if let httpsProxy = proxySettings[kCFNetworkProxiesHTTPSProxy as String] as? String,
           !httpsProxy.isEmpty {
            if let httpsEnabled = proxySettings[kCFNetworkProxiesHTTPSEnable as String] as? Int,
               httpsEnabled == 1 {
                return true
            }
        }

        // Check SOCKS proxy (used by some tools)
        if let socksProxy = proxySettings[kCFNetworkProxiesSOCKSProxy as String] as? String,
           !socksProxy.isEmpty {
            if let socksEnabled = proxySettings[kCFNetworkProxiesSOCKSEnable as String] as? Int,
               socksEnabled == 1 {
                return true
            }
        }

        return false
    }

    /// Detects active VPN connections.
    ///
    /// VPN tunnels route all traffic through a desktop interceptor.
    private static func checkVpn() -> Bool {
        // Check network interfaces for VPN tunnels
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return false
        }
        defer { freeifaddrs(ifaddr) }

        let vpnPrefixes = ["utun", "ppp", "ipsec", "tap", "tun"]

        var addr = firstAddr
        while true {
            let name = String(cString: addr.pointee.ifa_name)
            let flags = Int32(addr.pointee.ifa_flags)
            let isUp = (flags & IFF_UP) != 0

            if isUp {
                for prefix in vpnPrefixes {
                    if name.hasPrefix(prefix) {
                        return true
                    }
                }
            }

            guard let next = addr.pointee.ifa_next else { break }
            addr = next
        }

        return false
    }
}
