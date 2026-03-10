import '../platform/rasp_channel.dart';
import 'security_result.dart';

/// Detects network-level threats used during desktop-based reverse engineering:
///
/// - **HTTP Proxy** — Burp Suite, mitmproxy, Charles Proxy running on desktop
/// - **VPN** — VPN tunnels routing traffic through desktop interceptors
///
/// These are the primary tools attackers use to intercept HTTPS traffic
/// after decompiling and repackaging an APK/IPA.
///
/// **Android:** Checks system proxy properties, ConnectivityManager proxy,
/// global proxy settings, VPN transport capabilities, and tun/ppp interfaces.
///
/// **iOS:** Checks CFNetwork proxy settings (HTTP/HTTPS/SOCKS), and
/// network interfaces for utun/ppp/ipsec/tap/tun prefixes.
class NetworkThreatDetector {
  /// Executes network threat detection on the native platform.
  ///
  /// Returns detected if an HTTP proxy or VPN is active.
  static Future<SecurityResult> check() async {
    final isDetected =
        await RaspChannel.invokeDetection('checkNetworkThreats');
    return SecurityResult(
      isDetected: isDetected,
      message: isDetected
          ? 'Network threat detected (proxy or VPN active — possible MITM)'
          : null,
    );
  }
}
