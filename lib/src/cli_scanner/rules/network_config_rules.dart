import '../scan_rule.dart';
import '../severity.dart';

const _cat = 'Insecure Network Configuration';

/// Rules for detecting insecure network configuration.
List<ScanRule> networkConfigRules() => [
      // 13. HTTP URLs
      ScanRule(
        id: 'NET001',
        category: _cat,
        severity: Severity.medium,
        title: 'Insecure HTTP URL',
        description: 'Non-HTTPS URL found. Data transmitted over HTTP is unencrypted.',
        recommendation: 'Use HTTPS for all network communication.',
        pattern: RegExp(
          r'''['"`]http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|0\.0\.0\.0|schemas\.android\.com|schemas\.microsoft\.com|www\.w3\.org|ns\.adobe\.com|xml\.org)[^'"`\s]+['"`]''',
        ),
        fileExtensions: ['.dart', '.yaml', '.json', '.xml'],
      ),

      // 14. Disabled Certificate Validation
      ScanRule(
        id: 'NET002',
        category: _cat,
        severity: Severity.critical,
        title: 'Certificate validation disabled',
        description:
            'badCertificateCallback returns true unconditionally, disabling TLS verification.',
        recommendation:
            'Use CertPinShield for certificate pinning instead of disabling validation.',
        pattern: RegExp(
          r'badCertificateCallback\s*[:=]\s*\([^)]*\)\s*=>\s*true',
        ),
        fileExtensions: ['.dart'],
      ),

      // 15. Missing Certificate Pinning (HttpClient without pinning)
      ScanRule(
        id: 'NET003',
        category: _cat,
        severity: Severity.medium,
        title: 'HttpClient without certificate pinning',
        description:
            'HttpClient created without certificate pinning. Vulnerable to MITM attacks.',
        recommendation:
            'Use CertPinShield.instance.createPinnedClient() for MITM-resistant connections.',
        pattern: RegExp(
          r'HttpClient\(\)',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'cert_pin'),
          RegExp(r'tls_shield'),
          RegExp(r'CertPinShield'),
        ],
      ),

      // 16. Cleartext Traffic (Android)
      ScanRule(
        id: 'NET004',
        category: _cat,
        severity: Severity.high,
        title: 'Android cleartext traffic enabled',
        description:
            'android:usesCleartextTraffic="true" allows unencrypted HTTP on Android.',
        recommendation:
            'Set usesCleartextTraffic="false" and use network_security_config for exceptions.',
        pattern: RegExp(
          r'android:usesCleartextTraffic\s*=\s*"true"',
        ),
        fileExtensions: ['.xml'],
      ),

      // 17. Missing/Weak Network Security Config
      ScanRule(
        id: 'NET005',
        category: _cat,
        severity: Severity.medium,
        title: 'Trust-all certificates in network security config',
        description:
            'Network security config trusts user-installed certificates or all CAs.',
        recommendation:
            'Only trust system CAs and pin your server certificates.',
        customCheck: (path, content) {
          final matches = <RuleMatch>[];
          if (!path.endsWith('.xml')) return matches;
          final pattern = RegExp(
            r'<trust-anchors>[\s\S]*?<certificates\s+src="user"',
          );
          for (final m in pattern.allMatches(content)) {
            final lineNumber =
                content.substring(0, m.start).split('\n').length;
            matches.add(RuleMatch(
              lineNumber: lineNumber,
              matchedText: 'trust-anchors with user certificates',
            ));
          }
          return matches;
        },
        fileExtensions: ['.xml'],
      ),

      // 18. WebSocket without TLS
      ScanRule(
        id: 'NET006',
        category: _cat,
        severity: Severity.high,
        title: 'Unencrypted WebSocket (ws://)',
        description:
            'WebSocket using ws:// instead of wss://. Traffic is unencrypted.',
        recommendation: 'Use wss:// for all WebSocket connections.',
        pattern: RegExp(
          r'''['"`]ws://(?!localhost|127\.0\.0\.1)[^'"`\s]+['"`]''',
        ),
        fileExtensions: ['.dart'],
      ),

      // 19. Disabled SSL/TLS
      ScanRule(
        id: 'NET007',
        category: _cat,
        severity: Severity.critical,
        title: 'SSL/TLS verification bypassed',
        description:
            'SecurityContext or TLS verification explicitly disabled or bypassed.',
        recommendation: 'Never disable TLS verification in production code.',
        pattern: RegExp(
          r'(allowLegacyUnsafeRenegotiation\s*=\s*true|setTrustedCertificates.*false|onBadCertificate.*true)',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'cli_scanner'),
          RegExp(r'_test\.dart$'),
        ],
      ),

      // 20. CORS Wildcard
      ScanRule(
        id: 'NET008',
        category: _cat,
        severity: Severity.medium,
        title: 'CORS wildcard origin',
        description:
            'Access-Control-Allow-Origin set to * allows any website to make requests.',
        recommendation:
            'Restrict CORS to specific trusted origins.',
        pattern: RegExp(
          r'''Access-Control-Allow-Origin['":\s]+\*''',
        ),
        fileExtensions: ['.dart', '.json', '.yaml'],
      ),

      // 21. Proxy Trust
      ScanRule(
        id: 'NET009',
        category: _cat,
        severity: Severity.medium,
        title: 'Unconditional proxy trust',
        description:
            'Code blindly trusts proxy settings without validation.',
        recommendation:
            'Validate proxy settings and use RaspShield.checkNetworkThreats() to detect MITM.',
        pattern: RegExp(
          r"""findProxy\s*[:=]\s*\([^)]*\)\s*=>\s*['"]PROXY\s""",
        ),
        fileExtensions: ['.dart'],
      ),
    ];
