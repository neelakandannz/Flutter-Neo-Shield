import '../scan_rule.dart';
import '../severity.dart';

const _cat = 'Cryptography Weaknesses';

/// Rules for detecting cryptography weaknesses.
List<ScanRule> cryptoRules() => [
      // 48. Weak Hashing
      ScanRule(
        id: 'CRY001',
        category: _cat,
        severity: Severity.high,
        title: 'Weak hash algorithm (MD5/SHA1)',
        description:
            'MD5 or SHA-1 used for security purposes. Both are cryptographically broken.',
        recommendation:
            'Use SHA-256 or SHA-512 for integrity. Use bcrypt/Argon2 for passwords.',
        pattern: RegExp(
          r'\b(md5|sha1|MD5|SHA1)\b\s*[\.(]',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'// legacy'),
          RegExp(r'checksum'),
          RegExp(r'etag'),
          RegExp(r'_test\.dart$'),
        ],
      ),

      // 49. ECB Mode
      ScanRule(
        id: 'CRY002',
        category: _cat,
        severity: Severity.high,
        title: 'AES ECB mode detected',
        description:
            'ECB mode is deterministic — identical plaintext blocks produce identical ciphertext. Leaks patterns.',
        recommendation:
            'Use AES-GCM or AES-CBC with random IV. EncryptionShield uses secure modes by default.',
        pattern: RegExp(
          r'(AESMode\.ecb|\bECBMode\b|\bmode\s*:\s*ecb\b)',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
      ),

      // 50. Static IV/Nonce
      ScanRule(
        id: 'CRY003',
        category: _cat,
        severity: Severity.critical,
        title: 'Static/hardcoded IV or nonce',
        description:
            'Initialization vector or nonce is hardcoded. Reusing IV with same key breaks encryption.',
        recommendation:
            'Generate a random IV for each encryption operation using Random.secure().',
        pattern: RegExp(
          r'''(iv|nonce|initVector)\s*[:=]\s*['"`\[](0x)?[0-9a-fA-F,\s\dx]+['"`\]]''',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
      ),

      // 51. Weak Key Derivation
      ScanRule(
        id: 'CRY004',
        category: _cat,
        severity: Severity.high,
        title: 'Password used directly as encryption key',
        description:
            'Password used directly as key material without key derivation function.',
        recommendation:
            'Use PBKDF2, Argon2, or scrypt to derive keys from passwords.',
        pattern: RegExp(
          r'''(encrypt|cipher|aes|key)\s*[:=(]\s*['"`]?password''',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
      ),

      // 52. Insufficient Key Length
      ScanRule(
        id: 'CRY005',
        category: _cat,
        severity: Severity.medium,
        title: 'Potentially insufficient key length',
        description:
            'Key generation with insufficient key length. RSA keys should be at least 2048 bits.',
        recommendation:
            'Use AES-128+ and RSA-2048 minimum. EncryptionShield uses 256-bit keys by default.',
        pattern: RegExp(
          r'(keyLength|keySize|bits)\s*[:=]\s*(64|512|1024)\b',
        ),
        fileExtensions: ['.dart'],
      ),

      // 53. Insecure Random
      ScanRule(
        id: 'CRY006',
        category: _cat,
        severity: Severity.critical,
        title: 'Insecure random number generator for security',
        description:
            'Math Random() used for security-sensitive operations. '
            'Not cryptographically secure — output is predictable.',
        recommendation:
            'Use Random.secure() for all security-related random values.',
        customCheck: (path, content) {
          if (!path.endsWith('.dart')) return [];
          if (path.endsWith('_test.dart')) return [];
          final matches = <RuleMatch>[];
          final pattern = RegExp(r'Random\(\)');
          // UI-related context keywords (check +/- 5 lines)
          const uiKeywords = [
            'color', 'Color', 'animation', 'Animation',
            'shuffle', 'widget', 'Widget', 'paint', 'canvas',
            'random.secure', 'Random.secure',
          ];
          final lines = content.split('\n');
          for (var i = 0; i < lines.length; i++) {
            if (!pattern.hasMatch(lines[i])) continue;
            if (lines[i].contains('Random.secure')) continue;
            // Check surrounding lines for UI context
            var isUiContext = false;
            for (var j = (i - 5).clamp(0, lines.length);
                j < (i + 6).clamp(0, lines.length);
                j++) {
              final line = lines[j].toLowerCase();
              for (final kw in uiKeywords) {
                if (line.contains(kw.toLowerCase())) {
                  isUiContext = true;
                  break;
                }
              }
              if (isUiContext) break;
            }
            if (isUiContext) continue;
            matches.add(RuleMatch(
              lineNumber: i + 1,
              matchedText: lines[i].trim(),
            ));
          }
          return matches;
        },
        fileExtensions: ['.dart'],
      ),

      // 54. Custom Crypto
      ScanRule(
        id: 'CRY007',
        category: _cat,
        severity: Severity.medium,
        title: 'Custom cryptographic implementation',
        description:
            'Custom encryption/hashing implementation detected. DIY crypto is almost always broken.',
        recommendation:
            'Use established libraries (pointycastle, cryptography, encrypt) or EncryptionShield.',
        pattern: RegExp(
          r'(class\s+\w*(Cipher|Encrypt|Crypt)\w*\s*\{|\/\/\s*custom\s*(encrypt|crypt|cipher))',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'_test\.dart$'),
          RegExp(r'encryption_shield'),
          RegExp(r'string_shield'),
        ],
      ),

      // 55. Predictable Seeds
      ScanRule(
        id: 'CRY008',
        category: _cat,
        severity: Severity.high,
        title: 'Predictable random seed',
        description:
            'Random number generator initialized with fixed/predictable seed.',
        recommendation:
            'Use Random.secure() which draws from OS entropy pool. Never seed with constants.',
        pattern: RegExp(
          r'Random\(\s*\d+\s*\)',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'_test\.dart$'),
        ],
      ),
    ];
