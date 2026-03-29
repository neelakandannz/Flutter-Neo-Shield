import '../scan_rule.dart';
import '../severity.dart';

const _cat = 'Insecure Data Storage';

/// Rules for detecting insecure data storage patterns.
List<ScanRule> insecureStorageRules() => [
      // 22. SharedPreferences for Secrets
      ScanRule(
        id: 'STO001',
        category: _cat,
        severity: Severity.high,
        title: 'Sensitive data in SharedPreferences',
        description:
            'Tokens, passwords, or keys stored in SharedPreferences which is unencrypted plaintext.',
        recommendation:
            'Use SecureStorageShield for sensitive data (Keychain/Keystore-backed).',
        pattern: RegExp(
          r'SharedPreferences[\s\S]{0,100}(setString|setInt)[\s\S]{0,80}(token|password|secret|key|session|auth|credential|api_key|refresh)',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
      ),

      // 23. Unencrypted SQLite
      ScanRule(
        id: 'STO002',
        category: _cat,
        severity: Severity.high,
        title: 'Unencrypted SQLite database',
        description:
            'SQLite/sqflite used without encryption. Database files are readable on rooted devices.',
        recommendation:
            'Use sqflite_sqlcipher or encrypt sensitive columns with EncryptionShield.',
        pattern: RegExp(
          r'(openDatabase|getDatabasesPath|databaseFactory)\s*\(',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'sqlcipher'),
          RegExp(r'encrypted'),
          RegExp(r'cipher'),
        ],
      ),

      // 24. Unencrypted File Storage
      ScanRule(
        id: 'STO003',
        category: _cat,
        severity: Severity.high,
        title: 'Sensitive data written to plain file',
        description:
            'Secrets written to filesystem without encryption.',
        recommendation:
            'Encrypt data with EncryptionShield before writing to files.',
        pattern: RegExp(
          r'(writeAsString|writeAsBytes|writeString)\s*\([^)]*?(token|password|secret|key|session|credential)',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
      ),

      // 25. Hive without Encryption
      ScanRule(
        id: 'STO004',
        category: _cat,
        severity: Severity.medium,
        title: 'Hive box without encryption',
        description:
            'Hive.openBox() called without encryptionCipher. Data stored in plaintext.',
        recommendation:
            'Use Hive.openBox(encryptionCipher: HiveAesCipher(key)) for sensitive data.',
        pattern: RegExp(
          r'Hive\.openBox\s*[<(]',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'encryptionCipher'),
        ],
      ),

      // 26. GetStorage / MMKV without Encryption
      ScanRule(
        id: 'STO005',
        category: _cat,
        severity: Severity.medium,
        title: 'Unencrypted key-value storage',
        description:
            'GetStorage or MMKV used without encryption for potentially sensitive data.',
        recommendation:
            'Use SecureStorageShield or enable encryption for sensitive key-value pairs.',
        pattern: RegExp(
          r'(GetStorage|MMKV)\s*\(',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'encrypt'),
          RegExp(r'CryptKey'),
        ],
      ),

      // 27. Web LocalStorage/SessionStorage
      ScanRule(
        id: 'STO006',
        category: _cat,
        severity: Severity.high,
        title: 'Sensitive data in web storage',
        description:
            'localStorage/sessionStorage used for sensitive data. Accessible via XSS.',
        recommendation:
            'Use httpOnly cookies or in-memory storage for sensitive web data.',
        pattern: RegExp(
          r'''(localStorage|sessionStorage)\.(setItem|getItem)\s*\(\s*['"`](token|password|secret|key|session|auth|credential|api)''',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart', '.js'],
      ),

      // 28. Cache Directory Secrets
      ScanRule(
        id: 'STO007',
        category: _cat,
        severity: Severity.medium,
        title: 'Sensitive data in cache/temp directory',
        description:
            'Sensitive data written to cache or temp directories which may not be encrypted.',
        recommendation:
            'Avoid storing secrets in cache. Use SecureStorageShield instead.',
        pattern: RegExp(
          r'(getTemporaryDirectory|getCacheDirectory|getApplicationCacheDirectory)\(\)[\s\S]{0,200}(token|password|secret|key|session|credential)',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
      ),

      // 29. Logging Sensitive Data
      ScanRule(
        id: 'STO008',
        category: _cat,
        severity: Severity.high,
        title: 'Sensitive data in print/log statement',
        description:
            'print() or debugPrint() used with potentially sensitive data. Use LogShield.',
        recommendation:
            'Replace print() with shieldLog() to auto-redact PII in release builds.',
        pattern: RegExp(
          r'''(print|debugPrint|log)\s*\([^)]*?(password|token|secret|apiKey|api_key|credential|ssn|creditCard)[^)]*\)''',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'shieldLog'),
          RegExp(r'LogShield'),
          RegExp(r'_test\.dart$'),
        ],
      ),

      // 30. Secrets in Assets
      ScanRule(
        id: 'STO009',
        category: _cat,
        severity: Severity.high,
        title: 'Potential secrets in asset files',
        description:
            '.env files, credential files, or config files with secrets bundled in assets.',
        recommendation:
            'Never bundle secret-containing files in assets. Use runtime config.',
        customCheck: (path, content) {
          final matches = <RuleMatch>[];
          if (path.contains('assets/') || path.contains('assets\\')) {
            if (path.endsWith('.env') ||
                path.endsWith('credentials.json') ||
                path.endsWith('service-account.json') ||
                path.endsWith('.key') ||
                path.endsWith('.pem')) {
              matches.add(RuleMatch(
                lineNumber: 1,
                matchedText: 'Sensitive file in assets: $path',
              ));
            }
          }
          return matches;
        },
        fileExtensions: ['.env', '.json', '.key', '.pem'],
      ),
    ];
