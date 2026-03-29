import '../scan_rule.dart';
import '../severity.dart';

const _cat = 'Code Quality & Injection';

/// Rules for detecting code injection vulnerabilities.
List<ScanRule> codeInjectionRules() => [
      // 56. SQL Injection
      ScanRule(
        id: 'INJ001',
        category: _cat,
        severity: Severity.critical,
        title: 'Potential SQL injection',
        description:
            'String concatenation/interpolation in SQL query. Attacker can inject SQL.',
        recommendation:
            'Use parameterized queries: db.rawQuery("SELECT * WHERE id = ?", [id])',
        pattern: RegExp(
          r'''(rawQuery|rawInsert|rawUpdate|rawDelete|execute)\s*\(\s*['"`][\s\S]{0,200}\$[{a-z]''',
          caseSensitive: false,
        ),
        fileExtensions: ['.dart'],
      ),

      // 57. XSS in WebView
      ScanRule(
        id: 'INJ002',
        category: _cat,
        severity: Severity.critical,
        title: 'Potential XSS via WebView JavaScript execution',
        description:
            'evaluateJavascript() with unsanitized input — attacker can execute arbitrary JS.',
        recommendation:
            'Sanitize all input before passing to evaluateJavascript(). Use WebViewShield.',
        pattern: RegExp(
          r'(evaluateJavascript|runJavascript|runJavaScriptReturningResult)\s*\([^)]*\$[{a-z]',
        ),
        fileExtensions: ['.dart'],
      ),

      // 58. Command Injection
      ScanRule(
        id: 'INJ003',
        category: _cat,
        severity: Severity.critical,
        title: 'Potential command injection',
        description:
            'Process.run() with user-controlled arguments can execute arbitrary commands.',
        recommendation:
            'Validate and whitelist command arguments. Never pass raw user input.',
        pattern: RegExp(
          r'Process\.(run|start)\s*\([^)]*\$[{a-z]',
        ),
        fileExtensions: ['.dart'],
      ),

      // 59. Path Traversal
      ScanRule(
        id: 'INJ004',
        category: _cat,
        severity: Severity.high,
        title: 'Potential path traversal',
        description:
            'File path constructed from user input without sanitization. '
            'Attacker can use ../ to access arbitrary files.',
        recommendation:
            'Validate and canonicalize file paths. Reject paths containing "..".',
        pattern: RegExp(
          r'(File|Directory)\s*\([^)]*\$[{a-z]',
        ),
        fileExtensions: ['.dart'],
        exclusions: [
          RegExp(r'_test\.dart$'),
          RegExp(r'path\.join'),
          RegExp(r'getApplicationDocumentsDirectory'),
        ],
      ),

      // 60. Unsafe Deserialization
      ScanRule(
        id: 'INJ005',
        category: _cat,
        severity: Severity.medium,
        title: 'Unvalidated JSON deserialization',
        description:
            'jsonDecode on untrusted input without schema validation. May cause unexpected behavior.',
        recommendation:
            'Validate JSON structure and types after decoding. Use typed model classes.',
        customCheck: (path, content) {
          if (!path.endsWith('.dart')) return [];
          final matches = <RuleMatch>[];
          final pattern = RegExp(
            r'jsonDecode\s*\(\s*(response\.body|data|input|payload|raw)',
          );
          final lines = content.split('\n');
          for (var i = 0; i < lines.length; i++) {
            if (pattern.hasMatch(lines[i])) {
              // Check surrounding context (5 lines before) for try block
              var inTryBlock = false;
              for (var j = i - 1; j >= 0 && j >= i - 5; j--) {
                if (lines[j].contains('try')) {
                  inTryBlock = true;
                  break;
                }
              }
              if (!inTryBlock) {
                matches.add(RuleMatch(
                  lineNumber: i + 1,
                  matchedText: lines[i].trim(),
                ));
              }
            }
          }
          return matches;
        },
        fileExtensions: ['.dart'],
      ),

      // 61. ReDoS
      ScanRule(
        id: 'INJ006',
        category: _cat,
        severity: Severity.medium,
        title: 'Potentially vulnerable regex (ReDoS)',
        description:
            'Regex with nested quantifiers may cause catastrophic backtracking on crafted input.',
        recommendation:
            'Avoid nested quantifiers (e.g., (a+)+). Use atomic groups or possessive quantifiers.',
        pattern: RegExp(
          r'''RegExp\s*\(\s*r?['"`][^'"`]*(\+\+|\*\+|\+\*|\*\*|\([^)]*[+*]\)[+*])''',
        ),
        fileExtensions: ['.dart'],
      ),

      // 62. Dynamic Code Execution
      ScanRule(
        id: 'INJ007',
        category: _cat,
        severity: Severity.high,
        title: 'Dynamic code execution / reflection',
        description:
            'dart:mirrors or dynamic code loading detected. Enables runtime code manipulation.',
        recommendation:
            'Avoid dart:mirrors in production. Use code generation instead.',
        pattern: RegExp(
          r'''(import\s+['"]dart:mirrors['"]|MirrorSystem|reflect\s*\(|Function\.apply)''',
        ),
        fileExtensions: ['.dart'],
      ),

      // 63. Unsafe HTML Rendering
      ScanRule(
        id: 'INJ008',
        category: _cat,
        severity: Severity.high,
        title: 'Unsafe HTML rendering with user content',
        description:
            'HTML widget rendering user-controlled content without sanitization.',
        recommendation:
            'Sanitize HTML content. Use an allowlist of safe tags and attributes.',
        pattern: RegExp(
          r'(Html|HtmlWidget|flutter_html)\s*\([^)]*data:\s*[^)]*\$[{a-z]',
        ),
        fileExtensions: ['.dart'],
      ),
    ];
