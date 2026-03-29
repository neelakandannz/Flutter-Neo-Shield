import 'dart:convert';

import '../scan_result.dart';
import 'reporter.dart';

/// Machine-readable JSON reporter.
class JsonReporter extends Reporter {
  @override
  String format(ScanResult result) {
    const encoder = JsonEncoder.withIndent('  ');
    return encoder.convert(result.toJson());
  }
}
