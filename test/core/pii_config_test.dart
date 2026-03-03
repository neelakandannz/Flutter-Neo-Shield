import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('ShieldConfig', () {
    group('Default config', () {
      test('enabledTypes is empty by default', () {
        const config = ShieldConfig();
        expect(config.enabledTypes, isEmpty);
      });

      test('allTypesEnabled is true when enabledTypes is empty', () {
        const config = ShieldConfig();
        expect(config.allTypesEnabled, isTrue);
      });

      test('isTypeEnabled returns true for any type when enabledTypes is empty',
          () {
        const config = ShieldConfig();
        for (final type in PIIType.values) {
          expect(config.isTypeEnabled(type), isTrue);
        }
      });

      test('silentInRelease defaults to true', () {
        const config = ShieldConfig();
        expect(config.silentInRelease, isTrue);
      });

      test('enableReporting defaults to false', () {
        const config = ShieldConfig();
        expect(config.enableReporting, isFalse);
      });

      test('customReplacements defaults to empty map', () {
        const config = ShieldConfig();
        expect(config.customReplacements, isEmpty);
      });

      test('customPatterns defaults to empty list', () {
        const config = ShieldConfig();
        expect(config.customPatterns, isEmpty);
      });

      test('sensitiveNames defaults to empty set', () {
        const config = ShieldConfig();
        expect(config.sensitiveNames, isEmpty);
      });
    });

    group('copyWith', () {
      test('produces correct new config with overridden fields', () {
        const original = ShieldConfig();
        final updated = original.copyWith(
          enabledTypes: {PIIType.email, PIIType.phone},
          enableReporting: true,
          silentInRelease: false,
        );
        expect(updated.enabledTypes, {PIIType.email, PIIType.phone});
        expect(updated.enableReporting, isTrue);
        expect(updated.silentInRelease, isFalse);
      });

      test('preserves unmodified fields', () {
        const original = ShieldConfig(
          enabledTypes: {PIIType.ssn},
          enableReporting: true,
        );
        final updated = original.copyWith(silentInRelease: false);
        expect(updated.enabledTypes, {PIIType.ssn});
        expect(updated.enableReporting, isTrue);
        expect(updated.silentInRelease, isFalse);
      });

      test('copyWith with no arguments returns equivalent config', () {
        const original = ShieldConfig(
          enabledTypes: {PIIType.email},
          enableReporting: true,
        );
        final copy = original.copyWith();
        expect(copy.enabledTypes, original.enabledTypes);
        expect(copy.enableReporting, original.enableReporting);
        expect(copy.silentInRelease, original.silentInRelease);
        expect(copy.customReplacements, original.customReplacements);
        expect(copy.customPatterns, original.customPatterns);
        expect(copy.sensitiveNames, original.sensitiveNames);
      });

      test('copyWith custom replacements', () {
        const original = ShieldConfig();
        final updated = original.copyWith(
          customReplacements: {PIIType.email: '[REMOVED]'},
        );
        expect(updated.customReplacements[PIIType.email], '[REMOVED]');
      });
    });

    group('enabledTypes filtering', () {
      test('isTypeEnabled returns false for non-enabled types', () {
        const config = ShieldConfig(
          enabledTypes: {PIIType.email},
        );
        expect(config.isTypeEnabled(PIIType.email), isTrue);
        expect(config.isTypeEnabled(PIIType.phone), isFalse);
        expect(config.isTypeEnabled(PIIType.ssn), isFalse);
        expect(config.isTypeEnabled(PIIType.creditCard), isFalse);
      });

      test('allTypesEnabled is false when specific types are set', () {
        const config = ShieldConfig(
          enabledTypes: {PIIType.email},
        );
        expect(config.allTypesEnabled, isFalse);
      });

      test('isTypeEnabled returns true for all explicitly enabled types', () {
        const config = ShieldConfig(
          enabledTypes: {PIIType.email, PIIType.phone, PIIType.ssn},
        );
        expect(config.isTypeEnabled(PIIType.email), isTrue);
        expect(config.isTypeEnabled(PIIType.phone), isTrue);
        expect(config.isTypeEnabled(PIIType.ssn), isTrue);
        expect(config.isTypeEnabled(PIIType.ipAddress), isFalse);
      });
    });

    group('Custom replacements', () {
      test('stores custom replacements correctly', () {
        const config = ShieldConfig(
          customReplacements: {
            PIIType.email: '[REMOVED]',
            PIIType.phone: '[PHONE REMOVED]',
          },
        );
        expect(config.customReplacements[PIIType.email], '[REMOVED]');
        expect(config.customReplacements[PIIType.phone], '[PHONE REMOVED]');
        expect(config.customReplacements[PIIType.ssn], isNull);
      });
    });
  });
}
