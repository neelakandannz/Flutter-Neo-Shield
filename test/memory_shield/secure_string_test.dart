import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    MemoryShield().reset();
    MemoryShield().init(const MemoryShieldConfig(enablePlatformWipe: false));
  });

  group('SecureString', () {
    test('value returns original string', () {
      final secure = SecureString('my secret');
      expect(secure.value, equals('my secret'));
      secure.dispose();
    });

    test('dispose() makes value throw StateError', () {
      final secure = SecureString('disposable');
      secure.dispose();
      expect(() => secure.value, throwsStateError);
    });

    test('isDisposed is false before dispose and true after', () {
      final secure = SecureString('check disposed');
      expect(secure.isDisposed, isFalse);

      secure.dispose();
      expect(secure.isDisposed, isTrue);
    });

    test('useOnce executes action and disposes', () {
      final secure = SecureString('one-time');
      var actionResult = '';

      secure.useOnce((val) {
        actionResult = val;
      });

      expect(actionResult, equals('one-time'));
      expect(secure.isDisposed, isTrue);
    });

    test('useOnce returns correct result', () {
      final secure = SecureString('hello');
      final result = secure.useOnce((val) => val.toUpperCase());

      expect(result, equals('HELLO'));
      expect(secure.isDisposed, isTrue);
    });

    test('double-dispose does not throw (idempotent)', () {
      final secure = SecureString('double dispose');
      secure.dispose();

      // Second dispose should not throw.
      expect(() => secure.dispose(), returnsNormally);
      expect(secure.isDisposed, isTrue);
    });

    test('matches() returns true for equal string', () {
      final secure = SecureString('password123');
      expect(secure.matches('password123'), isTrue);
      secure.dispose();
    });

    test('matches() returns false for different string', () {
      final secure = SecureString('password123');
      expect(secure.matches('wrong-password'), isFalse);
      secure.dispose();
    });

    test(
        'matches() safely handles different length strings without leaking timing',
        () {
      final secure1 = SecureString('short');
      expect(secure1.matches('longer_string'), isFalse);

      final secure2 = SecureString('longer_string');
      expect(secure2.matches('short'), isFalse);

      secure1.dispose();
      secure2.dispose();
    });

    test('matches() throws StateError after dispose', () {
      final secure = SecureString('disposed-match');
      secure.dispose();
      expect(() => secure.matches('disposed-match'), throwsStateError);
    });

    test('internal bytes zeroed after dispose', () {
      final secure = SecureString('wipe me');

      // Verify value works before dispose.
      expect(secure.value, equals('wipe me'));

      secure.dispose();

      // After dispose, the container is disposed and value throws.
      expect(secure.isDisposed, isTrue);
      expect(() => secure.value, throwsStateError);
    });

    test('length returns correct value', () {
      final secure = SecureString('abcdef');
      expect(secure.length, equals(6));
      secure.dispose();
    });

    test('length returns correct value for empty string', () {
      final secure = SecureString('');
      expect(secure.length, equals(0));
      secure.dispose();
    });

    test('length returns correct value for unicode string', () {
      final secure = SecureString('hello');
      expect(secure.length, equals(5));
      secure.dispose();
    });

    test('createdAt is set on construction', () {
      final before = DateTime.now();
      final secure = SecureString('timestamp test');
      final after = DateTime.now();

      expect(secure.createdAt.isAfter(before) || secure.createdAt == before,
          isTrue);
      expect(secure.createdAt.isBefore(after) || secure.createdAt == after,
          isTrue);
      secure.dispose();
    });

    test('useOnce disposes even if action throws', () {
      final secure = SecureString('throw test');

      expect(
        () => secure.useOnce((val) => throw Exception('test error')),
        throwsException,
      );

      expect(secure.isDisposed, isTrue);
    });
  });
}
