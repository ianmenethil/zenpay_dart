/// Tests for `createSha3_512` and `createZpFingerprint`, including golden
/// vectors computed independently of this implementation (see
/// `test/fixtures/zp_hcp_v0_1_30_vectors.json`).
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:zenpay_dart/zenpay_dart.dart';

Map<String, Object?> _loadVectors() =>
    jsonDecode(
          File('test/fixtures/zp_hcp_v0_1_30_vectors.json').readAsStringSync(),
        )
        as Map<String, Object?>;

void main() {
  final vectors = _loadVectors();

  test('createSha3_512 matches an independently computed vector', () {
    final vector = vectors['sha3512'] as Map<String, Object?>;
    expect(createSha3_512(vector['input'] as String), vector['hex']);
  });

  test(
    'createZpFingerprint matches an independently computed hash-pipe vector',
    () {
      final vector = vectors['fingerprint'] as Map<String, Object?>;
      final result = createZpFingerprint(
        ZpFingerprintRequest(
          apiKey: vector['apiKey'] as String,
          username: vector['username'] as String,
          password: vector['password'] as String,
          mode: ZpPluginMode.fromWireValue(vector['mode'] as int),
          paymentAmount: vector['paymentAmount'] as String,
          merchantUniquePaymentId: ZpMupid(
            vector['merchantUniquePaymentId'] as String,
          ),
          timestamp: ZpTimestamp(vector['timestamp'] as String),
        ),
      );
      expect(result, isA<ZpFingerprintSuccess>());
      if (result is ZpFingerprintSuccess) {
        expect(result.fingerprint, vector['fingerprintHex']);
      }
    },
  );

  ZpFingerprintRequest baseInput({
    String apiKey = 'golden-api-key',
    String username = 'golden-username',
    String password = 'golden-password',
    ZpPluginMode mode = ZpPluginMode.makePayment,
    Object paymentAmount = '49.90',
    String merchantUniquePaymentId = 'golden-mupid-0001',
    String timestamp = '2026-01-15T10:30:00',
  }) => ZpFingerprintRequest(
    apiKey: apiKey,
    username: username,
    password: password,
    mode: mode,
    paymentAmount: paymentAmount,
    merchantUniquePaymentId: ZpMupid(merchantUniquePaymentId),
    timestamp: ZpTimestamp(timestamp),
  );

  test('rejects an apiKey shorter than 5 characters', () {
    expect(
      createZpFingerprint(baseInput(apiKey: 'ab')),
      isA<ZpFingerprintFailure>(),
    );
  });

  test('validateZpFingerprintRequest returns null for a valid request', () {
    expect(validateZpFingerprintRequest(baseInput()), isNull);
  });

  test(
    'validateZpFingerprintRequest rejects the same input createZpFingerprint does',
    () {
      expect(
        validateZpFingerprintRequest(baseInput(apiKey: 'ab')),
        isA<ZpFingerprintFailure>(),
      );
    },
  );

  test('rejects a malformed timestamp', () {
    expect(
      createZpFingerprint(baseInput(timestamp: '2026-01-15')),
      isA<ZpFingerprintFailure>(),
    );
  });

  test('rejects a non-positive amount for mode 0 (Make Payment)', () {
    expect(
      createZpFingerprint(
        baseInput(mode: ZpPluginMode.makePayment, paymentAmount: '0'),
      ),
      isA<ZpFingerprintFailure>(),
    );
  });

  test('mode 2 (Custom Payment) requires a positive amount but hashes "0"', () {
    final positive = createZpFingerprint(
      baseInput(mode: ZpPluginMode.customPayment, paymentAmount: '99.99'),
    );
    expect(positive, isA<ZpFingerprintSuccess>());

    final zero = createZpFingerprint(
      baseInput(mode: ZpPluginMode.customPayment, paymentAmount: '0'),
    );
    expect(zero, isA<ZpFingerprintFailure>());
  });

  test('mode 1 (Tokenise) allows a zero amount', () {
    expect(
      createZpFingerprint(
        baseInput(mode: ZpPluginMode.tokenise, paymentAmount: '0'),
      ),
      isA<ZpFingerprintSuccess>(),
    );
  });

  test('the same inputs always produce the same fingerprint', () {
    final a = createZpFingerprint(baseInput());
    final b = createZpFingerprint(baseInput());
    expect(
      (a as ZpFingerprintSuccess).fingerprint,
      (b as ZpFingerprintSuccess).fingerprint,
    );
  });

  test('changing the timestamp changes the fingerprint', () {
    final a = createZpFingerprint(baseInput(timestamp: '2026-01-15T10:30:00'));
    final b = createZpFingerprint(baseInput(timestamp: '2026-01-15T10:30:01'));
    expect(
      (a as ZpFingerprintSuccess).fingerprint,
      isNot((b as ZpFingerprintSuccess).fingerprint),
    );
  });
}
