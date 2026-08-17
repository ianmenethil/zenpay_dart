/// Tests for `createZpCallbackUrlToken`/`verifyZpCallbackUrlToken`,
/// including an independently computed HMAC-SHA3-512 vector (see
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
  final tokenVector = vectors['callbackToken'] as Map<String, Object?>;
  final secret = tokenVector['secret'] as String;

  test(
    'verifies a token whose HMAC-SHA3-512 signature was computed independently',
    () {
      final result = verifyZpCallbackUrlToken(
        tokenVector['token'] as String,
        secret,
      );
      expect(result.ok, isTrue);
      final decoded = tokenVector['decodedPayload'] as Map<String, Object?>;
      expect(
        result.payload!.mode,
        ZpPluginMode.fromWireValue(decoded['mode'] as int),
      );
      expect(
        result.payload!.merchantUniquePaymentId,
        decoded['merchantUniquePaymentId'],
      );
      expect(result.payload!.timestamp, decoded['timestamp']);
    },
  );

  test('create then verify round-trips the payload', () {
    const payload = ZpCallbackUrlTokenPayload(
      mode: ZpPluginMode.tokenise,
      merchantUniquePaymentId: 'mupid-0002',
      timestamp: '2026-02-01T09:00:00',
      extra: {'orderId': 'ORD-42'},
    );
    final token = createZpCallbackUrlToken(payload, secret);
    final result = verifyZpCallbackUrlToken(token, secret);

    expect(result.ok, isTrue);
    expect(result.payload!.mode, ZpPluginMode.tokenise);
    expect(result.payload!.merchantUniquePaymentId, 'mupid-0002');
    expect(result.payload!.timestamp, '2026-02-01T09:00:00');
    expect(result.payload!.extra['orderId'], 'ORD-42');
  });

  test('round-trips an optional paymentAmount', () {
    const payload = ZpCallbackUrlTokenPayload(
      mode: ZpPluginMode.makePayment,
      merchantUniquePaymentId: 'mupid-0003',
      timestamp: '2026-02-01T09:00:00',
      paymentAmount: '49.90',
    );
    final token = createZpCallbackUrlToken(payload, secret);
    final result = verifyZpCallbackUrlToken(token, secret);
    expect(result.payload!.paymentAmount, '49.90');
  });

  test('rejects a token verified with the wrong secret', () {
    const payload = ZpCallbackUrlTokenPayload(
      mode: ZpPluginMode.makePayment,
      merchantUniquePaymentId: 'mupid-0004',
      timestamp: '2026-02-01T09:00:00',
    );
    final token = createZpCallbackUrlToken(payload, secret);
    final result = verifyZpCallbackUrlToken(token, 'b'.padLeft(32, 'b'));
    expect(result.ok, isFalse);
    expect(result.reason, ZpCallbackUrlTokenFailureReason.badSignature);
  });

  test('rejects a token with a single flipped signature character', () {
    const payload = ZpCallbackUrlTokenPayload(
      mode: ZpPluginMode.makePayment,
      merchantUniquePaymentId: 'mupid-0005',
      timestamp: '2026-02-01T09:00:00',
    );
    final token = createZpCallbackUrlToken(payload, secret);
    final flipped =
        token.substring(0, token.length - 1) +
        (token[token.length - 1] == 'A' ? 'B' : 'A');
    final result = verifyZpCallbackUrlToken(flipped, secret);
    expect(result.ok, isFalse);
    expect(result.reason, ZpCallbackUrlTokenFailureReason.badSignature);
  });

  test('rejects a malformed (too-short) token', () {
    final result = verifyZpCallbackUrlToken('short', secret);
    expect(result.ok, isFalse);
    expect(result.reason, ZpCallbackUrlTokenFailureReason.malformed);
  });

  test('rejects an expired token', () {
    const payload = ZpCallbackUrlTokenPayload(
      mode: ZpPluginMode.makePayment,
      merchantUniquePaymentId: 'mupid-0006',
      timestamp: '2026-02-01T09:00:00',
    );
    final token = createZpCallbackUrlToken(
      payload,
      secret,
      const ZpCallbackUrlTokenOptions(expiresInSeconds: -1),
    );
    final result = verifyZpCallbackUrlToken(token, secret);
    expect(result.ok, isFalse);
    expect(result.reason, ZpCallbackUrlTokenFailureReason.expired);
  });

  test('a token with no expiresInSeconds never expires', () {
    const payload = ZpCallbackUrlTokenPayload(
      mode: ZpPluginMode.makePayment,
      merchantUniquePaymentId: 'mupid-0007',
      timestamp: '2026-02-01T09:00:00',
    );
    final token = createZpCallbackUrlToken(payload, secret);
    expect(verifyZpCallbackUrlToken(token, secret).ok, isTrue);
  });

  test('throws RangeError for a secret shorter than 32 bytes', () {
    const payload = ZpCallbackUrlTokenPayload(
      mode: ZpPluginMode.makePayment,
      merchantUniquePaymentId: 'mupid-0008',
      timestamp: '2026-02-01T09:00:00',
    );
    expect(
      () => createZpCallbackUrlToken(payload, 'too-short'),
      throwsRangeError,
    );
  });

  test('throws ArgumentError for a malformed timestamp', () {
    const payload = ZpCallbackUrlTokenPayload(
      mode: ZpPluginMode.makePayment,
      merchantUniquePaymentId: 'mupid-0009',
      timestamp: 'not-a-timestamp',
    );
    expect(
      () => createZpCallbackUrlToken(payload, secret),
      throwsArgumentError,
    );
  });

  test(
    'throws ArgumentError for a paymentAmount that is not a String or num',
    () {
      const payload = ZpCallbackUrlTokenPayload(
        mode: ZpPluginMode.makePayment,
        merchantUniquePaymentId: 'mupid-0010',
        timestamp: '2026-02-01T09:00:00',
        paymentAmount: {'amount': 1},
      );
      expect(
        () => createZpCallbackUrlToken(payload, secret),
        throwsArgumentError,
      );
    },
  );
}
