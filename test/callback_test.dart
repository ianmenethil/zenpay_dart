/// Tests for `verifyZpCallback` across all four payment modes, using golden
/// `ValidationCode` digests moved unchanged from the Dart backend rewrite's
/// `callback_verification_test.dart` (see
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
  final credentials = vectors['credentials'] as Map<String, Object?>;
  final mupid = vectors['mupid'] as String;
  final callbacks = vectors['callbacks'] as Map<String, Object?>;

  ZpVerifyCallbackContext contextFor(num amount) => ZpVerifyCallbackContext(
    apiKey: credentials['apiKey'] as String,
    username: credentials['username'] as String,
    password: credentials['password'] as String,
    paymentAmount: amount,
    merchantUniquePaymentId: ZpMupid(mupid),
  );

  group(
    'mode 0 (payment) — golden digest moved unchanged from the Dart backend rewrite',
    () {
      final vector = callbacks['mode0Payment'] as Map<String, Object?>;
      final mode = ZpPluginMode.fromWireValue(vector['mode'] as int);
      final amount = vector['paymentAmount'] as num;

      Map<String, Object?> body({String? reference, String? validationCode}) =>
          {
            'response': {
              'merchantUniquePaymentId': mupid,
              'paymentReference': reference ?? vector['reference'],
              'paymentStatus': 3,
            },
            'validationCode': validationCode ?? vector['validationCode'],
          };

      test('accepts the correctly hashed callback', () {
        final result = verifyZpCallback(mode, body(), contextFor(amount));
        expect(result, isA<ZpCallbackVerified>());
      });

      test('rejects a tampered validationCode', () {
        final result = verifyZpCallback(
          mode,
          body(validationCode: '0'.padLeft(128, '0')),
          contextFor(amount),
        );
        expect(result, isA<ZpCallbackRejected>());
      });

      test('rejects a callback whose reference was swapped', () {
        final result = verifyZpCallback(
          mode,
          body(reference: 'PAY-999'),
          contextFor(amount),
        );
        expect(result, isA<ZpCallbackRejected>());
      });

      test('rejects an amount that does not match the launched context', () {
        final result = verifyZpCallback(mode, body(), contextFor(10));
        expect(result, isA<ZpCallbackRejected>());
      });

      test(
        'reports a body that does not match the mode schema as malformed',
        () {
          final result = verifyZpCallback(mode, const {
            'nonsense': true,
          }, contextFor(amount));
          expect(result, isA<ZpCallbackMalformed>());
          if (result is ZpCallbackMalformed) {
            expect(result.message, contains('body must contain'));
          }
        },
      );

      test('surfaces business fields but never card/account-shaped ones', () {
        // Extra fields aren't part of the hash pipe, so adding them here
        // doesn't invalidate the golden validationCode above.
        final result = verifyZpCallback(mode, {
          'response': {
            'merchantUniquePaymentId': mupid,
            'paymentReference': vector['reference'],
            'paymentStatus': 3,
            'paymentStatusString': 'Successful',
            'customerReference': 'ORD-1001',
            'merchantCode': 'ZenTest1',
            'sku1': 'SKU-A',
            'sku2': 'SKU-B',
            'fundsToMerchant': 49.9,
            'settlementDate': '2026-02-01',
            'isPaymentSettledToMerchant': true,
            'additionalData': {
              'authCode': 'AUTH123',
              'rrn': 'RRN456',
              'stan': 'STAN789',
            },
            // Card/account-shaped — must never appear on the result.
            'accountOrCardNo': '4111********1111',
            'paymentCard': 'VISA',
            'cardHolderName': 'Jane Smith',
          },
          'validationCode': vector['validationCode'],
        }, contextFor(amount));

        expect(result, isA<ZpCallbackVerified>());
        final verified = result as ZpCallbackVerified;
        expect(verified.statusLabel, 'Successful');
        expect(verified.customerReference, 'ORD-1001');
        expect(verified.merchantCode, 'ZenTest1');
        expect(verified.sku1, 'SKU-A');
        expect(verified.sku2, 'SKU-B');
        expect(verified.fundsToMerchant, 49.9);
        expect(verified.settlementDate, '2026-02-01');
        expect(verified.isPaymentSettledToMerchant, isTrue);
        expect(verified.additionalData?.authCode, 'AUTH123');
        expect(verified.additionalData?.rrn, 'RRN456');
        expect(verified.additionalData?.stan, 'STAN789');
        // Preauth/tokenise-only fields stay null for a payment callback.
        expect(verified.preauthAmount, isNull);
        expect(verified.paymentDetail, isNull);
      });

      group('validateZpCallbackBody', () {
        test('returns null for a well-shaped body', () {
          expect(validateZpCallbackBody(mode, body()), isNull);
        });

        test('flags an empty reference without checking authenticity', () {
          final failure = validateZpCallbackBody(mode, body(reference: ''));
          expect(failure, isA<ZpCallbackMalformed>());
          expect(failure?.message, contains('paymentReference'));
        });

        test('flags a non-hex validationCode', () {
          final failure = validateZpCallbackBody(
            mode,
            body(validationCode: 'not-hex'),
          );
          expect(failure?.message, contains('128-character hex string'));
        });

        test('does not reject a tampered validationCode — shape only', () {
          // Unlike verifyZpCallback, shape validation never hashes: a body
          // with a wrong-but-correctly-shaped validationCode still passes.
          expect(
            validateZpCallbackBody(
              mode,
              body(validationCode: '0'.padLeft(128, '0')),
            ),
            isNull,
          );
        });

        test('reports a body missing response/validationCode as malformed', () {
          final failure = validateZpCallbackBody(mode, const {
            'nonsense': true,
          });
          expect(failure?.message, contains('body must contain'));
        });
      });
    },
  );

  test('mode 1 (tokenise) — golden digest for an amountless attempt', () {
    final vector = callbacks['mode1Tokenise'] as Map<String, Object?>;
    final mode = ZpPluginMode.fromWireValue(vector['mode'] as int);
    final result = verifyZpCallback(mode, {
      'response': {'token': vector['reference']},
      'validationCode': vector['validationCode'],
    }, contextFor(vector['paymentAmount'] as num));
    expect(result, isA<ZpCallbackVerified>());
  });

  test('mode 1 (tokenise) surfaces paymentDetail and doRedirect', () {
    final vector = callbacks['mode1Tokenise'] as Map<String, Object?>;
    final mode = ZpPluginMode.fromWireValue(vector['mode'] as int);
    final result = verifyZpCallback(mode, {
      'response': {
        'token': vector['reference'],
        'doRedirect': true,
        'paymentDetail': {
          'customerFee': 1.5,
          'merchantFee': 0.5,
          'processingAmount': 51.4,
          'paymentAmount': 49.9,
        },
      },
      'validationCode': vector['validationCode'],
    }, contextFor(vector['paymentAmount'] as num));

    expect(result, isA<ZpCallbackVerified>());
    final verified = result as ZpCallbackVerified;
    expect(verified.doRedirect, isTrue);
    expect(verified.paymentDetail?.customerFee, 1.5);
    expect(verified.paymentDetail?.merchantFee, 0.5);
    expect(verified.paymentDetail?.processingAmount, 51.4);
    expect(verified.paymentDetail?.paymentAmount, 49.9);
    // Payment/preauth-only fields stay null for a tokenise callback.
    expect(verified.sku1, isNull);
    expect(verified.preauthAmount, isNull);
  });

  test(
    'mode 2 (custom payment) — hash uses "0" but a positive context amount is still required',
    () {
      final vector = callbacks['mode2CustomPayment'] as Map<String, Object?>;
      final mode = ZpPluginMode.fromWireValue(vector['mode'] as int);
      final body = {
        'response': {
          'merchantUniquePaymentId': mupid, // needed to pass mupid check
          'paymentReference': vector['reference'],
          'paymentStatus': 3,
        },
        'validationCode': vector['validationCode'],
      };

      expect(
        verifyZpCallback(
          mode,
          body,
          contextFor(vector['paymentAmount'] as num),
        ),
        isA<ZpCallbackVerified>(),
      );
      // Preserves the installed zp-hcp@0.1.30 quirk: mode 2 always hashes
      // amount "0", but a non-positive context amount is still rejected.
      final rejected = verifyZpCallback(mode, body, contextFor(0));
      expect(rejected, isA<ZpCallbackRejected>());
    },
  );

  test('mode 3 (preauthorization) — golden digest', () {
    final vector = callbacks['mode3Preauthorization'] as Map<String, Object?>;
    final mode = ZpPluginMode.fromWireValue(vector['mode'] as int);
    final result = verifyZpCallback(mode, {
      'response': {'preauthReference': vector['reference'], 'preauthStatus': 3},
      'validationCode': vector['validationCode'],
    }, contextFor(vector['paymentAmount'] as num));
    expect(result, isA<ZpCallbackVerified>());
  });

  test('mode 3 (preauthorization) surfaces preauthAmount/preauthExpiryAt', () {
    final vector = callbacks['mode3Preauthorization'] as Map<String, Object?>;
    final mode = ZpPluginMode.fromWireValue(vector['mode'] as int);
    final result = verifyZpCallback(mode, {
      'response': {
        'preauthReference': vector['reference'],
        'preauthStatus': 3,
        'preauthStatusString': 'Held',
        'preauthAmount': 100.0,
        'preauthExpiryAt': '2026-03-01T00:00:00',
      },
      'validationCode': vector['validationCode'],
    }, contextFor(vector['paymentAmount'] as num));

    expect(result, isA<ZpCallbackVerified>());
    final verified = result as ZpCallbackVerified;
    expect(verified.statusLabel, 'Held');
    expect(verified.preauthAmount, 100.0);
    expect(verified.preauthExpiryAt, '2026-03-01T00:00:00');
    // Payment/tokenise-only fields stay null for a preauth callback.
    expect(verified.sku1, isNull);
    expect(verified.paymentDetail, isNull);
  });

  test(
    'PCI: card/account-shaped optional callback fields do not affect verification',
    () {
      final vector = callbacks['mode0Payment'] as Map<String, Object?>;
      final mode = ZpPluginMode.fromWireValue(vector['mode'] as int);
      final result = verifyZpCallback(mode, {
        'response': {
          'merchantUniquePaymentId': mupid,
          'paymentReference': vector['reference'],
          'paymentStatus': 3,
          'accountOrCardNo': '4111********1111',
          'paymentCard': 'VISA',
          'customerName': 'Jane Doe',
        },
        'validationCode': vector['validationCode'],
      }, contextFor(vector['paymentAmount'] as num));
      // ZpCallbackResult carries only validity + message — no card, account,
      // or customer field is ever readable from the result.
      expect(result, isA<ZpCallbackVerified>());
    },
  );

  test('rejects credentials shorter than 5 characters', () {
    final vector = callbacks['mode0Payment'] as Map<String, Object?>;
    final mode = ZpPluginMode.fromWireValue(vector['mode'] as int);
    final result = verifyZpCallback(
      mode,
      {
        'response': {
          'merchantUniquePaymentId': mupid,
          'paymentReference': vector['reference'],
        },
        'validationCode': vector['validationCode'],
      },
      const ZpVerifyCallbackContext(
        apiKey: 'ab',
        username: 'golden-username',
        password: 'golden-password',
        paymentAmount: 25.5,
        merchantUniquePaymentId: ZpMupid('golden-mupid-0001'),
      ),
    );
    expect(result, isA<ZpCallbackRejected>());
  });
}
