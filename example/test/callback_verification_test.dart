/// Tests for `verifyCallback` (`lib/src/security.dart`) — the backend-local
/// wrapper around `package:zenpay_dart/zenpay_dart.dart`'s `verifyZpCallback`.
/// Generic hash/schema correctness now lives in the package's own test
/// suite (`packages/zenpay_hcp/test/callback_test.dart`); this file covers
/// only what the wrapper adds: the optional-`merchantUniquePaymentId`
/// cross-check, the `"malformed"`/`"rejected"` reason mapping, and
/// [CallbackFields] extraction (including that card/account-shaped
/// optional fields never reach it).
library;

import 'package:test/test.dart';
import 'package:zenpay_dart_example/src/checkout_state.dart';
import 'package:zenpay_dart_example/src/config.dart';
import 'package:zenpay_dart_example/src/security.dart';

const _credentials = ZenPayCredentials(
  merchantCode: 'code',
  apiKey: 'golden-api-key',
  username: 'golden-username',
  password: 'golden-password',
);
const _mupid = 'golden-mupid-0001';

// Pipe: apiKey|username|password|0|2550|golden-mupid-0001|golden-ref-mode0
// Digest moved unchanged from the Dart backend rewrite's independently
// computed (via Python) golden vector — see
// packages/zenpay_hcp/test/fixtures/zp_hcp_v0_1_30_vectors.json.
const _mode0Digest =
    '32b527d357f16fccc2d27e702b2a9dd809e8e4608e6c85b6ebea86187d0fbb8'
    'c19e7c28448d528121e52799c4d3ebef284100fab926ce3f1ec92c7bbec93bd78';

CheckoutAttempt _attempt({required int mode, required num amount}) =>
    CheckoutAttempt(
      merchantUniquePaymentId: _mupid,
      idempotencyKey: 'idempotency-key-1234',
      orderId: 'ORDER-10001',
      mode: mode,
      client: CheckoutClient.web,
      amount: amount,
      customerName: 'Jane',
      customerEmail: 'jane@example.com',
      createdAt: DateTime.utc(2026, 8, 1, 10),
      status: MerchantPaymentStatus.sessionCreated,
    );

Map<String, Object?> _mode0Body({
  String reference = 'golden-ref-mode0',
  String? merchantUniquePaymentId,
}) => {
  'response': {
    'merchantUniquePaymentId': ?merchantUniquePaymentId,
    'paymentReference': reference,
    'paymentStatus': 3,
  },
  'validationCode': _mode0Digest,
};

void main() {
  test('extracts CallbackFields from a correctly hashed callback', () {
    final result = verifyCallback(
      _mode0Body(merchantUniquePaymentId: _mupid),
      _attempt(mode: 0, amount: 25.50),
      _credentials,
    );
    expect(result.ok, isTrue);
    expect(result.fields!.reference, 'golden-ref-mode0');
    expect(result.fields!.statusCode, 3);
    expect(result.fields!.merchantUniquePaymentId, _mupid);
  });

  test('rejects a callback whose optional merchantUniquePaymentId disagrees '
      'with the launched attempt (backend-local cross-check)', () {
    final result = verifyCallback(
      _mode0Body(merchantUniquePaymentId: 'mupid-99999'),
      _attempt(mode: 0, amount: 25.50),
      _credentials,
    );
    expect(result.ok, isFalse);
    expect(result.reason, 'rejected');
  });

  test(
    'accepts a callback whose body omits the optional merchantUniquePaymentId',
    () {
      final result = verifyCallback(
        _mode0Body(),
        _attempt(mode: 0, amount: 25.50),
        _credentials,
      );
      expect(result.ok, isTrue);
    },
  );

  test('maps a body that fails the mode schema to reason "malformed" '
      '(server_app.dart reads this to choose HTTP 400 vs 401)', () {
    final result = verifyCallback(
      const {'nonsense': true},
      _attempt(mode: 0, amount: 25.50),
      _credentials,
    );
    expect(result.ok, isFalse);
    expect(result.reason, 'malformed');
  });

  test(
    'maps a hash mismatch (schema-valid but inauthentic) to reason "rejected"',
    () {
      final result = verifyCallback(
        _mode0Body(reference: 'PAY-999'),
        _attempt(mode: 0, amount: 25.50),
        _credentials,
      );
      expect(result.ok, isFalse);
      expect(result.reason, 'rejected');
    },
  );

  test(
    'PCI: card/account-shaped optional callback fields never reach CallbackFields',
    () {
      final body = {
        'response': {
          'merchantUniquePaymentId': _mupid,
          'paymentReference': 'golden-ref-mode0',
          'paymentStatus': 3,
          'accountOrCardNo': '4111********1111',
          'paymentCard': 'VISA',
          'customerName': 'Jane Doe',
        },
        'validationCode': _mode0Digest,
      };
      final result = verifyCallback(
        body,
        _attempt(mode: 0, amount: 25.50),
        _credentials,
      );

      expect(result.ok, isTrue);
      // CallbackFields carries only correlation/status/failure — no card,
      // account, or customer field ever reaches persisted state.
      expect(result.fields!.reference, 'golden-ref-mode0');
      expect(result.fields!.statusCode, 3);
    },
  );
}
