/// Closes export drift: imports only the public barrel and references
/// every documented public symbol. If a symbol is renamed or dropped from
/// `lib/zenpay_dart.dart`, this file fails to compile.
library;

import 'package:test/test.dart';
import 'package:zenpay_dart/zenpay_dart.dart';

void main() {
  test('every documented public symbol is exported', () {
    // Enums.
    expect(ZpPluginMode.makePayment.wireValue, 0);
    expect(ZpDisplayMode.modal.wireValue, 0);
    expect(ZpUserMode.customer.wireValue, 0);
    expect(ZpOverrideFeePayer.accountDefault.wireValue, 0);
    expect(ZpPaymentStatus.pending.wireValue, 0);

    // Functions.
    expect(ZpPaymentStatus.tryFromWireValue(3)?.isSuccessful, isTrue);
    expect(createZpTimestamp(), isA<ZpTimestamp>());
    expect(createZpMupid(), isA<ZpMupid>());

    // createZpCheckoutUrl + its result type.
    final urlResult = createZpCheckoutUrl(
      ZpCheckoutUrlRequest(
        url: 'https://pay.sandbox.b2bpay.com.au/Online/v5',
        merchantCode: 'ZenTest1',
        apiKey: 'api-key-value',
        fingerprint: 'f'.padLeft(128, 'f'),
        merchantUniquePaymentId: const ZpMupid('mupid-0001'),
        timestamp: const ZpTimestamp('2026-01-15T10:30:00'),
        customerEmail: 'jane@example.com',
      ),
    );
    expect(urlResult, isA<ZpCheckoutUrlResult>());

    // Hash / fingerprint.
    expect(createSha3_512('x'), isA<String>());
    final fingerprint = createZpFingerprint(
      const ZpFingerprintRequest(
        apiKey: 'golden-api-key',
        username: 'golden-username',
        password: 'golden-password',
        mode: ZpPluginMode.makePayment,
        paymentAmount: '1.00',
        merchantUniquePaymentId: ZpMupid('golden-mupid-0001'),
        timestamp: ZpTimestamp('2026-01-01T00:00:00'),
      ),
    );
    expect(fingerprint, isA<ZpFingerprintResult>());

    // Callback types.
    final callbackResult = verifyZpCallback(
      ZpPluginMode.makePayment,
      const <String, Object?>{},
      const ZpVerifyCallbackContext(
        apiKey: 'golden-api-key',
        username: 'golden-username',
        password: 'golden-password',
        paymentAmount: '1.00',
        merchantUniquePaymentId: ZpMupid('golden-mupid-0001'),
      ),
    );
    expect(callbackResult, isA<ZpCallbackResult>());
  });
}
