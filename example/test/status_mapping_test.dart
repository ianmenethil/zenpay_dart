import 'package:test/test.dart';
import 'package:zenpay_reference_backend/src/checkout_state.dart';

void main() {
  test('maps documented ZenPay status codes', () {
    expect(mapZenPayStatus(0), MerchantPaymentStatus.pending);
    expect(mapZenPayStatus(1), MerchantPaymentStatus.error);
    expect(mapZenPayStatus(3), MerchantPaymentStatus.successful);
    expect(mapZenPayStatus(4), MerchantPaymentStatus.failed);
    expect(mapZenPayStatus(5), MerchantPaymentStatus.cancelled);
    expect(mapZenPayStatus(6), MerchantPaymentStatus.error);
    expect(mapZenPayStatus(7), MerchantPaymentStatus.pending);
    expect(mapZenPayStatus(999), MerchantPaymentStatus.unknown);
  });
}
