import 'package:test/test.dart';
import 'package:zenpay_dart_example/src/config.dart';
import 'package:zenpay_dart_example/src/session_service.dart';

AppConfig _configWithHosts(Set<String> hosts) => AppConfig(
  port: 7000,
  publicBaseUrl: Uri.parse('http://localhost:7000'),
  allowedAppOrigin: 'http://localhost:3000',
  merchantAppBearerToken: 'token',
  appReturnUriWeb: Uri.parse('https://localhost:3000/'),
  checkoutStatusTtlMinutes: 60,
  zenPay: ZenPayConfig(
    hppEndpointUrl: Uri.parse('https://pay.sandbox.travelpay.com.au/Online/v5'),
    allowedCheckoutHosts: hosts,
    credentials: const ZenPayCredentials(
      merchantCode: 'code',
      apiKey: 'key',
      username: 'user',
      password: 'pass',
    ),
  ),
);

void main() {
  final config = _configWithHosts({'pay.sandbox.travelpay.com.au'});
  const endpointUrl =
      'https://pay.sandbox.travelpay.com.au/Online/Session/abc123';

  test('returns endpointUrl unchanged', () {
    expect(resolveCheckoutUrl(endpointUrl, config).toString(), endpointUrl);
  });

  test('does not append secureToken in any form', () {
    final result = resolveCheckoutUrl(endpointUrl, config);
    expect(result.queryParameters.containsKey('secureToken'), isFalse);
  });

  test('rejects a non-HTTPS endpoint', () {
    expect(
      () => resolveCheckoutUrl(
        'http://pay.sandbox.travelpay.com.au/Online/Session',
        config,
      ),
      throwsA(
        isA<ZenPaySessionException>().having(
          (e) => e.code,
          'code',
          'ZENPAY_SESSION_ENDPOINT_NOT_HTTPS',
        ),
      ),
    );
  });

  test('rejects a host outside the allowlist', () {
    expect(
      () => resolveCheckoutUrl('https://evil.example/Session', config),
      throwsA(
        isA<ZenPaySessionException>().having(
          (e) => e.code,
          'code',
          'ZENPAY_RESOLVED_CHECKOUT_URL_NOT_ALLOWED',
        ),
      ),
    );
  });
}
