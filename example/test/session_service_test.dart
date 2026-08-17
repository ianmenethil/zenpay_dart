/// Tests for `createSession`, which now builds the HCP Authorise launch URL
/// locally with `package:zenpay_hcp` instead of calling ZenPay.
///
/// The assertions read the query string of the URL the app is actually handed,
/// which is the artifact that matters — there is no request body to inspect
/// any more.
library;

import 'package:test/test.dart';
import 'package:zenpay_dart/zenpay_dart.dart'
    show verifyZpCallbackUrlToken, ZpCallbackUrlTokenVerified;
import 'package:zenpay_dart_example/src/checkout_state.dart';
import 'package:zenpay_dart_example/src/config.dart';
import 'package:zenpay_dart_example/src/session_service.dart';

AppConfig _config({String callbackTokenSecret = ''}) => AppConfig(
  port: 7000,
  publicBaseUrl: Uri.parse('http://localhost:7000'),
  allowedAppOrigin: 'http://localhost:3000',
  merchantAppBearerToken: 'token',
  appReturnUriWeb: Uri.parse('https://localhost:3000/'),
  checkoutStatusTtlMinutes: 60,
  zenPay: ZenPayConfig(
    hppEndpointUrl: Uri.parse('https://pay.sandbox.travelpay.com.au/Online/v5'),
    allowedCheckoutHosts: {'pay.sandbox.travelpay.com.au'},
    // createZpFingerprint rejects any credential shorter than 5 characters.
    credentials: const ZenPayCredentials(
      merchantCode: 'merchant-code',
      apiKey: 'api-key',
      username: 'username',
      password: 'password',
    ),
  ),
  callbackTokenSecret: callbackTokenSecret,
);

CreateCheckoutBody _body({
  CheckoutClient client = CheckoutClient.web,
  String orderId = 'ORDER-1',
  int? mode,
}) => CreateCheckoutBody(
  orderId: orderId,
  customerName: 'Jane',
  customerEmail: 'jane@example.com',
  client: client,
  paymentAmount: 49.90,
  mode: mode,
);

Map<String, String> _query(AppCheckoutSession session) =>
    Uri.parse(session.checkoutUrl).queryParameters;

void main() {
  test('creates a session and returns launch data', () {
    final session = createSession(
      _body(),
      'idempotency-key-0000000001',
      _config(),
      AttemptStore(),
    );

    expect(
      session.checkoutUrl,
      startsWith(
        'https://pay.sandbox.travelpay.com.au/Online/v5/merchant-code/Authorise?',
      ),
    );

    final query = _query(session);
    expect(query['__ApiKey'], 'api-key');
    expect(query['__Fingerprint'], matches(RegExp(r'^[0-9a-f]{128}$')));
    expect(query['isJsPlugin'], 'true');
    expect(query['displayMode'], '1');
    expect(query['redirectOnError'], 'true');
    expect(query['mode'], '0');
    expect(query['customerName'], 'Jane');
    expect(query['paymentAmount'], '49.9');
    expect(query['merchantUniquePaymentId'], session.merchantUniquePaymentId);
  });

  test('carries the merchantUniquePaymentId on the redirectUrl', () {
    final session = createSession(
      _body(),
      'idempotency-key-0000000002',
      _config(),
      AttemptStore(),
    );

    final redirectUrl = Uri.parse(_query(session)['redirectUrl']!);
    expect(redirectUrl.path, '/return');
    expect(
      redirectUrl.queryParameters['merchantUniquePaymentId'],
      session.merchantUniquePaymentId,
    );
  });

  test(
    'mode 1 (tokenise) omits customerName/customerReference/paymentAmount',
    () {
      final session = createSession(
        _body(mode: 1),
        'idempotency-key-0000000003',
        _config(),
        AttemptStore(),
      );

      final query = _query(session);
      expect(query['mode'], '1');
      expect(query.containsKey('customerName'), isFalse);
      expect(query.containsKey('customerReference'), isFalse);
      expect(query.containsKey('paymentAmount'), isFalse);
    },
  );

  test('mobile client returns the app-return App Link', () {
    final store = AttemptStore();
    createSession(
      _body(client: CheckoutClient.mobile),
      'idempotency-key-0000000004',
      _config(),
      store,
    );
    final attempt = store.getByIdempotencyKey('idempotency-key-0000000004')!;
    expect(
      appReturnUriFor(attempt, _config()).toString(),
      'http://localhost:7000/zenpay/app-return',
    );
  });

  test('web client returns the configured web return origin', () {
    final store = AttemptStore();
    createSession(
      _body(client: CheckoutClient.web),
      'idempotency-key-0000000005',
      _config(),
      store,
    );
    final attempt = store.getByIdempotencyKey('idempotency-key-0000000005')!;
    expect(
      appReturnUriFor(attempt, _config()).toString(),
      'https://localhost:3000/',
    );
  });

  test('replays an idempotent retry with the identical launch URL', () {
    final store = AttemptStore();
    const key = 'idempotency-key-0000000007';

    final first = createSession(_body(), key, _config(), store);
    final second = createSession(_body(), key, _config(), store);

    expect(second.merchantUniquePaymentId, first.merchantUniquePaymentId);
    // The fingerprint covers the timestamp, so a rebuilt URL would differ.
    expect(second.checkoutUrl, first.checkoutUrl);
  });

  test('omits the callback token when no secret is configured', () {
    final session = createSession(
      _body(),
      'idempotency-key-0000000006',
      _config(),
      AttemptStore(),
    );
    final callbackUrl = Uri.parse(_query(session)['callbackUrl']!);
    expect(callbackUrl.queryParameters.containsKey('t'), isFalse);
  });

  test(
    'mints a callback token that verifies to this attempt when a secret is configured',
    () {
      const secret = 'a-secret-at-least-32-bytes-long!';
      final config = _config(callbackTokenSecret: secret);
      final session = createSession(
        _body(),
        'idempotency-key-0000000009',
        config,
        AttemptStore(),
      );

      final callbackUrl = Uri.parse(_query(session)['callbackUrl']!);
      final token = callbackUrl.queryParameters['t'];
      expect(token, isNotNull);

      final result = verifyZpCallbackUrlToken(token!, secret);
      expect(result, isA<ZpCallbackUrlTokenVerified>());
      expect(
        (result as ZpCallbackUrlTokenVerified).payload.merchantUniquePaymentId,
        session.merchantUniquePaymentId,
      );
    },
  );

  test('rejects an idempotency-key reuse with a conflicting body', () {
    final store = AttemptStore();
    const key = 'idempotency-key-0000000008';
    createSession(_body(orderId: 'ORDER-1'), key, _config(), store);

    expect(
      () => createSession(_body(orderId: 'ORDER-2'), key, _config(), store),
      throwsA(isA<HttpError>().having((e) => e.statusCode, 'statusCode', 409)),
    );
  });
}
