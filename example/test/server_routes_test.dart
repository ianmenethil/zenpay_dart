/// HTTP-layer tests for the reference backend.
///
/// Drives the real Shelf handler over real loopback HTTP. Nothing here calls
/// ZenPay: the backend no longer makes an outbound request at launch time.
library;

import 'dart:convert';
import 'dart:io';

import 'package:hashlib/hashlib.dart';
import 'package:http/http.dart' as http;
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:test/test.dart';
import 'package:zenpay_dart/zenpay_dart.dart'
    show
        ZpCallbackUrlTokenOptions,
        ZpCallbackUrlTokenPayload,
        ZpPluginMode,
        createZpCallbackUrlToken;
import 'package:zenpay_reference_backend/src/checkout_state.dart';
import 'package:zenpay_reference_backend/src/config.dart';
import 'package:zenpay_reference_backend/src/rate_limiter.dart';
import 'package:zenpay_reference_backend/src/server_app.dart';

const _token = 'test-bearer-token-value';
const _apiKey = 'test-api-key';
const _username = 'test-username';
const _password = 'test-password';
const _callbackTokenSecret = 'a-secret-at-least-32-bytes-long!';

AppConfig _config({String callbackTokenSecret = _callbackTokenSecret}) =>
    AppConfig(
      port: 0,
      publicBaseUrl: Uri.parse('http://127.0.0.1:7099'),
      allowedAppOrigin: 'http://localhost:3000',
      merchantAppBearerToken: _token,
      appReturnUriWeb: Uri.parse('https://localhost:3000/'),
      checkoutStatusTtlMinutes: 60,
      zenPay: ZenPayConfig(
        hppEndpointUrl: Uri.parse(
          'https://pay.sandbox.travelpay.com.au/Online/v5',
        ),
        allowedCheckoutHosts: {'pay.sandbox.travelpay.com.au'},
        credentials: const ZenPayCredentials(
          merchantCode: 'merchant-code',
          apiKey: _apiKey,
          username: _username,
          password: _password,
        ),
      ),
      callbackTokenSecret: callbackTokenSecret,
    );

CheckoutAttempt _attempt({
  String merchantUniquePaymentId = 'att-lookup',
  CheckoutClient client = CheckoutClient.mobile,
  int mode = 0,
  num amount = 49.90,
  MerchantPaymentStatus status = MerchantPaymentStatus.created,
  DateTime? createdAt,
}) => CheckoutAttempt(
  merchantUniquePaymentId: merchantUniquePaymentId,
  idempotencyKey: 'idempotency-key-$merchantUniquePaymentId',
  orderId: 'ORDER-$merchantUniquePaymentId',
  mode: mode,
  client: client,
  amount: amount,
  customerName: 'Test User',
  customerEmail: 'test@example.com',
  createdAt: createdAt ?? DateTime.now().toUtc(),
  status: status,
);

String _sign(int mode, String amountField, String mupid, String reference) =>
    sha3_512
        .string(
          [
            _apiKey,
            _username,
            _password,
            mode.toString(),
            amountField,
            mupid,
            reference,
          ].join('|'),
        )
        .hex();

void main() {
  late HttpServer server;
  late String base;
  late AttemptStore store;
  late AppConfig config;

  setUp(() async {
    config = _config();
    store = AttemptStore();
    server = await shelf_io.serve(
      buildHandler(config, store),
      InternetAddress.loopbackIPv4,
      0,
    );
    base = 'http://127.0.0.1:${server.port}';
  });

  tearDown(() async {
    await server.close(force: true);
  });

  Future<http.Response> call(
    String path, {
    String method = 'GET',
    Map<String, String>? headers,
    Object? body,
  }) async {
    final request = http.Request(method, Uri.parse('$base$path'));
    if (headers != null) request.headers.addAll(headers);
    if (body != null) request.body = body is String ? body : jsonEncode(body);
    return http.Response.fromStream(await request.send());
  }

  group('routing', () {
    test('serves health', () async {
      final response = await call('/api/v1/health');
      expect(response.statusCode, 200);
      expect((jsonDecode(response.body) as Map<String, Object?>)['ok'], true);
    });

    test('serves browser test page at /', () async {
      final response = await call('/');
      expect(response.statusCode, 200);
      expect(response.headers['content-type'], contains('text/html'));
      expect(response.body, contains('ZenPay Reference Backend Test'));
      expect(response.body, contains('Create Test Checkout'));
    });

    test('rejects an unknown path', () async {
      final response = await call('/not-a-route');
      expect(response.statusCode, 404);
      expect(jsonDecode(response.body), {'error': 'NOT_FOUND'});
    });

    test('reaches the status route and parses the payment id', () async {
      final response = await call(
        '/api/v1/sessions/11111111-2222-3333-4444-555555555555',
        headers: {'authorization': 'Bearer $_token'},
      );
      expect(response.statusCode, 404);
      expect(jsonDecode(response.body), {'error': 'CHECKOUT_NOT_FOUND'});
    });

    test('answers CORS preflight with the configured origin', () async {
      final response = await call('/api/v1/health', method: 'OPTIONS');
      expect(response.statusCode, 204);
      expect(
        response.headers['access-control-allow-origin'],
        'http://localhost:3000',
      );
    });
  });

  group('authorization', () {
    test('rejects a create with no credentials', () async {
      final response = await call(
        '/api/v1/sessions',
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: '{}',
      );
      expect(response.statusCode, 401);
    });

    test('rejects a create with the wrong token', () async {
      final response = await call(
        '/api/v1/sessions',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'authorization': 'Bearer not-the-token',
        },
        body: '{}',
      );
      expect(response.statusCode, 401);
    });

    test('rejects a status lookup with no credentials', () async {
      expect((await call('/api/v1/sessions/anything')).statusCode, 401);
    });
  });

  group('create-session request validation', () {
    Map<String, String> auth() => {
      'content-type': 'application/json',
      'authorization': 'Bearer $_token',
      'idempotency-key': 'idempotency-key-validation-0001',
    };

    test('rejects a content-type that is not application/json', () async {
      final response = await call(
        '/api/v1/sessions',
        method: 'POST',
        headers: {
          'authorization': 'Bearer $_token',
          'idempotency-key': 'idempotency-key-validation-0002',
        },
        body: '{}',
      );
      expect(response.statusCode, 415);
    });

    test('rejects an unknown field', () async {
      final response = await call(
        '/api/v1/sessions',
        method: 'POST',
        headers: auth(),
        body: {
          'orderId': 'O-1',
          'customerName': 'Jane',
          'customerEmail': 'jane@example.com',
          'client': 'web',
          'paymentAmount': 10,
          'notAllowed': true,
        },
      );
      expect(response.statusCode, 400);
      expect(jsonDecode(response.body), {'error': 'UNKNOWN_CHECKOUT_FIELD'});
    });

    test('rejects a body over 64 KiB', () async {
      final response = await call(
        '/api/v1/sessions',
        method: 'POST',
        headers: auth(),
        body: jsonEncode({'padding': 'x' * (65 * 1024)}),
      );
      expect(response.statusCode, 413);
    });

    test('rejects an idempotency key that is too short', () async {
      final response = await call(
        '/api/v1/sessions',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'authorization': 'Bearer $_token',
          'idempotency-key': 'short',
        },
        body: '{}',
      );
      expect(response.statusCode, 400);
      expect(jsonDecode(response.body), {'error': 'INVALID_IDEMPOTENCY_KEY'});
    });
  });

  group('status lookup', () {
    const merchantUniquePaymentId = 'att-lookup';

    setUp(() {
      store.create(_attempt(merchantUniquePaymentId: merchantUniquePaymentId));
    });

    test('returns 200 for a known attempt', () async {
      final response = await call(
        '/api/v1/sessions/$merchantUniquePaymentId',
        headers: {'authorization': 'Bearer $_token'},
      );
      expect(response.statusCode, 200);
      expect(
        (jsonDecode(response.body)
            as Map<String, Object?>)['merchantUniquePaymentId'],
        merchantUniquePaymentId,
      );
    });

    test('rejects an unknown merchantUniquePaymentId with 404', () async {
      final response = await call(
        '/api/v1/sessions/no-such-attempt',
        headers: {'authorization': 'Bearer $_token'},
      );
      expect(response.statusCode, 404);
      expect(jsonDecode(response.body), {'error': 'CHECKOUT_NOT_FOUND'});
    });
  });

  group('return broker', () {
    test('requires the merchant payment id', () async {
      final response = await call('/return');
      expect(response.statusCode, 400);
      expect(jsonDecode(response.body), {
        'error': 'RETURN_CORRELATION_REQUIRED',
      });
    });

    test('requires the merchant payment id to match a known attempt', () async {
      final response = await call('/return?merchantUniquePaymentId=unknown');
      expect(response.statusCode, 400);
      expect(jsonDecode(response.body), {
        'error': 'RETURN_CORRELATION_INVALID',
      });
    });

    test('redirects a mobile attempt to the app-return App Link', () async {
      store.create(
        _attempt(
          merchantUniquePaymentId: 'att-return-mobile',
          client: CheckoutClient.mobile,
        ),
      );
      final request = http.Request(
        'GET',
        Uri.parse('$base/return?merchantUniquePaymentId=att-return-mobile'),
      )..followRedirects = false;
      final response = await http.Response.fromStream(await request.send());
      expect(response.statusCode, 303);
      expect(response.headers['location'], contains('/zenpay/app-return'));
    });
  });

  group('frame return page', () {
    test(
      'posts the correlation values to the fixed origin, never "*"',
      () async {
        store.create(
          _attempt(
            merchantUniquePaymentId: 'att-frame-1',
            client: CheckoutClient.webFrame,
          ),
        );
        final response = await call(
          '/return?merchantUniquePaymentId=att-frame-1',
        );

        expect(response.statusCode, 200);
        expect(response.headers['content-type'], contains('text/html'));
        expect(response.body, contains('parent.postMessage'));
        expect(response.body, contains('"att-frame-1"'));
        expect(response.body, contains('"http://localhost:3000"'));
        expect(response.body, isNot(contains("'*'")));
      },
    );

    test(
      "escapes '<' so an attempt value cannot close the script element",
      () async {
        const trickyId = '</script><img src=x>';
        store.create(
          _attempt(
            merchantUniquePaymentId: trickyId,
            client: CheckoutClient.webFrame,
          ),
        );
        final response = await call(
          '/return?merchantUniquePaymentId=${Uri.encodeQueryComponent(trickyId)}',
        );

        expect(response.body.split('</script>').length, 2);
        expect(response.body, isNot(contains('"</script><img src=x>"')));
        expect(response.body, contains(r'</script>'));
      },
    );
  });

  group('callback', () {
    test('rejects a body with no merchant payment id', () async {
      final response = await call(
        '/api/v1/callbacks',
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: {'response': <String, Object?>{}},
      );
      expect(response.statusCode, 400);
      expect(jsonDecode(response.body), {
        'error': 'CALLBACK_MERCHANT_PAYMENT_ID_REQUIRED',
      });
    });

    test('does not accept a callback for an unknown payment', () async {
      final response = await call(
        '/api/v1/callbacks',
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: {
          'response': {'merchantUniquePaymentId': 'no-such-payment'},
        },
      );
      expect(response.statusCode, 404);
      expect(jsonDecode(response.body), {
        'error': 'CALLBACK_ATTEMPT_NOT_FOUND',
      });
    });

    test('verifies a correctly signed callback and updates status', () async {
      store.create(
        _attempt(merchantUniquePaymentId: 'att-cb-1', mode: 0, amount: 25.50),
      );
      const mupid = 'att-cb-1';
      final digest = _sign(0, '2550', mupid, 'PAY-1');

      final response = await call(
        '/api/v1/callbacks',
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: {
          'response': {
            'merchantUniquePaymentId': mupid,
            'paymentReference': 'PAY-1',
            'paymentStatus': 3,
          },
          'validationCode': digest,
        },
      );
      expect(response.statusCode, 200);

      final status = await call(
        '/api/v1/sessions/att-cb-1',
        headers: {'authorization': 'Bearer $_token'},
      );
      final body = jsonDecode(status.body) as Map<String, Object?>;
      expect(body['paymentReference'], 'PAY-1');
      expect(body['callbackVerified'], true);
    });

    test(
      'accepts a correctly signed callback carrying a valid callback token',
      () async {
        store.create(
          _attempt(
            merchantUniquePaymentId: 'att-cb-token-ok',
            mode: 0,
            amount: 25.50,
          ),
        );
        const mupid = 'att-cb-token-ok';
        final digest = _sign(0, '2550', mupid, 'PAY-TOKEN-OK');
        final token = createZpCallbackUrlToken(
          ZpCallbackUrlTokenPayload(
            mode: ZpPluginMode.makePayment,
            merchantUniquePaymentId: mupid,
            timestamp: '2026-01-01T00:00:00',
            paymentAmount: 25.50,
          ),
          _callbackTokenSecret,
          const ZpCallbackUrlTokenOptions(expiresInSeconds: 3600),
        );

        final response = await call(
          '/api/v1/callbacks?t=$token',
          method: 'POST',
          headers: {'content-type': 'application/json'},
          body: {
            'response': {
              'merchantUniquePaymentId': mupid,
              'paymentReference': 'PAY-TOKEN-OK',
              'paymentStatus': 3,
            },
            'validationCode': digest,
          },
        );
        expect(response.statusCode, 200);
      },
    );

    test(
      'still accepts a correctly signed callback with a missing or bad token '
      '(best-effort: the token never gates acceptance)',
      () async {
        store.create(
          _attempt(
            merchantUniquePaymentId: 'att-cb-token-bad',
            mode: 0,
            amount: 25.50,
          ),
        );
        const mupid = 'att-cb-token-bad';
        final digest = _sign(0, '2550', mupid, 'PAY-TOKEN-BAD');

        final response = await call(
          '/api/v1/callbacks?t=not-a-real-token',
          method: 'POST',
          headers: {'content-type': 'application/json'},
          body: {
            'response': {
              'merchantUniquePaymentId': mupid,
              'paymentReference': 'PAY-TOKEN-BAD',
              'paymentStatus': 3,
            },
            'validationCode': digest,
          },
        );
        expect(response.statusCode, 200);
      },
    );

    test(
      'rejects a second callback for the same reference with a conflicting status',
      () async {
        store.create(
          _attempt(merchantUniquePaymentId: 'att-cb-2', mode: 0, amount: 25.50),
        );
        const mupid = 'att-cb-2';
        final digest = _sign(0, '2550', mupid, 'PAY-2');
        final firstBody = {
          'response': {
            'merchantUniquePaymentId': mupid,
            'paymentReference': 'PAY-2',
            'paymentStatus': 3,
          },
          'validationCode': digest,
        };
        final conflictingBody = {
          'response': {
            'merchantUniquePaymentId': mupid,
            'paymentReference': 'PAY-2',
            'paymentStatus': 4,
          },
          'validationCode': digest,
        };

        final first = await call(
          '/api/v1/callbacks',
          method: 'POST',
          headers: {'content-type': 'application/json'},
          body: firstBody,
        );
        expect(first.statusCode, 200);

        final second = await call(
          '/api/v1/callbacks',
          method: 'POST',
          headers: {'content-type': 'application/json'},
          body: conflictingBody,
        );
        expect(second.statusCode, 409);
        expect(jsonDecode(second.body), {'error': 'CALLBACK_CONFLICT'});
      },
    );
  });

  group(
    'rate limiting (unit — avoids the route-level limiters\' shared state)',
    () {
      test(
        'blocks once the fixed window is exhausted, then resets on the next window',
        () {
          final limiter = FixedWindowRateLimiter(
            3,
            const Duration(seconds: 60),
          );
          final now = DateTime.utc(2026, 1, 1);

          expect(limiter.allow('k', now), isTrue);
          expect(limiter.allow('k', now), isTrue);
          expect(limiter.allow('k', now), isTrue);
          expect(limiter.allow('k', now), isFalse);
          expect(
            limiter.allow('k', now.add(const Duration(seconds: 61))),
            isTrue,
          );
        },
      );

      test('tracks separate keys independently', () {
        final limiter = FixedWindowRateLimiter(1, const Duration(seconds: 60));
        final now = DateTime.utc(2026, 1, 1);

        expect(limiter.allow('a', now), isTrue);
        expect(limiter.allow('a', now), isFalse);
        expect(limiter.allow('b', now), isTrue);
      });
    },
  );

  group('attempt store TTL purge (unit)', () {
    test('removes only attempts created before the cutoff', () {
      final cutoff = DateTime.utc(2026, 1, 1);
      final aStore = AttemptStore()
        ..create(
          _attempt(
            merchantUniquePaymentId: 'att-old',
            createdAt: cutoff.subtract(const Duration(minutes: 1)),
          ),
        )
        ..create(
          _attempt(
            merchantUniquePaymentId: 'att-fresh',
            createdAt: cutoff.add(const Duration(minutes: 1)),
          ),
        );

      final removed = aStore.purgeCreatedBefore(cutoff);

      expect(removed, 1);
      expect(aStore.getByMerchantPaymentId('att-old'), isNull);
      expect(aStore.getByMerchantPaymentId('att-fresh'), isNotNull);
    });
  });
}
