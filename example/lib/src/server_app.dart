/// The reference backend's HTTP surface and request pipeline.
///
/// Implements a complete Shelf HTTP handler covering:
/// - Route dispatching across all seven supported endpoints:
///   - `GET /`: Interactive manual test bench page ([_handleTestPage]).
///   - `GET /api/v1/health`: Health and readiness probe ([_handleHealth]).
///   - `GET /.well-known/assetlinks.json`: Android App Links verification ([_handleAssetlinks]).
///   - `POST /api/v1/sessions`: Checkout session creation ([_handleCreateSession]).
///   - `GET /api/v1/sessions/:id`: Authoritative checkout status lookup ([_handleGetSession]).
///   - `POST /api/v1/callbacks`: ZenPay webhook receiver and signature verification ([_handleCallback]).
///   - `GET /return`: Browser return broker and App Link redirector ([_handleReturn]).
/// - In-memory rate limiting for API routes and webhook callbacks.
/// - Constant-time Bearer token authorization.
/// - JSON body reading with size limits and Content-Type validation.
/// - Standardized JSON error response formatting and sanitization.
/// - Structured JSON logging adhering to PCI data protection guidelines.
library;

import 'dart:convert';
import 'dart:io';

import 'package:shelf/shelf.dart' as shelf;

import 'checkout_state.dart';
import 'checkout_validation.dart' show parseCreateCheckoutBody;
import 'config.dart';
import 'html_pages.dart' show frameReturnPageHtml, testPageHtml;
import 'rate_limiter.dart';
import 'security.dart'
    show checkCallbackToken, constantTimeEqual, verifyCallback;
import 'session_service.dart'
    show
        ZenPaySessionException,
        createSession,
        merchantUniquePaymentIdFromPath,
        appReturnUriFor,
        sessionsPathPrefix,
        returnPath,
        callbacksPath;

abstract final class _HeaderNames {
  static const authorization = 'authorization';
  static const contentType = 'content-type';
  static const idempotencyKey = 'idempotency-key';
  static const xForwardedFor = 'x-forwarded-for';
  static const userAgent = 'user-agent';
}

final _appRouteLimiter = FixedWindowRateLimiter(
  60,
  const Duration(seconds: 60),
);
final _callbackLimiter = FixedWindowRateLimiter(
  240,
  const Duration(seconds: 60),
);

/// Enforces that [key] has not exceeded [limiter]'s quota, throwing `HttpError(429)` if breached.
void _requireRateLimit(FixedWindowRateLimiter limiter, String key) {
  if (!limiter.allow(key)) throw HttpError(429, 'RATE_LIMITED');
}

/// Validates the `Authorization: Bearer <token>` header against [config.merchantAppBearerToken]
/// in constant time to prevent timing attacks.
///
/// Throws [HttpError] `(401, 'UNAUTHORIZED')` if missing or mismatched.
void _requireMerchantAuthorization(String? authorization, AppConfig config) {
  final expected = 'Bearer ${config.merchantAppBearerToken}';
  if (authorization == null || !constantTimeEqual(authorization, expected)) {
    throw HttpError(401, 'UNAUTHORIZED');
  }
}

/// Extracts client IP address from `X-Forwarded-For` header or underlying connection info.
String _clientIp(shelf.Request request) {
  final forwardedFor = request.headers[_HeaderNames.xForwardedFor];
  final rawIp = forwardedFor?.split(',').first.trim();
  if (rawIp != null && rawIp.isNotEmpty) return rawIp;
  final connectionInfo =
      request.context['shelf.io.connection_info'] as HttpConnectionInfo?;
  return connectionInfo?.remoteAddress.address ?? 'unknown';
}

/// Reads and parses a JSON request body with a 64KB maximum size limit.
///
/// Ensures full stream draining to prevent mid-write TCP socket resets,
/// validating `Content-Type: application/json` headers and structure.
Future<Map<String, Object?>> _readJson(shelf.Request request) async {
  final contentType = request.headers[_HeaderNames.contentType];
  if (contentType == null ||
      !contentType.toLowerCase().startsWith('application/json')) {
    throw HttpError(415, 'APPLICATION_JSON_REQUIRED');
  }

  final chunks = <int>[];
  var tooLarge = false;
  // Drain the full stream even once over-limit, so the client's upload
  // completes and it can read the error response instead of the
  // connection being torn down mid-write.
  await for (final chunk in request.read()) {
    if (!tooLarge) {
      chunks.addAll(chunk);
      tooLarge = chunks.length > 64 * 1024;
    }
  }
  if (tooLarge) throw HttpError(413, 'REQUEST_BODY_TOO_LARGE');
  if (chunks.isEmpty) throw HttpError(400, 'REQUEST_BODY_REQUIRED');

  Object? parsed;
  try {
    parsed = jsonDecode(utf8.decode(chunks));
  } on FormatException {
    throw HttpError(400, 'INVALID_JSON');
  }
  if (parsed is! Map<String, Object?>) throw HttpError(400, 'INVALID_JSON');
  return parsed;
}

/// Constructs a standardized JSON [shelf.Response] with security headers.
///
/// Applies `no-store`, `nosniff`, `no-referrer`, and restrictive CSP headers,
/// optionally attaching CORS access control headers if [allowedOrigin] is provided.
shelf.Response _json(int status, Object? body, {String? allowedOrigin}) {
  final headers = {
    _HeaderNames.contentType: 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'none'",
  };
  if (allowedOrigin != null) {
    headers['access-control-allow-origin'] = allowedOrigin;
    headers['vary'] = 'origin';
  }
  return shelf.Response(status, body: jsonEncode(body), headers: headers);
}

/// Creates a `303 See Other` redirect [shelf.Response] to [location].
shelf.Response _redirect(Uri location) => shelf.Response(
  303,
  headers: {
    'location': location.toString(),
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
  },
);

/// Serves the interactive testing interface HTML page at `GET /`.
shelf.Response _handleTestPage(AppConfig config) => shelf.Response.ok(
  testPageHtml(config),
  headers: {
    _HeaderNames.contentType: 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  },
);

/// Answers `GET /api/v1/health` with service status and configuration readiness.
shelf.Response _handleHealth(AppConfig config) {
  final missingSession = sessionConfigurationErrors(config);
  final missingCallback = callbackConfigurationErrors(config);
  return _json(200, {
    'ok': true,
    'sessionReady': missingSession.isEmpty,
    'callbackReady': missingCallback.isEmpty,
    'missingSessionConfiguration': missingSession,
    'missingCallbackConfiguration': missingCallback,
  });
}

/// Serves Android App Links Digital Asset Links JSON at `GET /.well-known/assetlinks.json`.
Future<shelf.Response> _handleAssetlinks() async {
  final file = File(
    '${Directory.current.path}/../app/platform_config/android/assetlinks.json',
  );
  if (!await file.exists()) throw HttpError(404, 'NOT_FOUND');
  return shelf.Response.ok(
    await file.readAsBytes(),
    headers: {_HeaderNames.contentType: 'application/json'},
  );
}

/// Handles `POST /api/v1/sessions` to initiate a checkout session.
///
/// Authenticates the merchant Bearer token, enforces idempotency, validates
/// payload fields, generates the HCP launch URL, and registers the attempt.
Future<shelf.Response> _handleCreateSession(
  shelf.Request request,
  AppConfig config,
  AttemptStore store,
) async {
  _requireMerchantAuthorization(
    request.headers[_HeaderNames.authorization],
    config,
  );
  _requireRateLimit(_appRouteLimiter, _clientIp(request));

  final missing = sessionConfigurationErrors(config);
  if (missing.isNotEmpty) {
    throw HttpError(503, 'SESSION_CONFIGURATION_REQUIRED:${missing.join(',')}');
  }

  final idempotencyKey = request.headers[_HeaderNames.idempotencyKey];
  if (idempotencyKey == null ||
      idempotencyKey.length < 16 ||
      idempotencyKey.length > 128) {
    throw HttpError(400, 'INVALID_IDEMPOTENCY_KEY');
  }

  final rawBody = await _readJson(request);
  final body = parseCreateCheckoutBody(rawBody);
  logEvent('checkout_request_received', {
    'stage': 'client > making request to our backend',
    'mode': body.mode ?? 0,
    'body': rawBody,
  });

  final session = createSession(body, idempotencyKey, config, store);
  logEvent('checkout_response_sent', {
    'stage': 'backend > response to client',
    'mode': body.mode ?? 0,
    'body': session.toJson(),
  });

  return _json(201, session.toJson(), allowedOrigin: config.allowedAppOrigin);
}

/// Handles `GET /api/v1/sessions/:id` for authoritative payment status polling.
shelf.Response _handleGetSession(
  shelf.Request request,
  Uri requestedUri,
  AppConfig config,
  AttemptStore store,
) {
  _requireMerchantAuthorization(
    request.headers[_HeaderNames.authorization],
    config,
  );
  _requireRateLimit(_appRouteLimiter, _clientIp(request));

  final merchantUniquePaymentId = merchantUniquePaymentIdFromPath(
    requestedUri.path,
  );
  final attempt = store.getByMerchantPaymentId(merchantUniquePaymentId);
  if (attempt == null) throw HttpError(404, 'CHECKOUT_NOT_FOUND');

  return _json(200, {
    'merchantUniquePaymentId': attempt.merchantUniquePaymentId,
    'status': attempt.status.name,
    'paymentReference': attempt.paymentReference,
    'preauthReference': attempt.preauthReference,
    'tokenReference': attempt.tokenReference,
    'failureCode': attempt.failureCode,
    'failureReason': attempt.failureReason,
    'callbackVerified': attempt.verifiedCallbackReference != null,
    'zenPayStatusCode': attempt.verifiedCallbackStatusCode,
  }, allowedOrigin: config.allowedAppOrigin);
}

/// Handles `POST /api/v1/callbacks` receiving asynchronous webhook notifications from ZenPay.
///
/// Authenticates webhook cryptographic signatures, validates attempt correlation,
/// detects conflicts, and updates the attempt status and transaction references.
Future<shelf.Response> _handleCallback(
  shelf.Request request,
  AppConfig config,
  AttemptStore store,
) async {
  _requireRateLimit(_callbackLimiter, _clientIp(request));
  final missing = callbackConfigurationErrors(config);
  if (missing.isNotEmpty) {
    throw HttpError(
      503,
      'CALLBACK_CONFIGURATION_REQUIRED:${missing.join(',')}',
    );
  }

  final tokenCheck = checkCallbackToken(
    request.requestedUri.queryParameters['t'],
    config.callbackTokenSecret,
  );
  if (tokenCheck != null) {
    logEvent(
      tokenCheck.verified
          ? 'callback_token_verified'
          : 'callback_token_check_failed',
      {'detail': tokenCheck.detail},
      !tokenCheck.verified,
    );
  }

  final payload = await _readJson(request);
  final merchantUniquePaymentId = switch (payload['response']) {
    {'merchantUniquePaymentId': final String id} when id.isNotEmpty => id,
    _ => null,
  };
  if (merchantUniquePaymentId == null) {
    throw HttpError(400, 'CALLBACK_MERCHANT_PAYMENT_ID_REQUIRED');
  }

  final attempt = store.getByMerchantPaymentId(merchantUniquePaymentId);
  if (attempt == null) throw HttpError(404, 'CALLBACK_ATTEMPT_NOT_FOUND');

  final verification = verifyCallback(
    payload,
    attempt,
    config.zenPay.credentials,
  );
  if (!verification.ok) {
    logEvent('callback_rejected', {
      'merchantUniquePaymentId': merchantUniquePaymentId,
      'reason': verification.reason,
      'validationCode': payload['validationCode'],
    }, true);
    final malformed = verification.reason == 'malformed';
    throw HttpError(
      malformed ? 400 : 401,
      malformed ? 'CALLBACK_BODY_INVALID' : 'CALLBACK_VALIDATION_FAILED',
    );
  }
  final fields = verification.fields!;
  logEvent('callback_verified', {
    'merchantUniquePaymentId': fields.merchantUniquePaymentId,
    'validationCode': fields.validationCode,
    'statusCode': fields.statusCode,
    'mappedStatus': mapZenPayStatus(fields.statusCode).name,
    if (fields.failureCode != null) 'failureCode': fields.failureCode,
    if (fields.failureReason != null) 'failureReason': fields.failureReason,
  });

  if (attempt.verifiedCallbackReference != null &&
      (!constantTimeEqual(
            attempt.verifiedCallbackReference!,
            fields.reference,
          ) ||
          attempt.verifiedCallbackStatusCode != fields.statusCode)) {
    throw HttpError(409, 'CALLBACK_CONFLICT');
  }

  store.replace(
    attempt.merchantUniquePaymentId,
    attempt.copyWith(
      paymentReference: attempt.mode == 0 || attempt.mode == 2
          ? fields.reference
          : attempt.paymentReference,
      preauthReference: attempt.mode == 3
          ? fields.reference
          : attempt.preauthReference,
      tokenReference: attempt.mode == 1
          ? fields.reference
          : attempt.tokenReference,
      status: mapZenPayStatus(fields.statusCode),
      failureCode: fields.failureCode,
      failureReason: fields.failureReason,
      verifiedCallbackReference: fields.reference,
      verifiedCallbackStatusCode: fields.statusCode,
    ),
  );

  return _json(200, {'ok': true});
}

const _terminalStatuses = {
  MerchantPaymentStatus.successful,
  MerchantPaymentStatus.failed,
  MerchantPaymentStatus.cancelled,
  MerchantPaymentStatus.error,
};

/// Handles `GET /return` receiving customer browser redirects from ZenPay Hosted Payment Page.
///
/// Updates attempt status to `browserReturned` (unless already in a terminal state),
/// then renders a `postMessage` landing page for `webFrame` clients or issues a
/// 303 redirect to the App Link / web origin for mobile / web clients.
shelf.Response _handleReturn(
  Uri requestedUri,
  AppConfig config,
  AttemptStore store,
) {
  final merchantUniquePaymentId =
      requestedUri.queryParameters['merchantUniquePaymentId'];
  if (merchantUniquePaymentId == null) {
    throw HttpError(400, 'RETURN_CORRELATION_REQUIRED');
  }

  final attempt = store.getByMerchantPaymentId(merchantUniquePaymentId);
  if (attempt == null) {
    throw HttpError(400, 'RETURN_CORRELATION_INVALID');
  }

  store.replace(
    merchantUniquePaymentId,
    attempt.copyWith(
      status: _terminalStatuses.contains(attempt.status)
          ? attempt.status
          : MerchantPaymentStatus.browserReturned,
    ),
  );

  if (attempt.client == CheckoutClient.webFrame) {
    return shelf.Response.ok(
      frameReturnPageHtml(
        config.allowedAppOrigin,
        attempt.merchantUniquePaymentId,
      ),
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'referrer-policy': 'no-referrer',
      },
    );
  }

  final appReturn = appReturnUriFor(attempt, config).replace(
    queryParameters: {
      'merchantUniquePaymentId': attempt.merchantUniquePaymentId,
    },
  );
  return _redirect(appReturn);
}

/// Dispatches an incoming [request] to the appropriate endpoint handler based on method and path.
Future<shelf.Response> _dispatch(
  shelf.Request request,
  AppConfig config,
  AttemptStore store,
) async {
  final method = request.method;
  final path = request.requestedUri.path;

  if (method == 'GET' && path == '/') {
    return _handleTestPage(config);
  }
  if (method == 'GET' && path == '/api/v1/health') {
    return _handleHealth(config);
  }
  if (method == 'GET' && path == '/.well-known/assetlinks.json') {
    return _handleAssetlinks();
  }
  if (method == 'POST' && path == '/api/v1/sessions') {
    return _handleCreateSession(request, config, store);
  }
  if (method == 'GET' && path.startsWith(sessionsPathPrefix)) {
    return _handleGetSession(request, request.requestedUri, config, store);
  }
  if (method == 'POST' && path == callbacksPath) {
    return _handleCallback(request, config, store);
  }
  if (method == 'GET' && path == returnPath) {
    return _handleReturn(request.requestedUri, config, store);
  }

  throw HttpError(404, 'NOT_FOUND');
}

final _sanitizePattern = RegExp(r'[^A-Za-z0-9_:.-]');

/// Builds the top-level Shelf [shelf.Handler] serving all reference backend routes.
///
/// Handles CORS preflight `OPTIONS` requests, dispatches routes via [_dispatch],
/// sanitizes error responses, and emits structured audit logs.
shelf.Handler buildHandler(AppConfig config, AttemptStore store) {
  return (shelf.Request request) async {
    final startTime = DateTime.now();
    final clientIp = _clientIp(request);
    shelf.Response response;

    try {
      if (request.method == 'OPTIONS') {
        response = shelf.Response(
          204,
          headers: {
            'access-control-allow-origin': config.allowedAppOrigin,
            'access-control-allow-methods': 'GET,POST,OPTIONS',
            'access-control-allow-headers':
                'Authorization,Content-Type,Idempotency-Key',
          },
        );
      } else {
        response = await _dispatch(request, config, store);
      }
    } on HttpError catch (error) {
      logEvent('request_error', {
        'method': request.method,
        'path': request.requestedUri.path,
        'status': error.statusCode,
        'code': error.code,
      }, true);
      response = _json(error.statusCode, {'error': error.code});
    } catch (error) {
      final code = error.toString().replaceAll(_sanitizePattern, '_');
      logEvent('request_error', {
        'method': request.method,
        'path': request.requestedUri.path,
        'status': 500,
        'code': code,
        if (error is ZenPaySessionException && error.detail != null)
          'detail': error.detail,
      }, true);
      response = _json(500, {'error': code});
    }

    // CORS preflight always answers 204 with the same fixed headers above —
    // logging it carries no information, just noise on every real request.
    if (request.method != 'OPTIONS') {
      logEvent('http_request', {
        'ip': clientIp,
        'userAgent': request.headers[_HeaderNames.userAgent] ?? 'unknown',
        'method': request.method,
        'path': request.requestedUri.path,
        'status': response.statusCode,
        'durationMs': DateTime.now().difference(startTime).inMilliseconds,
      });
    }
    return response;
  };
}

const _encoder = JsonEncoder.withIndent('  ');

/// Emits a structured JSON log entry to standard output or standard error.
///
/// Caller must ensure that sensitive credentials (passwords, card details, secrets)
/// are strictly redacted prior to logging to maintain PCI-DSS compliance.
void logEvent(
  String event, [
  Map<String, Object?> fields = const {},
  bool isError = false,
]) {
  final payload = _encoder.convert({
    'timestamp': DateTime.now().toIso8601String(),
    'event': event,
    ...fields,
  });
  if (isError) {
    stderr.writeln(payload);
  } else {
    stdout.writeln(payload);
  }
}
