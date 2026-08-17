/// The reference backend's HTTP surface: one flat Shelf handler covering
/// all six routes, request logging, CORS, and error sanitization.
library;

import 'dart:convert';
import 'dart:io';

import 'package:shelf/shelf.dart' as shelf;

import 'checkout_state.dart';
import 'config.dart';
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

void _requireRateLimit(FixedWindowRateLimiter limiter, String key) {
  if (!limiter.allow(key)) throw HttpError(429, 'RATE_LIMITED');
}

void _requireMerchantAuthorization(String? authorization, AppConfig config) {
  final expected = 'Bearer ${config.merchantAppBearerToken}';
  if (authorization == null || !constantTimeEqual(authorization, expected)) {
    throw HttpError(401, 'UNAUTHORIZED');
  }
}

String _clientIp(shelf.Request request) {
  final forwardedFor = request.headers[_HeaderNames.xForwardedFor];
  final rawIp = forwardedFor?.split(',').first.trim();
  if (rawIp != null && rawIp.isNotEmpty) return rawIp;
  final connectionInfo =
      request.context['shelf.io.connection_info'] as HttpConnectionInfo?;
  return connectionInfo?.remoteAddress.address ?? 'unknown';
}

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

shelf.Response _redirect(Uri location) => shelf.Response(
  303,
  headers: {
    'location': location.toString(),
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
  },
);

/// Frame return page: `postMessage`s to a fixed origin — never `*`.
String _frameReturnPageHtml(String targetOrigin, String attempt) {
  final payload = jsonEncode({
    'merchantUniquePaymentId': attempt,
  }).replaceAll('<', '\\u003c');
  final origin = jsonEncode(targetOrigin).replaceAll('<', '\\u003c');
  return '<!doctype html>\n'
      '<meta charset="utf-8">\n'
      '<title>Returning to app</title>\n'
      '<script>\n'
      '  parent.postMessage($payload, $origin);\n'
      '</script>';
}

shelf.Response _handleTestPage(AppConfig config) => shelf.Response.ok(
  _testPageHtml(config),
  headers: {
    _HeaderNames.contentType: 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  },
);

String _testPageHtml(AppConfig config) {
  final tokenJson = jsonEncode(
    config.merchantAppBearerToken,
  ).replaceAll('<', '\\u003c');
  return '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ZenPay Reference Backend Test</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --error: #ef4444;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 2rem 1rem;
      display: flex;
      justify-content: center;
    }
    .container {
      max-width: 640px;
      width: 100%;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2rem;
      box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3);
    }
    h1 { font-size: 1.5rem; margin-top: 0; margin-bottom: 0.5rem; }
    p.subtitle { color: var(--text-muted); font-size: 0.9rem; margin-top: 0; margin-bottom: 1.5rem; }
    .btn {
      background: var(--primary);
      color: white;
      border: none;
      padding: 0.75rem 1.5rem;
      font-size: 1rem;
      font-weight: 600;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.2s;
      width: 100%;
    }
    .btn:hover { background: var(--primary-hover); }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .status-panel {
      margin-top: 1.5rem;
      padding: 1rem;
      border-radius: 8px;
      background: var(--bg);
      border: 1px solid var(--border);
      display: none;
    }
    .status-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
    .status-row:last-child { margin-bottom: 0; }
    .label { color: var(--text-muted); font-size: 0.85rem; }
    .value { font-weight: 600; font-size: 0.95rem; font-family: monospace; }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.65rem;
      border-radius: 9999px;
      font-size: 0.8rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-sessionCreated { background: rgba(59, 130, 246, 0.2); color: #60a5fa; }
    .badge-browserReturned { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
    .badge-successful { background: rgba(34, 197, 94, 0.2); color: #4ade80; }
    .badge-failed, .badge-cancelled, .badge-error { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .error-box {
      margin-top: 1.5rem;
      padding: 1rem;
      border-radius: 8px;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid var(--error);
      color: #fca5a5;
      font-family: monospace;
      font-size: 0.9rem;
      display: none;
      word-break: break-all;
    }
    .info-box { margin-top: 1rem; font-size: 0.8rem; color: var(--text-muted); line-height: 1.4; }
  </style>
</head>
<body>
  <div class="container">
    <h1>ZenPay Reference Backend Test</h1>
    <p class="subtitle">Create a checkout session and test the payment flow in browser.</p>
    
    <button id="create-btn" class="btn" onclick="createCheckout()">Create Test Checkout</button>

    <div id="error-box" class="error-box"></div>

    <div id="status-panel" class="status-panel">
      <div class="status-row">
        <span class="label">Status</span>
        <span id="status-badge" class="badge"></span>
      </div>
      <div class="status-row">
        <span class="label">Payment ID</span>
        <span id="mupid-val" class="value"></span>
      </div>
      <div class="status-row">
        <span class="label">Poll Count</span>
        <span id="poll-val" class="value">0 / 40</span>
      </div>
    </div>

    <div class="info-box">
      Note: Local development bearer token embedded in test page JS.
    </div>
  </div>

  <script>
    const BEARER_TOKEN = $tokenJson;
    let pollInterval = null;
    let pollCount = 0;

    async function createCheckout() {
      const btn = document.getElementById('create-btn');
      const errBox = document.getElementById('error-box');
      const panel = document.getElementById('status-panel');
      const mupidVal = document.getElementById('mupid-val');

      errBox.style.display = 'none';
      panel.style.display = 'none';
      btn.disabled = true;

      if (pollInterval) clearInterval(pollInterval);
      pollCount = 0;

      const idempotencyKey = 'test-' + Date.now();
      const orderId = 'ord-' + Date.now();

      try {
        const response = await fetch('/api/v1/sessions', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + BEARER_TOKEN,
            'Idempotency-Key': idempotencyKey,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            orderId: orderId,
            customerName: 'Test Customer',
            customerEmail: 'test@example.com',
            client: 'web',
            paymentAmount: 10.00
          })
        });

        const data = await response.json().catch(() => ({ error: 'NON_JSON_RESPONSE' }));

        if (!response.ok) {
          errBox.textContent = 'Error (' + response.status + '): ' + (data.error || JSON.stringify(data));
          errBox.style.display = 'block';
          btn.disabled = false;
          return;
        }

        window.open(data.checkoutUrl, '_blank');

        panel.style.display = 'block';
        mupidVal.textContent = data.merchantUniquePaymentId;
        updateBadge('sessionCreated');

        pollStatus(data.merchantUniquePaymentId);
        pollInterval = setInterval(() => pollStatus(data.merchantUniquePaymentId), 3000);

      } catch (err) {
        errBox.textContent = 'Network / Request Error: ' + err.message;
        errBox.style.display = 'block';
      } finally {
        btn.disabled = false;
      }
    }

    function updateBadge(status) {
      const badge = document.getElementById('status-badge');
      badge.textContent = status;
      badge.className = 'badge badge-' + status;
    }

    async function pollStatus(mupid) {
      pollCount++;
      document.getElementById('poll-val').textContent = pollCount + ' / 40';

      try {
        const response = await fetch('/api/v1/sessions/' + encodeURIComponent(mupid), {
          headers: {
            'Authorization': 'Bearer ' + BEARER_TOKEN
          }
        });
        if (response.ok) {
          const data = await response.json();
          updateBadge(data.status);

          const terminal = ['successful', 'failed', 'cancelled', 'error'];
          if (terminal.includes(data.status) || pollCount >= 40) {
            clearInterval(pollInterval);
            pollInterval = null;
          }
        }
      } catch (e) {
        // Ignore transient poll errors
      }
    }
  </script>
</body>
</html>''';
}

const _allowedCheckoutKeys = {
  'orderId',
  'customerName',
  'customerEmail',
  'mode',
  'client',
  'paymentAmount',
  'customerReference',
  'contactNumber',
};

final _emailPattern = RegExp(r'^[^\s@]+@[^\s@]+\.[^\s@]+$');

CreateCheckoutBody _parseCreateCheckoutBody(Map<String, Object?> value) {
  for (final key in value.keys) {
    if (!_allowedCheckoutKeys.contains(key)) {
      throw HttpError(400, 'UNKNOWN_CHECKOUT_FIELD');
    }
  }

  final orderId = value['orderId'];
  if (orderId is! String ||
      orderId.trim().isEmpty ||
      orderId.trim().length > 128) {
    throw HttpError(400, 'INVALID_CHECKOUT_REQUEST');
  }
  final customerName = value['customerName'];
  if (customerName is! String ||
      customerName.trim().isEmpty ||
      customerName.trim().length > 250) {
    throw HttpError(400, 'INVALID_CHECKOUT_REQUEST');
  }
  final customerEmail = value['customerEmail'];
  if (customerEmail is! String ||
      customerEmail.trim().isEmpty ||
      customerEmail.trim().length > 254 ||
      !_emailPattern.hasMatch(customerEmail.trim())) {
    throw HttpError(400, 'INVALID_CHECKOUT_REQUEST');
  }
  final modeRaw = value['mode'];
  if (modeRaw != null && (modeRaw is! int || modeRaw < 0 || modeRaw > 3)) {
    throw HttpError(400, 'INVALID_CHECKOUT_MODE');
  }
  final client = switch (value['client']) {
    final String c => CheckoutClient.tryParse(c),
    _ => null,
  };
  if (client == null) throw HttpError(400, 'INVALID_CHECKOUT_CLIENT');
  final paymentAmount = value['paymentAmount'];
  if (paymentAmount is! num || paymentAmount <= 0 || paymentAmount > 999999) {
    throw HttpError(400, 'INVALID_CHECKOUT_AMOUNT');
  }
  final customerReferenceRaw = value['customerReference'];
  if (customerReferenceRaw != null &&
      (customerReferenceRaw is! String ||
          customerReferenceRaw.trim().isEmpty ||
          customerReferenceRaw.trim().length > 128)) {
    throw HttpError(400, 'INVALID_CHECKOUT_REFERENCE');
  }
  final contactNumberRaw = value['contactNumber'];
  if (contactNumberRaw != null &&
      (contactNumberRaw is! String ||
          contactNumberRaw.trim().isEmpty ||
          contactNumberRaw.trim().length > 32)) {
    throw HttpError(400, 'INVALID_CHECKOUT_CONTACT_NUMBER');
  }

  return CreateCheckoutBody(
    orderId: orderId.trim(),
    customerName: customerName.trim(),
    customerEmail: customerEmail.trim(),
    client: client,
    paymentAmount: paymentAmount,
    mode: modeRaw as int?,
    customerReference: (customerReferenceRaw as String?)?.trim(),
    contactNumber: (contactNumberRaw as String?)?.trim(),
  );
}

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
  final body = _parseCreateCheckoutBody(rawBody);
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
      _frameReturnPageHtml(
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

/// Builds the single Shelf [shelf.Handler] serving all seven routes: request
/// logging (path only, never the query string), CORS preflight, dispatch,
/// and sanitized error responses.
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

/// Writes an indented JSON log line. Fields must be pre-redacted by the
/// caller — see `docs/SECURITY_AND_PCI.md` for what must never appear here.
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
