/// Checkout session creation: idempotency, HCP Authorise launch-URL
/// construction, and the app-facing response shape.
///
/// The launch URL is built here with `package:zenpay_hcp` — the same
/// `createZpFingerprint` → `ZpCheckoutUrlRequest` → validate → URL sequence a
/// TypeScript integrator runs with `@ianmenethil/zp-hcp/server`, minus the
/// browser plugin. There is no outbound call to ZenPay at launch time.
library;

import 'package:zenpay_dart/zenpay_dart.dart';

import 'checkout_state.dart';
import 'config.dart';

/// Path prefix for the `/api/v1/sessions/:merchantUniquePaymentId` status-lookup route.
const sessionsPathPrefix = '/api/v1/sessions/';

/// Path for the `/return` route.
const returnPath = '/return';

/// Path for the `/api/v1/callbacks` route.
const callbacksPath = '/api/v1/callbacks';

/// Extracts the payment id segment from a `/api/v1/sessions/:merchantUniquePaymentId` path.
String merchantUniquePaymentIdFromPath(String pathname) =>
    pathname.substring(sessionsPathPrefix.length);

/// The App Link (mobile) or web origin (web/webFrame) ZenPay's return broker
/// redirects to once the browser returns.
Uri appReturnUriFor(CheckoutAttempt attempt, AppConfig config) =>
    attempt.client == CheckoutClient.mobile
    ? config.publicBaseUrl.resolve('/zenpay/app-return')
    : config.appReturnUriWeb;

void _requireIdempotentMatch(
  CheckoutAttempt existing,
  CreateCheckoutBody body,
  int mode,
) {
  if (existing.orderId != body.orderId ||
      existing.customerEmail != body.customerEmail ||
      existing.customerName != body.customerName ||
      existing.mode != mode ||
      existing.amount != body.paymentAmount) {
    throw HttpError(409, 'IDEMPOTENCY_KEY_REUSED');
  }
}

AppCheckoutSession _toAppCheckoutSession(CheckoutAttempt attempt) {
  final checkoutUrl = attempt.checkoutUrl;
  if (checkoutUrl == null) {
    throw StateError(
      'Cannot format an unlaunched attempt as an app session response.',
    );
  }
  return AppCheckoutSession(
    merchantUniquePaymentId: attempt.merchantUniquePaymentId,
    checkoutUrl: checkoutUrl,
  );
}

/// ZenPay recomputes the fingerprint from what the launch URL actually
/// carries, so the amount hashed here must be the amount sent there. Modes
/// that carry no `paymentAmount` must therefore hash `0`, not the amount the
/// merchant app happened to quote.
num _fingerprintAmount(CreateCheckoutBody body, int mode) =>
    _isPaymentLike(mode) ? body.paymentAmount : 0;

bool _isPaymentLike(int mode) => mode == 0 || mode == 2 || mode == 3;

/// Callback-URL token lifetime: generous enough for a slow ZenPay callback,
/// short enough not to matter if one leaks.
const _callbackTokenTtl = Duration(hours: 24);

/// The callback URL for one attempt: the fixed `/api/v1/callbacks` route,
/// with an optional signed `?t=<token>` binding it to this specific
/// mode/mupid/timestamp/amount when [AppConfig.callbackTokenSecretConfigured]
/// — verified on receipt by `security.dart`'s `checkCallbackToken`. Absent
/// a configured secret, this is just the bare route, unchanged from before.
String _callbackUrlFor({
  required String merchantUniquePaymentId,
  required String timestamp,
  required int mode,
  required CreateCheckoutBody body,
  required AppConfig config,
}) {
  final base = config.publicBaseUrl.resolve(callbacksPath);
  if (!config.callbackTokenSecretConfigured) return base.toString();

  final token = createZpCallbackUrlToken(
    ZpCallbackUrlTokenPayload(
      mode: ZpPluginMode.fromWireValue(mode),
      merchantUniquePaymentId: merchantUniquePaymentId,
      timestamp: timestamp,
      paymentAmount: _fingerprintAmount(body, mode),
    ),
    config.callbackTokenSecret,
    ZpCallbackUrlTokenOptions(expiresInSeconds: _callbackTokenTtl.inSeconds),
  );
  return base.replace(queryParameters: {'t': token}).toString();
}

ZpCheckoutUrlRequest _buildAuthoriseRequest({
  required String fingerprint,
  required String merchantUniquePaymentId,
  required String timestamp,
  required CreateCheckoutBody body,
  required int mode,
  required AppConfig config,
}) {
  final returnUrl = config.publicBaseUrl.replace(
    path: returnPath,
    queryParameters: {'merchantUniquePaymentId': merchantUniquePaymentId},
  );
  final isPaymentLike = _isPaymentLike(mode);
  // ZenPay only honours the account-method flags for mode 0 or 2.
  final isModeZeroOrTwo = mode == 0 || mode == 2;
  // ZenPay only honours the wallet flags for mode 0 (Make Payment).
  final isMakePayment = mode == 0;

  return ZpCheckoutUrlRequest(
    url: config.zenPay.hppEndpointUrl.toString(),
    apiKey: config.zenPay.credentials.apiKey,
    fingerprint: fingerprint,
    merchantCode: config.zenPay.credentials.merchantCode,
    mode: ZpPluginMode.fromWireValue(mode),
    timestamp: ZpTimestamp(timestamp),
    merchantUniquePaymentId: ZpMupid(merchantUniquePaymentId),
    customerEmail: body.customerEmail,
    redirectUrl: returnUrl.toString(),
    callbackUrl: _callbackUrlFor(
      merchantUniquePaymentId: merchantUniquePaymentId,
      timestamp: timestamp,
      mode: mode,
      body: body,
      config: config,
    ),
    displayMode: ZpDisplayMode.redirectUrl,
    userMode: ZpUserMode.customer,
    redirectOnError: true,
    customerName: isPaymentLike ? body.customerName : null,
    customerReference: isPaymentLike
        ? (body.customerReference ?? body.orderId)
        : null,
    paymentAmount: isPaymentLike ? body.paymentAmount : null,
    contactNumber: body.contactNumber,
    allowBankAcOneOffPayment: false,
    allowPayToOneOffPayment: isModeZeroOrTwo ? true : null,
    allowPayIdOneOffPayment: false,
    allowApplePayOneOffPayment: isMakePayment,
    allowGooglePayOneOffPayment: isMakePayment ? true : null,
    allowLatitudePayOneOffPayment: false,
    allowSlicePayOneOffPayment: false,
    allowUnionPayOneOffPayment: isMakePayment,
    allowAliPayPlusOneOffPayment: isMakePayment,
    allowWeChatPayOneOffPayment: isMakePayment ? true : null,
    sendConfirmationEmailToCustomer: false,
    sendConfirmationEmailToMerchant: false,
    allowSaveCardUserOption: false,
  );
}

/// Builds and validates the HCP launch URL for one attempt.
///
/// Fingerprint first, then the Authorise payload carrying it, then the URL
Uri _buildCheckoutUrl({
  required String merchantUniquePaymentId,
  required String timestamp,
  required CreateCheckoutBody body,
  required int mode,
  required AppConfig config,
}) {
  final credentials = config.zenPay.credentials;
  final fingerprint = createZpFingerprint(
    ZpFingerprintRequest(
      apiKey: credentials.apiKey,
      username: credentials.username,
      password: credentials.password,
      mode: ZpPluginMode.fromWireValue(mode),
      paymentAmount: _fingerprintAmount(body, mode),
      merchantUniquePaymentId: ZpMupid(merchantUniquePaymentId),
      timestamp: ZpTimestamp(timestamp),
    ),
  );
  if (fingerprint is! ZpFingerprintSuccess) {
    throw ZenPaySessionException('ZENPAY_FINGERPRINT_FAILED');
  }

  final authoriseRequest = _buildAuthoriseRequest(
    fingerprint: fingerprint.fingerprint,
    merchantUniquePaymentId: merchantUniquePaymentId,
    timestamp: timestamp,
    body: body,
    mode: mode,
    config: config,
  );

  final result = createZpCheckoutUrl(authoriseRequest);
  if (result is! ZpCheckoutUrlSuccess) {
    throw ZenPaySessionException('ZENPAY_CHECKOUT_URL_FAILED');
  }
  return resolveCheckoutUrl(result.url, config);
}

/// Creates (or replays, by idempotency key) a ZenPay checkout session for
/// [body], returning the launch data the merchant app needs.
///
/// A replay returns the stored URL rather than rebuilding it: the fingerprint
/// covers the timestamp, so a rebuild would produce a different URL for the
/// same attempt.
AppCheckoutSession createSession(
  CreateCheckoutBody body,
  String idempotencyKey,
  AppConfig config,
  AttemptStore store,
) {
  final mode = body.mode ?? 0;

  final existing = store.getByIdempotencyKey(idempotencyKey);
  if (existing != null) {
    _requireIdempotentMatch(existing, body, mode);
    if (existing.checkoutUrl != null) {
      return _toAppCheckoutSession(existing);
    }
  }

  final merchantUniquePaymentId =
      existing?.merchantUniquePaymentId ?? createZpMupid().value;
  final createdAt = DateTime.now().toUtc();

  final attempt =
      existing ??
      CheckoutAttempt(
        merchantUniquePaymentId: merchantUniquePaymentId,
        idempotencyKey: idempotencyKey,
        orderId: body.orderId,
        mode: mode,
        client: body.client,
        amount: body.paymentAmount,
        customerName: body.customerName,
        customerEmail: body.customerEmail,
        createdAt: createdAt,
        status: MerchantPaymentStatus.created,
      );

  if (existing == null) store.create(attempt);

  final checkoutUrl = _buildCheckoutUrl(
    merchantUniquePaymentId: merchantUniquePaymentId,
    timestamp: createZpTimestamp().value,
    body: body,
    mode: mode,
    config: config,
  );

  final updated = store.replace(
    merchantUniquePaymentId,
    attempt.copyWith(
      checkoutUrl: checkoutUrl.toString(),
      status: MerchantPaymentStatus.sessionCreated,
    ),
  );

  return _toAppCheckoutSession(updated);
}

/// Thrown when a checkout URL cannot be built, or resolves somewhere the
/// allowlist does not permit.
///
/// [detail], when present, carries the specific reason (e.g. schema
/// validation errors) for logging — never sent to the client, which only
/// gets [code].
class ZenPaySessionException implements Exception {
  ZenPaySessionException(this.code, {this.detail});

  final String code;
  final String? detail;

  @override
  String toString() => code;
}

/// Validates a launch URL: HTTPS scheme plus the configured host allowlist.
///
/// Applies to any URL bound for the app, whoever produced it — a
/// misconfigured `ZENPAY_HPP_ENDPOINT_URL` fails here rather than sending the
/// customer somewhere unintended.
Uri resolveCheckoutUrl(String endpointUrl, AppConfig config) {
  final checkoutUrl = Uri.parse(endpointUrl);
  if (checkoutUrl.scheme != 'https') {
    throw ZenPaySessionException('ZENPAY_SESSION_ENDPOINT_NOT_HTTPS');
  }
  if (!config.zenPay.allowedCheckoutHosts.contains(
    checkoutUrl.host.toLowerCase(),
  )) {
    throw ZenPaySessionException('ZENPAY_RESOLVED_CHECKOUT_URL_NOT_ALLOWED');
  }
  return checkoutUrl;
}
