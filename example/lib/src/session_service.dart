/// Checkout session creation and Hosted Payment Page (HCP) URL generation.
///
/// Orchestrates the checkout initiation lifecycle:
/// - Enforces request idempotency via [createSession] and [AttemptStore].
/// - Calculates cryptographic SHA3-512 payment fingerprints via `package:zenpay_dart`.
/// - Assembles the authoritative `ZpCheckoutUrlRequest` with appropriate feature
///   flags, return URLs, and callback destinations.
/// - Validates generated launch URLs against HTTPS scheme requirements and host allowlists.
/// - Does not make outbound network calls at launch time; launch URLs are computed locally.
library;

import 'package:zenpay_dart/zenpay_dart.dart';

import 'checkout_state.dart';
import 'config.dart';

const sessionsPathPrefix = '/api/v1/sessions/';
const returnPath = '/return';
const callbacksPath = '/api/v1/callbacks';

/// Extracts the payment identifier segment from a `/api/v1/sessions/:merchantUniquePaymentId` [pathname].
String merchantUniquePaymentIdFromPath(String pathname) =>
    pathname.substring(sessionsPathPrefix.length);

/// Computes the destination return URI for an [attempt] based on its client presentation kind.
///
/// Returns an Android App Link / Universal Link URI for [CheckoutClient.mobile], or
/// the configured web origin [config.appReturnUriWeb] for [CheckoutClient.web] and
/// [CheckoutClient.webFrame].
Uri appReturnUriFor(CheckoutAttempt attempt, AppConfig config) =>
    attempt.client == CheckoutClient.mobile
    ? config.publicBaseUrl.resolve('/zenpay/app-return')
    : config.appReturnUriWeb;

/// Verifies that a replayed idempotency request matches the original [existing] attempt's parameters.
///
/// Throws [HttpError] `(409, 'IDEMPOTENCY_KEY_REUSED')` if any core order parameter differs.
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

/// Converts a stored [attempt] record into an [AppCheckoutSession] DTO.
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

/// Determines the amount value to hash into the SHA3-512 fingerprint for [body] and [mode].
///
/// ZenPay recalculates fingerprints from the launch URL parameters. Modes that carry
/// no payment amount (such as Tokenise without payment) hash `0` rather than the
/// quoted payment amount.
num _fingerprintAmount(CreateCheckoutBody body, int mode) =>
    _isPaymentLike(mode) ? body.paymentAmount : 0;

/// Returns `true` if the specified [mode] represents a payment-carrying transaction (modes 0, 2, 3).
bool _isPaymentLike(int mode) => mode == 0 || mode == 2 || mode == 3;

const _callbackTokenTtl = Duration(hours: 24);

/// Constructs the callback URL for an attempt, appending a signed `?t=<token>` parameter
/// when [AppConfig.callbackTokenSecretConfigured] is enabled.
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

/// Assembles the complete [ZpCheckoutUrlRequest] configuration.
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

/// Builds and validates the HCP launch URL for a single checkout attempt.
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

/// Creates a new checkout session or replays an existing session by [idempotencyKey].
///
/// Returns an [AppCheckoutSession] containing the unique payment identifier and
/// the validated ZenPay Hosted Payment Page launch URL.
///
/// Replayed requests return the pre-existing checkout URL to preserve the original
/// cryptographic timestamp signature.
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

/// Thrown when checkout session URL generation fails or violates security allowlists.
class ZenPaySessionException implements Exception {
  ZenPaySessionException(this.code, {this.detail});

  final String code;

  /// Optional internal diagnostic detail (used only for server logging, not sent to clients).
  final String? detail;

  @override
  String toString() => code;
}

/// Validates that a generated launch URL uses HTTPS and targets an allowed host domain.
///
/// Throws [ZenPaySessionException] if scheme is not HTTPS or if the host is not
/// present in [config.zenPay.allowedCheckoutHosts].
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
