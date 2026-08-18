/// Backend security primitives, timing-safe equality, and callback verification.
///
/// Implements:
/// - [constantTimeEqual]: Constant-time string equality comparison using SHA-256
///   digests to prevent timing side-channel attacks on authorization tokens and references.
/// - [CallbackFields]: Structured container of extracted verified callback metadata.
/// - [CallbackVerification]: Result wrapper indicating callback authentication success or rejection.
/// - [verifyCallback]: Delegated cryptographic signature validation (SHA3-512 `ValidationCode`)
///   against the corresponding stored checkout attempt using `package:zenpay_dart`.
/// - [checkCallbackToken]: Best-effort validation of signed `?t=` URL query parameters.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:hashlib/hashlib.dart';
import 'package:zenpay_dart/zenpay_dart.dart';

import 'checkout_state.dart' show CheckoutAttempt;
import 'config.dart' show ZenPayCredentials;

/// Compares two strings [a] and [b] in constant time, avoiding a timing side-channel.
///
/// Hashes both operands to SHA-256 digests and performs timing-safe byte equality
/// comparison. Used for validating Bearer authentication tokens and sensitive references.
bool constantTimeEqual(String a, String b) =>
    HashDigest(Uint8List.fromList(utf8.encode(a))).isEqual(utf8.encode(b));

/// Structured callback payload fields persisted against a [CheckoutAttempt].
class CallbackFields {
  const CallbackFields({
    required this.merchantUniquePaymentId,
    required this.validationCode,
    required this.reference,
    required this.statusCode,
    this.failureCode,
    this.failureReason,
  });

  final String merchantUniquePaymentId;

  /// The SHA3-512 ValidationCode signature echoed by ZenPay in the callback.
  final String validationCode;

  /// Transaction, preauth, or token reference assigned by ZenPay upon completion.
  final String reference;

  /// ZenPay raw numeric status code (e.g. 3 for Successful, 4 for Failed).
  final int statusCode;

  final String? failureCode;
  final String? failureReason;
}

/// The result of authenticating and verifying an incoming ZenPay webhook callback body.
class CallbackVerification {
  const CallbackVerification.ok(this.fields) : reason = null;

  const CallbackVerification.rejected(this.reason) : fields = null;

  /// Extracted callback fields when verification succeeded, or `null` if rejected.
  final CallbackFields? fields;

  /// Rejection diagnostic reason (`"malformed"` or `"rejected"`), or `null` on success.
  ///
  /// - `"malformed"`: Payload does not conform to the expected schema for the attempt's mode.
  /// - `"rejected"`: Payload was well-formed but failed SHA3-512 `ValidationCode` cryptographic check.
  final String? reason;

  bool get ok => fields != null;
}

/// Verifies an incoming ZenPay webhook [payload] against a stored [attempt] and
/// merchant [credentials] using `package:zenpay_dart`'s `verifyZpCallback`.
///
/// Recomputes the SHA3-512 hash over the response fields, merchant password,
/// and attempt metadata, ensuring the callback payload was minted by ZenPay
/// and has not been tampered with in transit.
///
/// Returns [CallbackVerification.ok] with extracted [CallbackFields] on success,
/// or [CallbackVerification.rejected] if malformed or mismatched.
CallbackVerification verifyCallback(
  Map<String, Object?> payload,
  CheckoutAttempt attempt,
  ZenPayCredentials credentials,
) {
  final mode = ZpPluginMode.fromWireValue(attempt.mode);
  final result = verifyZpCallback(
    mode,
    payload,
    ZpVerifyCallbackContext(
      apiKey: credentials.apiKey,
      username: credentials.username,
      password: credentials.password,
      paymentAmount: attempt.amount,
      merchantUniquePaymentId: ZpMupid(attempt.merchantUniquePaymentId),
    ),
  );

  switch (result) {
    case ZpCallbackMalformed():
      return const CallbackVerification.rejected('malformed');
    case ZpCallbackRejected():
      return const CallbackVerification.rejected('rejected');
    case ZpCallbackVerified():
      break;
  }

  // The package already verifies echoedMupid if present.
  return CallbackVerification.ok(
    CallbackFields(
      merchantUniquePaymentId: attempt.merchantUniquePaymentId,
      validationCode: payload['validationCode'] as String,
      reference: result.reference,
      statusCode: result.statusCode,
      failureCode: result.failureCode,
      failureReason: result.failureReason,
    ),
  );
}

/// Checks the optional signed `?t=<token>` query parameter on an incoming callback URL.
///
/// Validates HMAC-SHA3-512 signatures minted by `session_service.dart` during launch URL
/// construction.
///
/// Best-effort only: this check produces audit telemetry for request logging and
/// **never** gates callback acceptance — [verifyCallback]'s SHA3-512 `ValidationCode`
/// check remains the sole authoritative proof of payment integrity.
///
/// Returns `null` when no secret is configured (feature inactive) or [tokenRaw] was absent.
({bool verified, String detail})? checkCallbackToken(
  String? tokenRaw,
  String secret,
) {
  if (secret.length < 32) return null;
  if (tokenRaw == null) return (verified: false, detail: 'absent');

  final result = verifyZpCallbackUrlToken(tokenRaw, secret);
  return switch (result) {
    ZpCallbackUrlTokenVerified(:final payload) => (
      verified: true,
      detail: payload.merchantUniquePaymentId,
    ),
    ZpCallbackUrlTokenFailure(:final reason) => (
      verified: false,
      detail: reason.name,
    ),
  };
}
