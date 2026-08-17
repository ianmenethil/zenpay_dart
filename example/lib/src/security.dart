/// Backend-local security primitives: constant-time comparison for bearer
/// tokens and callback references, and the mode-aware callback verifier
/// built on top of `package:zenpay_dart/server.dart`.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:hashlib/hashlib.dart';
import 'package:zenpay_dart/zenpay_dart.dart';

import 'checkout_state.dart' show CheckoutAttempt;
import 'config.dart' show ZenPayCredentials;

/// Compares two strings in constant time, avoiding a timing side-channel.
bool constantTimeEqual(String a, String b) =>
    HashDigest(Uint8List.fromList(utf8.encode(a))).isEqual(utf8.encode(b));

/// The callback fields this backend persists against an attempt.
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
  final String validationCode;
  final String reference;
  final int statusCode;
  final String? failureCode;
  final String? failureReason;
}

/// The result of verifying a ZenPay callback body.
class CallbackVerification {
  const CallbackVerification.ok(this.fields) : reason = null;

  const CallbackVerification.rejected(this.reason) : fields = null;

  /// Non-null when verification succeeded.
  final CallbackFields? fields;

  /// `"malformed"` (body does not match the mode's schema) or `"rejected"`
  /// (schema matched but the hash, reference, or amount did not).
  /// Null when [fields] is non-null.
  final String? reason;

  bool get ok => fields != null;
}

/// Verifies a ZenPay callback [payload] against [attempt] and
/// [credentials] via `package:zenpay_dart`'s `verifyZpCallback`.
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

/// Checks the optional signed `?t=<token>` on an incoming callback URL,
/// minted per attempt by `session_service.dart`'s callback-URL builder.
///
/// Best-effort only: the result is for logging, and never gates callback
/// acceptance — [verifyCallback]'s SHA3-512 `validationCode` check remains
/// the sole authority. Returns `null` when no secret is configured (the
/// feature is inactive) or [tokenRaw] was not supplied.
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
