/// Outgoing ZenPay HCP Authorise fingerprint generation.
library;

import 'crypto.dart';
import 'enums.dart';

/// Fields required to generate an Authorise fingerprint.
class ZpFingerprintRequest {
  /// Creates a fingerprint request.
  const ZpFingerprintRequest({
    required this.apiKey,
    required this.username,
    required this.password,
    required this.mode,
    required this.merchantUniquePaymentId,
    required this.timestamp,
    this.paymentAmount,
  });

  /// Merchant API key — hash field 1.
  final String apiKey;

  /// Merchant username — hash field 2.
  final String username;

  /// Merchant password — hash field 3.
  final String password;

  /// Payment operating mode — hash field 4.
  final ZpPluginMode mode;

  /// Payment amount in dollars — hash field 5.
  ///
  /// Optional for tokenisation. Modes 0, 2 and 3 require a positive amount.
  /// Mode 2 still hashes `"0"` regardless of the supplied amount.
  final Object? paymentAmount;

  /// Per-payment Merchant Unique Payment ID — hash field 6.
  final ZpMupid merchantUniquePaymentId;

  /// UTC `yyyy-MM-ddTHH:mm:ss` timestamp — hash field 7.
  final ZpTimestamp timestamp;
}

/// Result of [createZpFingerprint].
sealed class ZpFingerprintResult {
  const ZpFingerprintResult();
}

/// A successfully generated fingerprint.
final class ZpFingerprintSuccess extends ZpFingerprintResult {
  /// Creates a successful fingerprint result.
  const ZpFingerprintSuccess(this.fingerprint);

  /// 128-character lowercase SHA3-512 digest.
  final String fingerprint;
}

/// A fingerprint validation failure.
final class ZpFingerprintFailure extends ZpFingerprintResult {
  /// Creates a fingerprint validation failure.
  const ZpFingerprintFailure(this.message);

  /// Why fingerprint creation failed.
  final String message;
}

(ZpCents?, ZpFingerprintFailure?) _validate(ZpFingerprintRequest request) {
  if (request.apiKey.length < zpMinCredentialLength) {
    return (
      null,
      const ZpFingerprintFailure('apiKey must be at least 5 characters'),
    );
  }

  if (request.username.length < zpMinCredentialLength) {
    return (
      null,
      const ZpFingerprintFailure('username must be at least 5 characters'),
    );
  }

  if (request.password.length < zpMinCredentialLength) {
    return (
      null,
      const ZpFingerprintFailure('password must be at least 5 characters'),
    );
  }

  if (request.merchantUniquePaymentId.value.length < zpMinCredentialLength) {
    return (
      null,
      const ZpFingerprintFailure(
        'merchantUniquePaymentId must be at least 5 characters',
      ),
    );
  }

  if (!isValidZpTimestamp(request.timestamp.value)) {
    return (
      null,
      const ZpFingerprintFailure(
        'timestamp must be in YYYY-MM-DDTHH:MM:SS format',
      ),
    );
  }

  final (amount, failureReason) = resolveZpHashAmountChecked(
    request.mode,
    request.paymentAmount,
  );

  if (failureReason == null) {
    return (amount, null);
  }

  return (
    null,
    switch (failureReason) {
      ZpAmountFailureReason.notANumber => const ZpFingerprintFailure(
        zpErrPaymentAmountNumber,
      ),
      ZpAmountFailureReason.notPositive => const ZpFingerprintFailure(
        zpErrPaymentAmountPositive,
      ),
      ZpAmountFailureReason.unresolvable => ZpFingerprintFailure(
        'invalid amount "${request.paymentAmount}" — expected a '
        'non-negative number with at most 2 decimal places',
      ),
    },
  );
}

/// Validates [request] without computing a fingerprint.
///
/// Returns `null` when [request] is valid.
ZpFingerprintFailure? validateZpFingerprintRequest(
  ZpFingerprintRequest request,
) {
  final (_, failure) = _validate(request);
  return failure;
}

/// Creates the SHA3-512 fingerprint required by ZenPay Authorise.
///
/// Generate a fresh fingerprint, MUPID and timestamp for every plugin open.
/// Merchant credentials must remain server-side.
ZpFingerprintResult createZpFingerprint(ZpFingerprintRequest request) {
  final (amount, failure) = _validate(request);

  if (failure != null) {
    return failure;
  }

  final pipe = [
    request.apiKey,
    request.username,
    request.password,
    request.mode.wireValue,
    amount!.value,
    request.merchantUniquePaymentId.value,
    request.timestamp.value,
  ].join(zpPipeDelimiter);

  return ZpFingerprintSuccess(createSha3_512(pipe));
}
