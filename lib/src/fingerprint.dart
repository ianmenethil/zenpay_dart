/// Outgoing Authorise fingerprint generation.
library;

import 'crypto.dart';
import 'enums.dart';

const _minCredentialLength = 5;
const _pipeDelimiter = '|';

const _errApiKeyLength = 'apiKey must be at least 5 characters';
const _errUsernameLength = 'username must be at least 5 characters';
const _errPasswordLength = 'password must be at least 5 characters';
const _errMupidLength = 'merchantUniquePaymentId must be at least 5 characters';
const _errTimestampFormat = 'timestamp must be in YYYY-MM-DDTHH:MM:SS format';
const _errPaymentAmountNumber = 'paymentAmount must be a valid number';
const _errPaymentAmountPositive = 'paymentAmount must be greater than 0';

/// The seven fields required to generate an outgoing Authorise fingerprint.
class ZpFingerprintRequest {
  /// Creates the input to [createZpFingerprint].
  const ZpFingerprintRequest({
    required this.apiKey,
    required this.username,
    required this.password,
    required this.mode,
    required this.paymentAmount,
    required this.merchantUniquePaymentId,
    required this.timestamp,
  });

  /// Merchant API key — hash field 1.
  final String apiKey;

  /// Merchant username — hash field 2.
  final String username;

  /// Merchant password — hash field 3.
  final String password;

  /// Payment operating mode — hash field 4.
  final ZpPluginMode mode;

  /// Payment amount in dollars (string or number) — hash field 5.
  final Object paymentAmount;

  /// Per-payment idempotency key — hash field 6.
  final ZpMupid merchantUniquePaymentId;

  /// UTC ISO 8601 timestamp exactly in `yyyy-MM-ddTHH:mm:ss` format — hash
  /// field 7. Reuse the exact same string in the launch URL.
  final ZpTimestamp timestamp;
}

/// Result of [createZpFingerprint]: exhaustively pattern-match with a
/// `switch` over [ZpFingerprintSuccess] / [ZpFingerprintFailure].
sealed class ZpFingerprintResult {
  const ZpFingerprintResult();
}

/// A successfully computed fingerprint.
final class ZpFingerprintSuccess extends ZpFingerprintResult {
  /// Creates a successfully computed fingerprint result.
  const ZpFingerprintSuccess(this.fingerprint);

  /// 128-character lowercase hex digest.
  final String fingerprint;
}

/// A validation failure, with a human-readable [message].
final class ZpFingerprintFailure extends ZpFingerprintResult {
  /// Creates a fingerprint validation failure result.
  const ZpFingerprintFailure(this.message);

  /// Human-readable description of why fingerprint creation failed.
  final String message;
}

(ZpCents?, ZpFingerprintFailure?) _validateFingerprintRequest(
  ZpFingerprintRequest request,
) {
  if (request.apiKey.length < _minCredentialLength) {
    return (null, const ZpFingerprintFailure(_errApiKeyLength));
  }
  if (request.username.length < _minCredentialLength) {
    return (null, const ZpFingerprintFailure(_errUsernameLength));
  }
  if (request.password.length < _minCredentialLength) {
    return (null, const ZpFingerprintFailure(_errPasswordLength));
  }
  if (request.merchantUniquePaymentId.value.length < _minCredentialLength) {
    return (null, const ZpFingerprintFailure(_errMupidLength));
  }
  if (!isValidZpTimestamp(request.timestamp.value)) {
    return (null, const ZpFingerprintFailure(_errTimestampFormat));
  }

  final numericAmount = num.tryParse(request.paymentAmount.toString().trim());
  if (numericAmount == null) {
    return (null, const ZpFingerprintFailure(_errPaymentAmountNumber));
  }
  if (request.mode.requiresPositiveAmount && numericAmount <= 0) {
    return (null, const ZpFingerprintFailure(_errPaymentAmountPositive));
  }

  final amountField = resolveZpHashAmountField(
    request.mode,
    request.paymentAmount,
  );
  if (amountField == null) {
    return (
      null,
      ZpFingerprintFailure(
        'invalid amount "${request.paymentAmount}" — expected a non-negative '
        'number with at most 2 decimal places',
      ),
    );
  }

  return (amountField, null);
}

/// Validates [request] without computing a fingerprint — the
/// standalone-callable counterpart of the checks [createZpFingerprint] runs
/// internally. Equivalent to `ZpFingerprintInputSchema` on the TypeScript
/// side. Returns `null` when [request] is valid.
ZpFingerprintFailure? validateZpFingerprintRequest(
  ZpFingerprintRequest request,
) {
  final (_, failure) = _validateFingerprintRequest(request);
  return failure;
}

/// Creates the ZenPay HCP `fingerprint` required in every Authorise request.
///
/// Pass [ZpFingerprintRequest.paymentAmount] in dollars — converted to whole
/// cents internally; mode 2 always hashes `"0"`. Never throws.
ZpFingerprintResult createZpFingerprint(ZpFingerprintRequest request) {
  final (amountField, failure) = _validateFingerprintRequest(request);
  if (failure != null) return failure;

  final fingerprint = createSha3_512(
    [
      request.apiKey,
      request.username,
      request.password,
      request.mode.wireValue.toString(),
      amountField!.value,
      request.merchantUniquePaymentId.value,
      request.timestamp.value,
    ].join(_pipeDelimiter),
  );
  return ZpFingerprintSuccess(fingerprint);
}
