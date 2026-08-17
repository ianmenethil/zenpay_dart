/// Incoming HCP callback verification: one verifier, [verifyZpCallback],
/// over a single SHA3-512 hash check.
///
/// A verified result proves callback *authenticity*, not payment *success*
/// — check [ZpCallbackVerified.statusCode] against [ZpPaymentStatus]
/// separately.
library;

import 'crypto.dart';
import 'enums.dart';

const _minCredentialLength = 5;
final _validationCodePattern = RegExp(r'^[0-9a-f]{128}$');

// Wire / JSON field names
const _fieldResponse = 'response';
const _fieldValidationCode = 'validationCode';
const _fieldMerchantUniquePaymentId = 'merchantUniquePaymentId';
const _fieldPaymentStatus = 'paymentStatus';
const _fieldPreauthStatus = 'preauthStatus';
const _fieldFailureCode = 'failureCode';
const _fieldFailureReason = 'failureReason';

// Business-data fields shared by payment (mode 0/2) and preauth (mode 3)
// responses — never card/account-shaped, safe to surface on the result.
const _fieldCustomerReference = 'customerReference';
const _fieldMerchantCode = 'merchantCode';
const _fieldAdditionalReference = 'additionalReference';
const _fieldBaseAmount = 'baseAmount';
const _fieldCustomerFee = 'customerFee';
const _fieldProcessorReference = 'processorReference';
const _fieldProcessingDate = 'processingDate';
const _fieldTransactionSource = 'transactionSource';
const _fieldTransactionSourceString = 'transactionSourceString';

// Payment-only (mode 0/2) business-data fields.
const _fieldPaymentStatusString = 'paymentStatusString';
const _fieldFundsToMerchant = 'fundsToMerchant';
const _fieldSettlementDate = 'settlementDate';
const _fieldIsPaymentSettledToMerchant = 'isPaymentSettledToMerchant';
const _fieldProcessedAmount = 'processedAmount';
const _fieldPayToStatus = 'payToStatus';
const _fieldSku1 = 'sku1';
const _fieldSku2 = 'sku2';
const _fieldAdditionalData = 'additionalData';
const _fieldAuthCode = 'authCode';
const _fieldRrn = 'rrn';
const _fieldStan = 'stan';

// Preauth-only (mode 3) business-data fields.
const _fieldPreauthStatusString = 'preauthStatusString';
const _fieldPreauthAmount = 'preauthAmount';
const _fieldPreauthExpiryAt = 'preauthExpiryAt';

// Tokenise-only (mode 1) business-data fields.
const _fieldPaymentDetail = 'paymentDetail';
const _fieldMerchantFee = 'merchantFee';
const _fieldProcessingAmount = 'processingAmount';
const _fieldPaymentAmount = 'paymentAmount';
const _fieldDoRedirect = 'doRedirect';

// Delimiters
const _pipeDelimiter = '|';

// Validation error messages
const _errValidationCodeHex =
    'validationCode must be a 128-character hex string';
const _errCredentialLength =
    'apiKey, username, password, and merchantUniquePaymentId must each '
    'be at least 5 characters';
const _errPaymentAmountNumber = 'paymentAmount must be a valid number';
const _errPaymentAmountPositive = 'paymentAmount must be greater than 0';
const _errPaymentAmountInvalid = 'paymentAmount is invalid';
const _errValidationCodeMismatch =
    'validationCode does not match the computed hash';
const _errMupidMismatch =
    'response.merchantUniquePaymentId does not match the launched attempt';
const _errMalformedBody =
    'body must contain a response object and a validationCode string';

/// Merchant-known credentials, amount, and mupid used to verify a callback.
class ZpVerifyCallbackContext {
  /// Creates the context [verifyZpCallback] hashes against.
  const ZpVerifyCallbackContext({
    required this.apiKey,
    required this.username,
    required this.password,
    required this.paymentAmount,
    required this.merchantUniquePaymentId,
  });

  /// Merchant API key — hash field 1.
  final String apiKey;

  /// Merchant username — hash field 2.
  final String username;

  /// Merchant password — hash field 3.
  final String password;

  /// Payment amount in dollars, as launched — hash field 5. Ignored for
  /// mode 2 (always hashes `"0"`); may be `0`/absent for mode 1.
  final Object paymentAmount;

  /// Per-payment idempotency key — hash field 6. Also checked (when the
  /// callback body echoes one) against the response's own
  /// `merchantUniquePaymentId`, so a callback cannot be replayed against
  /// the wrong attempt even with a valid hash.
  final ZpMupid merchantUniquePaymentId;
}

/// Result of [verifyZpCallback]: exhaustively pattern-match with a `switch`
/// over [ZpCallbackVerified] / [ZpCallbackMalformed] / [ZpCallbackRejected].
sealed class ZpCallbackResult {
  const ZpCallbackResult();
}

/// Acquirer auth-trace fields nested in a payment (mode 0/2) response's
/// `additionalData`. Trace numbers, not card data — safe to surface.
final class ZpCallbackAdditionalData {
  /// Creates acquirer auth-trace data from a callback response.
  const ZpCallbackAdditionalData({this.authCode, this.rrn, this.stan});

  /// Card-network authorization code.
  final String? authCode;

  /// Retrieval reference number.
  final String? rrn;

  /// System trace audit number.
  final String? stan;
}

/// Fee breakdown nested in a tokenise (mode 1) response's `paymentDetail`.
final class ZpTokenisePaymentDetail {
  /// Creates a fee breakdown from a tokenise callback response.
  const ZpTokenisePaymentDetail({
    this.customerFee,
    this.merchantFee,
    this.processingAmount,
    this.paymentAmount,
  });

  /// Fee charged to the customer.
  final num? customerFee;

  /// Fee charged to the merchant.
  final num? merchantFee;

  /// Amount actually processed.
  final num? processingAmount;

  /// Payment amount associated with the tokenise attempt.
  final num? paymentAmount;
}

/// An authentic callback. [statusCode] is a raw [ZpPaymentStatus] wire
/// value — check [ZpPaymentStatus.isSuccessful], do not compare to a
/// literal.
///
/// Every field below `failureReason` is business/reconciliation data, never
/// card- or account-shaped — see the PCI test in `callback_test.dart`
/// ("card/account-shaped optional callback fields do not affect
/// verification"). Fields not applicable to [statusCode]'s originating
/// mode are `null` (e.g. [preauthAmount] is only ever set for mode 3).
final class ZpCallbackVerified extends ZpCallbackResult {
  /// Creates an authentic callback verification result.
  const ZpCallbackVerified({
    required this.reference,
    required this.statusCode,
    this.failureCode,
    this.failureReason,
    this.customerReference,
    this.merchantUniquePaymentId,
    this.merchantCode,
    this.additionalReference,
    this.baseAmount,
    this.customerFee,
    this.processorReference,
    this.processingDate,
    this.transactionSource,
    this.transactionSourceString,
    this.statusLabel,
    this.fundsToMerchant,
    this.settlementDate,
    this.isPaymentSettledToMerchant,
    this.processedAmount,
    this.payToStatus,
    this.sku1,
    this.sku2,
    this.additionalData,
    this.preauthAmount,
    this.preauthExpiryAt,
    this.paymentDetail,
    this.doRedirect,
  });

  /// The mode-specific reference: `paymentReference`, `preauthReference`,
  /// or `token`.
  final String reference;

  /// Raw payment status code returned by ZenPay.
  final int statusCode;

  /// Optional failure code if payment failed.
  final String? failureCode;

  /// Optional failure reason string if payment failed.
  final String? failureReason;

  // Shared by payment (mode 0/2) and preauth (mode 3).

  /// Customer reference echoed from launch.
  final String? customerReference;

  /// Merchant unique payment id echoed from launch.
  final String? merchantUniquePaymentId;

  /// Merchant code echoed from launch.
  final String? merchantCode;

  /// Additional merchant reference echoed from launch.
  final String? additionalReference;

  /// Pre-fee base amount.
  final num? baseAmount;

  /// Fee charged to the customer.
  final num? customerFee;

  /// Processor-side reference for this transaction.
  final String? processorReference;

  /// Date the transaction was processed.
  final String? processingDate;

  /// Numeric transaction source code.
  final num? transactionSource;

  /// Human-readable transaction source label.
  final String? transactionSourceString;

  // Payment-only (mode 0/2).

  /// Human-readable label for [statusCode] (`paymentStatusString` /
  /// `preauthStatusString` on the wire — unified here, matching how
  /// [statusCode] itself already unifies `paymentStatus`/`preauthStatus`).
  final String? statusLabel;

  /// Funds settled to the merchant.
  final num? fundsToMerchant;

  /// Date funds were settled to the merchant.
  final String? settlementDate;

  /// Whether funds have been settled to the merchant.
  final bool? isPaymentSettledToMerchant;

  /// Amount actually processed.
  final num? processedAmount;

  /// PayTo-specific status, when the payment method was PayTo.
  final String? payToStatus;

  /// Product SKU 1, echoed from launch.
  final String? sku1;

  /// Product SKU 2, echoed from launch.
  final String? sku2;

  /// Acquirer auth-trace numbers (authCode/rrn/stan).
  final ZpCallbackAdditionalData? additionalData;

  // Preauth-only (mode 3).

  /// Held preauthorization amount.
  final num? preauthAmount;

  /// When the preauthorization hold expires.
  final String? preauthExpiryAt;

  // Tokenise-only (mode 1).

  /// Fee breakdown for the tokenise attempt.
  final ZpTokenisePaymentDetail? paymentDetail;

  /// Whether the caller should redirect after tokenisation.
  final bool? doRedirect;
}

/// The callback body does not match the expected shape for [mode] — a
/// client/network problem, not a security rejection. Callers typically
/// answer HTTP 400.
final class ZpCallbackMalformed extends ZpCallbackResult {
  /// Creates a malformed callback result with an explanatory message.
  const ZpCallbackMalformed(this.message);

  /// Human-readable explanation of why the callback was malformed.
  final String message;
}

/// The body was shaped correctly but failed verification — a wrong hash,
/// or a reference/mupid that does not match the launched attempt. Callers
/// typically answer HTTP 401.
final class ZpCallbackRejected extends ZpCallbackResult {
  /// Creates a rejected callback result with an explanatory message.
  const ZpCallbackRejected(this.message);

  /// Human-readable explanation of why the callback was rejected.
  final String message;
}

(ZpCents?, ZpCallbackRejected?) _validateCallbackContext(
  ZpPluginMode mode,
  ZpVerifyCallbackContext context,
) {
  if (context.apiKey.length < _minCredentialLength ||
      context.username.length < _minCredentialLength ||
      context.password.length < _minCredentialLength ||
      context.merchantUniquePaymentId.value.length < _minCredentialLength) {
    return (null, const ZpCallbackRejected(_errCredentialLength));
  }

  final numericAmount = num.tryParse(context.paymentAmount.toString().trim());
  if (numericAmount == null) {
    return (null, const ZpCallbackRejected(_errPaymentAmountNumber));
  }
  if (mode.requiresPositiveAmount && numericAmount <= 0) {
    return (null, const ZpCallbackRejected(_errPaymentAmountPositive));
  }

  final amountField = resolveZpHashAmountField(mode, context.paymentAmount);
  if (amountField == null) {
    return (null, const ZpCallbackRejected(_errPaymentAmountInvalid));
  }

  return (amountField, null);
}

bool _verifyCallbackHash({
  required ZpPluginMode mode,
  required ZpVerifyCallbackContext context,
  required ZpCents amountField,
  required String reference,
  required String validationCode,
}) {
  final pipe = [
    context.apiKey,
    context.username,
    context.password,
    mode.wireValue.toString(),
    amountField.value,
    context.merchantUniquePaymentId.value,
    reference,
  ].join(_pipeDelimiter);

  return constantTimeHexEqual(createSha3_512(pipe), validationCode);
}

typedef _CallbackShape = ({
  Map<String, Object?>? response,
  String? reference,
  String? validationCode,
  ZpCallbackMalformed? failure,
});

_CallbackShape _extractCallbackShape(
  ZpPluginMode mode,
  Map<String, Object?> body,
) {
  if (body case {
    _fieldResponse: final Map<String, Object?> response,
    _fieldValidationCode: final String validationCode,
  }) {
    final referenceField = mode.callbackReferenceField;
    final reference = response[referenceField];
    if (reference is! String || reference.trim().isEmpty) {
      return (
        response: null,
        reference: null,
        validationCode: null,
        failure: ZpCallbackMalformed(
          'response.$referenceField must not be empty',
        ),
      );
    }

    if (!_validationCodePattern.hasMatch(validationCode)) {
      return (
        response: null,
        reference: null,
        validationCode: null,
        failure: const ZpCallbackMalformed(_errValidationCodeHex),
      );
    }

    return (
      response: response,
      reference: reference,
      validationCode: validationCode,
      failure: null,
    );
  }
  return (
    response: null,
    reference: null,
    validationCode: null,
    failure: const ZpCallbackMalformed(_errMalformedBody),
  );
}

/// Validates that [body] has the shape a callback for [mode] must have — a
/// `response` object with a non-empty mode-specific reference field, and a
/// 128-character hex `validationCode` — without checking authenticity. The
/// standalone-callable counterpart of the shape checks [verifyZpCallback]
/// runs internally. Equivalent to `ZpPaymentCallbackBodySchema` /
/// `ZpPreauthCallbackBodySchema` / `ZpTokeniseCallbackBodySchema` on the
/// TypeScript side — one schema per mode there; parameterized by [mode]
/// here, matching [verifyZpCallback]'s own shape. Returns `null` when
/// [body] is well-shaped for [mode].
ZpCallbackMalformed? validateZpCallbackBody(
  ZpPluginMode mode,
  Map<String, Object?> body,
) => _extractCallbackShape(mode, body).failure;

ZpCallbackAdditionalData? _extractAdditionalData(
  Map<String, Object?> response,
) {
  final raw = response[_fieldAdditionalData];
  if (raw is! Map<String, Object?>) return null;
  return ZpCallbackAdditionalData(
    authCode: raw[_fieldAuthCode] as String?,
    rrn: raw[_fieldRrn] as String?,
    stan: raw[_fieldStan] as String?,
  );
}

ZpTokenisePaymentDetail? _extractPaymentDetail(Map<String, Object?> response) {
  final raw = response[_fieldPaymentDetail];
  if (raw is! Map<String, Object?>) return null;
  return ZpTokenisePaymentDetail(
    customerFee: raw[_fieldCustomerFee] as num?,
    merchantFee: raw[_fieldMerchantFee] as num?,
    processingAmount: raw[_fieldProcessingAmount] as num?,
    paymentAmount: raw[_fieldPaymentAmount] as num?,
  );
}

/// Builds the verified result, populating only the business fields that
/// apply to [mode] — tokenise (1) never carries the shared payment/preauth
/// fields, and preauth (3) never carries the payment-only ones.
ZpCallbackVerified _buildVerified(
  ZpPluginMode mode,
  String reference,
  int statusCode,
  Map<String, Object?> response,
) {
  final failureCode = response[_fieldFailureCode] as String?;
  final failureReason = response[_fieldFailureReason] as String?;

  if (mode == ZpPluginMode.tokenise) {
    return ZpCallbackVerified(
      reference: reference,
      statusCode: statusCode,
      failureCode: failureCode,
      failureReason: failureReason,
      paymentDetail: _extractPaymentDetail(response),
      doRedirect: response[_fieldDoRedirect] as bool?,
    );
  }

  final isPreauth = mode == ZpPluginMode.preauthorization;
  return ZpCallbackVerified(
    reference: reference,
    statusCode: statusCode,
    failureCode: failureCode,
    failureReason: failureReason,
    customerReference: response[_fieldCustomerReference] as String?,
    merchantUniquePaymentId: response[_fieldMerchantUniquePaymentId] as String?,
    merchantCode: response[_fieldMerchantCode] as String?,
    additionalReference: response[_fieldAdditionalReference] as String?,
    baseAmount: response[_fieldBaseAmount] as num?,
    customerFee: response[_fieldCustomerFee] as num?,
    processorReference: response[_fieldProcessorReference] as String?,
    processingDate: response[_fieldProcessingDate] as String?,
    transactionSource: response[_fieldTransactionSource] as num?,
    transactionSourceString: response[_fieldTransactionSourceString] as String?,
    statusLabel: isPreauth
        ? response[_fieldPreauthStatusString] as String?
        : response[_fieldPaymentStatusString] as String?,
    fundsToMerchant: isPreauth ? null : response[_fieldFundsToMerchant] as num?,
    settlementDate: isPreauth
        ? null
        : response[_fieldSettlementDate] as String?,
    isPaymentSettledToMerchant: isPreauth
        ? null
        : response[_fieldIsPaymentSettledToMerchant] as bool?,
    processedAmount: isPreauth ? null : response[_fieldProcessedAmount] as num?,
    payToStatus: isPreauth ? null : response[_fieldPayToStatus] as String?,
    sku1: isPreauth ? null : response[_fieldSku1] as String?,
    sku2: isPreauth ? null : response[_fieldSku2] as String?,
    additionalData: isPreauth ? null : _extractAdditionalData(response),
    preauthAmount: isPreauth ? response[_fieldPreauthAmount] as num? : null,
    preauthExpiryAt: isPreauth
        ? response[_fieldPreauthExpiryAt] as String?
        : null,
  );
}

int _extractStatusCode(ZpPluginMode mode, Map<String, Object?> response) {
  final statusField = switch (mode) {
    ZpPluginMode.makePayment ||
    ZpPluginMode.customPayment => _fieldPaymentStatus,
    ZpPluginMode.preauthorization => _fieldPreauthStatus,
    ZpPluginMode.tokenise => null,
  };

  return statusField == null
      ? ZpPaymentStatus.successful.wireValue
      : (response[statusField] as num?)?.toInt() ??
            ZpPaymentStatus.pending.wireValue;
}

/// Verifies the authenticity of an incoming HCP callback — payment (mode
/// 0/2), preauth (mode 3), or tokenise (mode 1) — by recomputing the
/// SHA3-512 hash and comparing it (constant-time) to `body.validationCode`.
///
/// Recover [mode] from your own launch state — never sniff it from [body].
/// Never throws.
ZpCallbackResult verifyZpCallback(
  ZpPluginMode mode,
  Map<String, Object?> body,
  ZpVerifyCallbackContext context,
) {
  final shape = _extractCallbackShape(mode, body);
  if (shape.failure != null) return shape.failure!;
  final response = shape.response!;
  final reference = shape.reference!;
  final validationCode = shape.validationCode!;

  final (amountField, contextError) = _validateCallbackContext(mode, context);
  if (contextError != null) return contextError;

  if (!_verifyCallbackHash(
    mode: mode,
    context: context,
    amountField: amountField!,
    reference: reference,
    validationCode: validationCode,
  )) {
    return const ZpCallbackRejected(_errValidationCodeMismatch);
  }

  // The hash proves the callback is authentic for *some* attempt with this
  // mupid; this catches a callback body whose own echoed id disagrees with
  // it (relevant for modes 0/2, which carry it in the response).
  if (response case {_fieldMerchantUniquePaymentId: final String echoedMupid}) {
    if (echoedMupid.isNotEmpty &&
        echoedMupid != context.merchantUniquePaymentId.value) {
      return const ZpCallbackRejected(_errMupidMismatch);
    }
  }

  final statusCode = _extractStatusCode(mode, response);

  return _buildVerified(mode, reference, statusCode, response);
}
