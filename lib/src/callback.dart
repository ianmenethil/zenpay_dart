/// Incoming HCP callback verification.
///
/// A verified result proves callback *authenticity*, not payment *success*.
/// Check [ZpCallbackVerified.statusCode] against [ZpPaymentStatus] separately.
library;

import 'crypto.dart';
import 'enums.dart';

final _validationCodePattern = RegExp(r'^[0-9a-f]{128}$');

const _errValidationCodeHex =
    'validationCode must be a 128-character hex string';

const _errCredentialLength =
    'apiKey, username, password, and merchantUniquePaymentId must each '
    'be at least 5 characters';

const _errPaymentAmountInvalid = 'paymentAmount is invalid';

const _errValidationCodeMismatch =
    'validationCode does not match the computed hash';

const _errMupidMismatch =
    'response.merchantUniquePaymentId does not match the launched attempt';

const _errMalformedBody =
    'body must contain a response object and a validationCode string';

/// Merchant-known credentials, amount, and MUPID used to verify a callback.
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

  /// Payment amount in dollars, as launched — hash field 5.
  ///
  /// Ignored for mode 2, which always hashes `"0"`. May be `0` for mode 1.
  final Object paymentAmount;

  /// Per-payment idempotency key — hash field 6.
  ///
  /// When the callback echoes its own `merchantUniquePaymentId`, that value
  /// is also checked against this value.
  final ZpMupid merchantUniquePaymentId;
}

/// Result of [verifyZpCallback].
///
/// Exhaustively pattern-match with a `switch` over [ZpCallbackVerified],
/// [ZpCallbackMalformed], and [ZpCallbackRejected].
sealed class ZpCallbackResult {
  const ZpCallbackResult();
}

/// Acquirer authorization trace fields returned in `additionalData`.
final class ZpCallbackAdditionalData {
  /// Creates acquirer authorization trace data.
  const ZpCallbackAdditionalData({this.authCode, this.rrn, this.stan});

  /// Card-network authorization code.
  final String? authCode;

  /// Retrieval reference number.
  final String? rrn;

  /// System trace audit number.
  final String? stan;
}

/// Fee breakdown returned by a tokenisation callback.
final class ZpTokenisePaymentDetail {
  /// Creates a tokenisation payment-detail result.
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

  /// Payment amount associated with the tokenisation attempt.
  final num? paymentAmount;
}

/// An authentic callback.
///
/// [statusCode] is a raw [ZpPaymentStatus] wire value. Check
/// [ZpPaymentStatus.isSuccessful] rather than comparing against a literal.
final class ZpCallbackVerified extends ZpCallbackResult {
  /// Creates an authentic callback verification result.
  const ZpCallbackVerified({
    required this.reference,
    required this.statusCode,
    this.failureCode,
    this.failureReason,
    this.customerName,
    this.customerReference,
    this.merchantUniquePaymentId,
    this.merchantCode,
    this.additionalReference,
    this.cardCategory,
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
    this.token,
    this.cardInformationSaved,
    this.cardTypeValue,
    this.cardTypeString,
    this.subCardTypeString,
    this.preauthAmount,
    this.preauthExpiryAt,
    this.paymentDetail,
    this.doRedirect,
    this.cardType,
    this.isRestrictedCard,
  });

  /// Mode-specific payment, preauthorization, or token reference.
  final String reference;

  /// Raw payment status code returned by ZenPay.
  final int statusCode;

  /// Optional failure code.
  final String? failureCode;

  /// Optional failure reason.
  final String? failureReason;

  /// Customer name echoed from launch.
  final String? customerName;

  /// Customer reference echoed from launch.
  final String? customerReference;

  /// Merchant unique payment ID echoed from launch.
  final String? merchantUniquePaymentId;

  /// Merchant code echoed from launch.
  final String? merchantCode;

  /// Additional merchant reference echoed from launch.
  final String? additionalReference;

  /// Card category label. Payment/preauthorization only.
  final String? cardCategory;

  /// Pre-fee base amount.
  final num? baseAmount;

  /// Fee charged to the customer.
  final num? customerFee;

  /// Processor-side transaction reference.
  final String? processorReference;

  /// Date the transaction was processed.
  final String? processingDate;

  /// Numeric transaction source code.
  final num? transactionSource;

  /// Human-readable transaction source label.
  final String? transactionSourceString;

  /// Human-readable payment or preauthorization status.
  final String? statusLabel;

  /// Funds settled to the merchant.
  final num? fundsToMerchant;

  /// Date funds were settled to the merchant.
  final String? settlementDate;

  /// Whether funds have been settled to the merchant.
  final bool? isPaymentSettledToMerchant;

  /// Amount actually processed.
  final num? processedAmount;

  /// PayTo-specific status.
  final String? payToStatus;

  /// Product SKU 1.
  final String? sku1;

  /// Product SKU 2.
  final String? sku2;

  /// Acquirer authorization trace data.
  final ZpCallbackAdditionalData? additionalData;

  /// Reusable saved-card or account token.
  final String? token;

  /// Whether [token] was saved.
  final bool? cardInformationSaved;

  /// Numeric card scheme code.
  final num? cardTypeValue;

  /// Card scheme label.
  final String? cardTypeString;

  /// Card sub-type label. Payment/preauthorization only.
  final String? subCardTypeString;

  /// Held preauthorization amount.
  final num? preauthAmount;

  /// When the preauthorization hold expires.
  final String? preauthExpiryAt;

  /// Tokenisation fee breakdown.
  final ZpTokenisePaymentDetail? paymentDetail;

  /// Whether the caller should redirect after tokenisation.
  final bool? doRedirect;

  /// Card type label. Tokenisation only.
  final String? cardType;

  /// Whether the card is restricted. Tokenisation only.
  final bool? isRestrictedCard;
}

/// The callback body does not match the expected shape for its mode.
final class ZpCallbackMalformed extends ZpCallbackResult {
  /// Creates a malformed callback result.
  const ZpCallbackMalformed(this.message);

  /// Why the callback was malformed.
  final String message;
}

/// The callback was shaped correctly but failed authenticity verification.
final class ZpCallbackRejected extends ZpCallbackResult {
  /// Creates a rejected callback result.
  const ZpCallbackRejected(this.message);

  /// Why the callback was rejected.
  final String message;
}

typedef _CallbackShape = ({
  Map<String, Object?> response,
  String reference,
  String validationCode,
});

Map<String, Object?>? _asObjectMap(Object? value) {
  if (value is Map<String, Object?>) return value;
  if (value is! Map) return null;

  final result = <String, Object?>{};

  for (final MapEntry(:key, :value) in value.entries) {
    if (key is! String) return null;
    result[key] = value;
  }

  return result;
}

String? _string(
  Map<String, Object?> data,
  String key, {
  String path = 'response',
}) => switch (data[key]) {
  null => null,
  final String value => value,
  _ => throw FormatException('$path.$key must be a string'),
};

num? _number(
  Map<String, Object?> data,
  String key, {
  String path = 'response',
}) => switch (data[key]) {
  null => null,
  final num value => value,
  _ => throw FormatException('$path.$key must be a number'),
};

bool? _boolean(
  Map<String, Object?> data,
  String key, {
  String path = 'response',
}) => switch (data[key]) {
  null => null,
  final bool value => value,
  _ => throw FormatException('$path.$key must be a boolean'),
};

Map<String, Object?>? _object(
  Map<String, Object?> data,
  String key, {
  String path = 'response',
}) {
  final value = data[key];

  if (value == null) return null;

  return _asObjectMap(value) ??
      (throw FormatException('$path.$key must be an object'));
}

_CallbackShape _parseCallbackShape(
  ZpPluginMode mode,
  Map<String, Object?> body,
) {
  final response = _asObjectMap(body['response']);
  final validationCode = body['validationCode'];

  if (response == null || validationCode is! String) {
    throw const FormatException(_errMalformedBody);
  }

  final referenceField = mode.callbackReferenceField;
  final reference = response[referenceField];

  if (reference is! String || reference.trim().isEmpty) {
    throw FormatException('response.$referenceField must not be empty');
  }

  if (!_validationCodePattern.hasMatch(validationCode)) {
    throw const FormatException(_errValidationCodeHex);
  }

  return (
    response: response,
    reference: reference,
    validationCode: validationCode,
  );
}

(ZpCents?, ZpCallbackRejected?) _validateCallbackContext(
  ZpPluginMode mode,
  ZpVerifyCallbackContext context,
) {
  if (context.apiKey.length < zpMinCredentialLength ||
      context.username.length < zpMinCredentialLength ||
      context.password.length < zpMinCredentialLength ||
      context.merchantUniquePaymentId.value.length < zpMinCredentialLength) {
    return (null, const ZpCallbackRejected(_errCredentialLength));
  }

  final (amount, failureReason) = resolveZpHashAmountChecked(
    mode,
    context.paymentAmount,
  );

  if (failureReason == null) {
    return (amount, null);
  }

  return (
    null,
    switch (failureReason) {
      ZpAmountFailureReason.notANumber => const ZpCallbackRejected(
        zpErrPaymentAmountNumber,
      ),
      ZpAmountFailureReason.notPositive => const ZpCallbackRejected(
        zpErrPaymentAmountPositive,
      ),
      ZpAmountFailureReason.unresolvable => const ZpCallbackRejected(
        _errPaymentAmountInvalid,
      ),
    },
  );
}

bool _verifyCallbackHash({
  required ZpPluginMode mode,
  required ZpVerifyCallbackContext context,
  required ZpCents amount,
  required String reference,
  required String validationCode,
}) {
  final value = [
    context.apiKey,
    context.username,
    context.password,
    mode.wireValue.toString(),
    amount.value,
    context.merchantUniquePaymentId.value,
    reference,
  ].join(zpPipeDelimiter);

  return constantTimeHexEqual(createSha3_512(value), validationCode);
}

ZpCallbackAdditionalData? _additionalData(Map<String, Object?> response) {
  final data = _object(response, 'additionalData');

  if (data == null) return null;

  return ZpCallbackAdditionalData(
    authCode: _string(data, 'authCode', path: 'response.additionalData'),
    rrn: _string(data, 'rrn', path: 'response.additionalData'),
    stan: _string(data, 'stan', path: 'response.additionalData'),
  );
}

ZpTokenisePaymentDetail? _paymentDetail(Map<String, Object?> response) {
  final data = _object(response, 'paymentDetail');

  if (data == null) return null;

  return ZpTokenisePaymentDetail(
    customerFee: _number(data, 'customerFee', path: 'response.paymentDetail'),
    merchantFee: _number(data, 'merchantFee', path: 'response.paymentDetail'),
    processingAmount: _number(
      data,
      'processingAmount',
      path: 'response.paymentDetail',
    ),
    paymentAmount: _number(
      data,
      'paymentAmount',
      path: 'response.paymentDetail',
    ),
  );
}

int _statusCode(ZpPluginMode mode, Map<String, Object?> response) {
  if (mode == ZpPluginMode.tokenise) {
    return ZpPaymentStatus.successful.wireValue;
  }

  final field = mode == ZpPluginMode.preauthorization
      ? 'preauthStatus'
      : 'paymentStatus';

  return switch (response[field]) {
    null => ZpPaymentStatus.pending.wireValue,
    final num value => value.toInt(),
    _ => throw FormatException('response.$field must be a number'),
  };
}

ZpCallbackVerified _buildTokeniseResult(
  String reference,
  int statusCode,
  Map<String, Object?> response,
) => ZpCallbackVerified(
  reference: reference,
  statusCode: statusCode,
  failureCode: _string(response, 'failureCode'),
  failureReason: _string(response, 'failureReason'),
  cardType: _string(response, 'cardType'),
  isRestrictedCard: _boolean(response, 'isRestrictedCard'),
  cardTypeValue: _number(response, 'cardTypeValue'),
  cardTypeString: _string(response, 'cardTypeString'),
  paymentDetail: _paymentDetail(response),
  doRedirect: _boolean(response, 'doRedirect'),
);

ZpCallbackVerified _buildPaymentOrPreauthResult(
  ZpPluginMode mode,
  String reference,
  int statusCode,
  Map<String, Object?> response,
) {
  final isPreauth = mode == ZpPluginMode.preauthorization;

  return ZpCallbackVerified(
    reference: reference,
    statusCode: statusCode,
    failureCode: _string(response, 'failureCode'),
    failureReason: _string(response, 'failureReason'),
    customerName: _string(response, 'customerName'),
    customerReference: _string(response, 'customerReference'),
    merchantUniquePaymentId: _string(response, 'merchantUniquePaymentId'),
    merchantCode: _string(response, 'merchantCode'),
    additionalReference: _string(response, 'additionalReference'),
    cardCategory: _string(response, 'cardCategory'),
    baseAmount: _number(response, 'baseAmount'),
    customerFee: _number(response, 'customerFee'),
    processorReference: _string(response, 'processorReference'),
    processingDate: _string(response, 'processingDate'),
    transactionSource: _number(response, 'transactionSource'),
    transactionSourceString: _string(response, 'transactionSourceString'),
    cardTypeValue: _number(response, 'cardTypeValue'),
    cardTypeString: _string(response, 'cardTypeString'),
    subCardTypeString: _string(response, 'subCardTypeString'),
    statusLabel: _string(
      response,
      isPreauth ? 'preauthStatusString' : 'paymentStatusString',
    ),
    fundsToMerchant: isPreauth ? null : _number(response, 'fundsToMerchant'),
    settlementDate: isPreauth ? null : _string(response, 'settlementDate'),
    isPaymentSettledToMerchant: isPreauth
        ? null
        : _boolean(response, 'isPaymentSettledToMerchant'),
    processedAmount: isPreauth ? null : _number(response, 'processedAmount'),
    payToStatus: isPreauth ? null : _string(response, 'payToStatus'),
    sku1: isPreauth ? null : _string(response, 'sku1'),
    sku2: isPreauth ? null : _string(response, 'sku2'),
    additionalData: isPreauth ? null : _additionalData(response),
    token: isPreauth ? null : _string(response, 'token'),
    cardInformationSaved: isPreauth
        ? null
        : _boolean(response, 'cardInformationSaved'),
    preauthAmount: isPreauth ? _number(response, 'preauthAmount') : null,
    preauthExpiryAt: isPreauth ? _string(response, 'preauthExpiryAt') : null,
  );
}

ZpCallbackVerified _buildVerifiedResult(
  ZpPluginMode mode,
  String reference,
  int statusCode,
  Map<String, Object?> response,
) => mode == ZpPluginMode.tokenise
    ? _buildTokeniseResult(reference, statusCode, response)
    : _buildPaymentOrPreauthResult(mode, reference, statusCode, response);

/// Validates the callback body's structural shape for [mode].
///
/// The body must contain a `response` object, a non-empty mode-specific
/// reference, and a 128-character hexadecimal `validationCode`.
///
/// Returns `null` when [body] is structurally valid. This does not verify
/// callback authenticity.
ZpCallbackMalformed? validateZpCallbackBody(
  ZpPluginMode mode,
  Map<String, Object?> body,
) {
  try {
    _parseCallbackShape(mode, body);
    return null;
  } on FormatException catch (error) {
    return ZpCallbackMalformed(error.message.toString());
  }
}

/// Verifies the authenticity of an incoming HCP callback.
///
/// Supports payment (mode 0/2), preauthorization (mode 3), and tokenisation
/// (mode 1) callbacks by recomputing the SHA3-512 validation hash and
/// comparing it in constant time with `body.validationCode`.
///
/// Recover [mode] from your own launch state. Never infer it from [body].
///
/// Never throws for malformed callback data.
ZpCallbackResult verifyZpCallback(
  ZpPluginMode mode,
  Map<String, Object?> body,
  ZpVerifyCallbackContext context,
) {
  try {
    final (:response, :reference, :validationCode) = _parseCallbackShape(
      mode,
      body,
    );

    final (amount, contextError) = _validateCallbackContext(mode, context);

    if (contextError != null) {
      return contextError;
    }

    if (!_verifyCallbackHash(
      mode: mode,
      context: context,
      amount: amount!,
      reference: reference,
      validationCode: validationCode,
    )) {
      return const ZpCallbackRejected(_errValidationCodeMismatch);
    }

    final echoedMupid = _string(response, 'merchantUniquePaymentId');

    if (echoedMupid != null &&
        echoedMupid.isNotEmpty &&
        echoedMupid != context.merchantUniquePaymentId.value) {
      return const ZpCallbackRejected(_errMupidMismatch);
    }

    return _buildVerifiedResult(
      mode,
      reference,
      _statusCode(mode, response),
      response,
    );
  } on FormatException catch (error) {
    return ZpCallbackMalformed(error.message.toString());
  }
}
