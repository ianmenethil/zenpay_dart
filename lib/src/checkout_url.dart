/// Hosted-checkout Authorise URL construction.
///
/// Every query value is percent-encoded exactly once via [Uri]. ZenPay's own
/// browser plugin builds the query with `URLSearchParams` then
/// `decodeURIComponent`s the whole string back, undoing every escape — a
/// live `&`/`#` in free text would split or truncate the query there. This
/// builder does not have that bug: reserved characters stay escaped.
library;

import 'crypto.dart';
import 'enums.dart';

/// The HCP endpoint pattern ZenPay operates: `pay`/`payuat`/`pay.sandbox`
/// on one of the known ZenPay-operated brand domains, `/Online/v4` or
/// `/Online/v5`.
final _hcpEndpointPattern = RegExp(
  r'^https://(pay|payuat|pay\.sandbox)\.'
  r'(travelpay|childcareeasypay|zenpay|b2bpay|schooleasypay'
  r'|thoroughbredpayments|rentalrewards)'
  r'\.com\.au/[Oo]nline/v[45]/?$',
);

final _emailPattern = RegExp(r'^[^\s@]+@[^\s@]+\.[^\s@]+$');

const _authorisePath = 'Authorise';

/// Query parameter keys on the Authorise URL.
abstract final class _Param {
  static const apiKey = '__ApiKey';
  static const fingerprint = '__Fingerprint';
  static const timestamp = 'timestamp';
  static const merchantUniquePaymentId = 'merchantUniquePaymentId';
  static const customerEmail = 'customerEmail';
  static const mode = 'mode';
  static const overrideFeePayer = 'overrideFeePayer';
  static const userMode = 'userMode';
  static const displayMode = 'displayMode';
  static const hideHeader = 'hideHeader';
  static const hideTermsAndConditions = 'hideTermsAndConditions';
  static const showFeeOnTokenising = 'showFeeOnTokenising';
  static const showFailedPaymentFeeOnTokenising =
      'showFailedPaymentFeeOnTokenising';
  static const sendConfirmationEmailToCustomer =
      'sendConfirmationEmailToCustomer';
  static const allowBankAcOneOffPayment = 'allowBankAcOneOffPayment';
  static const allowPayIdOneOffPayment = 'allowPayIdOneOffPayment';
  static const allowApplePayOneOffPayment = 'allowApplePayOneOffPayment';
  static const allowUnionPayOneOffPayment = 'allowUnionPayOneOffPayment';
  static const allowAliPayPlusOneOffPayment = 'allowAliPayPlusOneOffPayment';
  static const isJsPlugin = 'isJsPlugin';
  static const callbackUrl = 'callbackUrl';
  static const redirectUrl = 'redirectUrl';
  static const sendConfirmationEmailToMerchant =
      'sendConfirmationEmailToMerchant';
  static const allowPayToOneOffPayment = 'allowPayToOneOffPayment';
  static const allowGooglePayOneOffPayment = 'allowGooglePayOneOffPayment';
  static const allowLatitudePayOneOffPayment = 'allowLatitudePayOneOffPayment';
  static const allowSlicePayOneOffPayment = 'allowSlicePayOneOffPayment';
  static const allowWeChatPayOneOffPayment = 'allowWeChatPayOneOffPayment';
  static const allowSaveCardUserOption = 'allowSaveCardUserOption';
  static const hideMerchantLogo = 'hideMerchantLogo';
  static const redirectOnError = 'redirectOnError';
  static const customerName = 'customerName';
  static const customerReference = 'customerReference';
  static const paymentAmount = 'paymentAmount';
  static const customerNameLabel = 'customerNameLabel';
  static const customerReferenceLabel = 'customerReferenceLabel';
  static const paymentAmountLabel = 'paymentAmountLabel';
  static const title = 'title';
  static const token = 'token';
  static const abn = 'AustralianBusinessNumber';
  static const sku1 = 'sku1';
  static const sku2 = 'sku2';
  static const additionalReference = 'additionalReference';
  static const contactNumber = 'contactNumber';
  static const departureDate = 'departureDate';
  static const companyName = 'companyName';
}

/// Validation error messages.
abstract final class _Err {
  static const apiKeyFingerprintEmpty =
      'apiKey and fingerprint must not be empty';
  static const merchantCodeEmpty = 'merchantCode must not be empty';
  static const callbackOrRedirectRequired =
      'callbackUrl and redirectUrl cannot both be empty';
  static const departureDateRequired =
      'departureDate is required when allowSlicePayOneOffPayment is true';
}

/// The Authorise request: every field ZenPay's hosted-checkout endpoint
/// accepts, minus browser-only concerns (theme, fonts, modal sizing,
/// lifecycle callbacks) that have no meaning when a server builds the URL.
class ZpCheckoutUrlRequest {
  /// Creates a checkout-URL request.
  ///
  /// [displayMode] defaults to [ZpDisplayMode.redirectUrl] — the correct
  /// value for a system-browser or redirect-based integration.
  /// [ZpDisplayMode.modal] exists only because ZenPay's API accepts it.
  const ZpCheckoutUrlRequest({
    required this.url,
    required this.apiKey,
    required this.fingerprint,
    required this.merchantCode,
    required this.timestamp,
    required this.merchantUniquePaymentId,
    required this.customerEmail,
    this.callbackUrl,
    this.redirectUrl,
    this.mode = ZpPluginMode.makePayment,
    this.overrideFeePayer = ZpOverrideFeePayer.accountDefault,
    this.userMode = ZpUserMode.customer,
    this.displayMode = ZpDisplayMode.redirectUrl,
    this.hideHeader = true,
    this.hideTermsAndConditions = false,
    this.showFeeOnTokenising = false,
    this.showFailedPaymentFeeOnTokenising = false,
    this.sendConfirmationEmailToCustomer = false,
    this.sendConfirmationEmailToMerchant,
    this.allowBankAcOneOffPayment = false,
    this.allowPayIdOneOffPayment = false,
    this.allowPayToOneOffPayment,
    this.allowApplePayOneOffPayment = true,
    this.allowGooglePayOneOffPayment,
    this.allowUnionPayOneOffPayment = true,
    this.allowAliPayPlusOneOffPayment = true,
    this.allowLatitudePayOneOffPayment,
    this.allowSlicePayOneOffPayment,
    this.allowWeChatPayOneOffPayment,
    this.allowSaveCardUserOption,
    this.hideMerchantLogo,
    this.redirectOnError,
    this.customerName,
    this.customerReference,
    this.paymentAmount,
    this.customerNameLabel,
    this.customerReferenceLabel,
    this.paymentAmountLabel,
    this.title,
    this.cardProxy,
    this.abn,
    this.sku1,
    this.sku2,
    this.additionalReference,
    this.contactNumber,
    this.departureDate,
    this.companyName,
  });

  /// The HCP Authorise endpoint, e.g.
  /// `https://pay.sandbox.travelpay.com.au/Online/v5`.
  final String url;

  /// Merchant API key — sent as `__ApiKey`. Not a secret; safe in a launch
  /// URL handed to a client.
  final String apiKey;

  /// Per-transaction SHA3-512 digest from [createZpFingerprint] — sent as
  /// `__Fingerprint`. Not a secret; bound to one mode/amount/mupid/timestamp.
  final String fingerprint;

  /// Merchant API key (public merchant identifier).
  final String merchantCode;

  /// Must equal the timestamp used to compute [fingerprint], or ZenPay's
  /// recomputed hash will not match.
  final ZpTimestamp timestamp;

  /// Merchant Unique Payment Identifier.
  final ZpMupid merchantUniquePaymentId;

  /// Customer email address.
  final String customerEmail;

  /// Server-to-server callback destination. At least one of [callbackUrl]
  /// or [redirectUrl] is required.
  final String? callbackUrl;

  /// Browser redirect destination after payment. At least one of
  /// [callbackUrl] or [redirectUrl] is required.
  final String? redirectUrl;

  /// Checkout plugin mode.
  final ZpPluginMode mode;

  /// Override fee payer setting.
  final ZpOverrideFeePayer overrideFeePayer;

  /// Target user mode.
  final ZpUserMode userMode;

  /// Target display mode (modal or redirect).
  final ZpDisplayMode displayMode;

  /// Whether to hide the top header element.
  final bool hideHeader;

  /// Whether to hide terms and conditions.
  final bool hideTermsAndConditions;

  /// Whether to display fee during tokenisation.
  final bool showFeeOnTokenising;

  /// Whether to display failed payment fee during tokenisation.
  final bool showFailedPaymentFeeOnTokenising;

  /// Whether to send payment confirmation email to the customer.
  final bool sendConfirmationEmailToCustomer;

  /// Whether to send payment confirmation email to the merchant.
  final bool? sendConfirmationEmailToMerchant;

  /// Allow direct debit / bank account payment option.
  final bool allowBankAcOneOffPayment;

  /// Allow PayID payment option.
  final bool allowPayIdOneOffPayment;

  /// Allow PayTo payment option.
  final bool? allowPayToOneOffPayment;

  /// Allow Apple Pay payment option.
  final bool allowApplePayOneOffPayment;

  /// Allow Google Pay payment option.
  final bool? allowGooglePayOneOffPayment;

  /// Allow UnionPay payment option.
  final bool allowUnionPayOneOffPayment;

  /// Allow Alipay+ payment option.
  final bool allowAliPayPlusOneOffPayment;

  /// Allow LatitudePay payment option.
  final bool? allowLatitudePayOneOffPayment;

  /// Requires [departureDate] when `true`.
  final bool? allowSlicePayOneOffPayment;

  /// Allow WeChat Pay payment option.
  final bool? allowWeChatPayOneOffPayment;

  /// Allow customer option to save card for future use.
  final bool? allowSaveCardUserOption;

  /// Hide merchant logo from header.
  final bool? hideMerchantLogo;

  /// Redirect to return URL even on payment error.
  final bool? redirectOnError;

  /// Required (with [customerReference]) for [ZpPluginMode.makePayment] and
  /// [ZpPluginMode.customPayment].
  final String? customerName;

  /// Required (with [customerName]) for [ZpPluginMode.makePayment] and
  /// [ZpPluginMode.customPayment].
  final String? customerReference;

  /// Dollars, string or number. Required and must be positive for
  /// [ZpPluginMode.makePayment], [ZpPluginMode.customPayment] and
  /// [ZpPluginMode.preauthorization].
  final Object? paymentAmount;

  /// Custom UI label for customer name field.
  final String? customerNameLabel;

  /// Custom UI label for customer reference field.
  final String? customerReferenceLabel;

  /// Custom UI label for payment amount field.
  final String? paymentAmountLabel;

  /// Custom page title.
  final String? title;

  /// Sent as `token`.
  final String? cardProxy;

  /// Australian Business Number — sent as `AustralianBusinessNumber`.
  final String? abn;

  /// Product SKU 1 identifier.
  final String? sku1;

  /// Product SKU 2 identifier.
  final String? sku2;

  /// Additional merchant reference payload.
  final String? additionalReference;

  /// Customer contact phone number.
  final String? contactNumber;

  /// Required when [allowSlicePayOneOffPayment] is `true`.
  final String? departureDate;

  /// Merchant company name.
  final String? companyName;
}

/// Result of [createZpCheckoutUrl]: exhaustively pattern-match with a
/// `switch` over [ZpCheckoutUrlSuccess] / [ZpCheckoutUrlFailure].
sealed class ZpCheckoutUrlResult {
  const ZpCheckoutUrlResult();
}

/// A successfully built checkout URL.
final class ZpCheckoutUrlSuccess extends ZpCheckoutUrlResult {
  /// Creates a successfully built checkout URL result.
  const ZpCheckoutUrlSuccess(this.url);

  /// Fully assembled and percent-encoded checkout URL string.
  final String url;
}

/// A validation failure, with a human-readable [message].
final class ZpCheckoutUrlFailure extends ZpCheckoutUrlResult {
  /// Creates a checkout URL failure result with an explanatory message.
  const ZpCheckoutUrlFailure(this.message);

  /// Human-readable explanation of why URL assembly failed.
  final String message;
}

/// Validates [request] without building a URL — the standalone-callable
/// counterpart of the checks [createZpCheckoutUrl] runs internally before
/// assembling a URL. Equivalent to `ZpAuthoriseRequestSchema` on the
/// TypeScript side. Returns `null` when [request] is valid.
ZpCheckoutUrlFailure? validateZpCheckoutUrlRequest(
  ZpCheckoutUrlRequest request,
) {
  if (request.apiKey.isEmpty || request.fingerprint.isEmpty) {
    return const ZpCheckoutUrlFailure(_Err.apiKeyFingerprintEmpty);
  }
  if (!_hcpEndpointPattern.hasMatch(request.url)) {
    return ZpCheckoutUrlFailure(
      'url "${request.url}" is not a recognized ZenPay HCP endpoint',
    );
  }
  if (request.merchantCode.isEmpty) {
    return const ZpCheckoutUrlFailure(_Err.merchantCodeEmpty);
  }

  if ((request.callbackUrl?.isEmpty ?? true) &&
      (request.redirectUrl?.isEmpty ?? true)) {
    return const ZpCheckoutUrlFailure(_Err.callbackOrRedirectRequired);
  }

  if (!_emailPattern.hasMatch(request.customerEmail)) {
    return ZpCheckoutUrlFailure(
      'customerEmail "${request.customerEmail}" is not a valid email',
    );
  }

  final requiresCustomerFields =
      request.mode == ZpPluginMode.makePayment ||
      request.mode == ZpPluginMode.customPayment;

  if (requiresCustomerFields &&
      ((request.customerName?.isEmpty ?? true) ||
          (request.customerReference?.isEmpty ?? true))) {
    return ZpCheckoutUrlFailure(
      'customerName and customerReference are required for mode ${request.mode.wireValue}',
    );
  }

  if (request.mode.requiresPositiveAmount) {
    final amount = num.tryParse(request.paymentAmount?.toString().trim() ?? '');
    if (amount == null || amount <= 0) {
      return ZpCheckoutUrlFailure(
        'paymentAmount must be a positive number for mode ${request.mode.wireValue}',
      );
    }
  }

  if (request.allowSlicePayOneOffPayment == true &&
      (request.departureDate?.isEmpty ?? true)) {
    return const ZpCheckoutUrlFailure(_Err.departureDateRequired);
  }

  return null;
}

Map<String, String> _buildQueryParams(ZpCheckoutUrlRequest request) {
  return <String, String>{
    _Param.apiKey: request.apiKey,
    _Param.fingerprint: request.fingerprint,
    _Param.timestamp: request.timestamp.value,
    _Param.merchantUniquePaymentId: request.merchantUniquePaymentId.value,
    _Param.customerEmail: request.customerEmail,
    _Param.mode: '${request.mode.wireValue}',
    _Param.overrideFeePayer: '${request.overrideFeePayer.wireValue}',
    _Param.userMode: '${request.userMode.wireValue}',
    _Param.displayMode: '${request.displayMode.wireValue}',
    _Param.hideHeader: '${request.hideHeader}',
    _Param.hideTermsAndConditions: '${request.hideTermsAndConditions}',
    _Param.showFeeOnTokenising: '${request.showFeeOnTokenising}',
    _Param.showFailedPaymentFeeOnTokenising:
        '${request.showFailedPaymentFeeOnTokenising}',
    _Param.sendConfirmationEmailToCustomer:
        '${request.sendConfirmationEmailToCustomer}',
    _Param.allowBankAcOneOffPayment: '${request.allowBankAcOneOffPayment}',
    _Param.allowPayIdOneOffPayment: '${request.allowPayIdOneOffPayment}',
    _Param.allowApplePayOneOffPayment: '${request.allowApplePayOneOffPayment}',
    _Param.allowUnionPayOneOffPayment: '${request.allowUnionPayOneOffPayment}',
    _Param.allowAliPayPlusOneOffPayment:
        '${request.allowAliPayPlusOneOffPayment}',
    // ZenPay's browser plugin always sends this; a server-built URL matches
    // that shape rather than exposing it as a caller-settable option.
    _Param.isJsPlugin: 'true',
    if (request.callbackUrl != null) _Param.callbackUrl: request.callbackUrl!,
    if (request.redirectUrl != null) _Param.redirectUrl: request.redirectUrl!,
    if (request.sendConfirmationEmailToMerchant != null)
      _Param.sendConfirmationEmailToMerchant:
          '${request.sendConfirmationEmailToMerchant!}',
    if (request.allowPayToOneOffPayment != null)
      _Param.allowPayToOneOffPayment: '${request.allowPayToOneOffPayment!}',
    if (request.allowGooglePayOneOffPayment != null)
      _Param.allowGooglePayOneOffPayment:
          '${request.allowGooglePayOneOffPayment!}',
    if (request.allowLatitudePayOneOffPayment != null)
      _Param.allowLatitudePayOneOffPayment:
          '${request.allowLatitudePayOneOffPayment!}',
    if (request.allowSlicePayOneOffPayment != null)
      _Param.allowSlicePayOneOffPayment:
          '${request.allowSlicePayOneOffPayment!}',
    if (request.allowWeChatPayOneOffPayment != null)
      _Param.allowWeChatPayOneOffPayment:
          '${request.allowWeChatPayOneOffPayment!}',
    if (request.allowSaveCardUserOption != null)
      _Param.allowSaveCardUserOption: '${request.allowSaveCardUserOption!}',
    if (request.hideMerchantLogo != null)
      _Param.hideMerchantLogo: '${request.hideMerchantLogo!}',
    if (request.redirectOnError != null)
      _Param.redirectOnError: '${request.redirectOnError!}',
    if (request.customerName != null)
      _Param.customerName: request.customerName!,
    if (request.customerReference != null)
      _Param.customerReference: request.customerReference!,
    if (request.paymentAmount != null)
      _Param.paymentAmount: '${request.paymentAmount!}',
    if (request.customerNameLabel != null)
      _Param.customerNameLabel: request.customerNameLabel!,
    if (request.customerReferenceLabel != null)
      _Param.customerReferenceLabel: request.customerReferenceLabel!,
    if (request.paymentAmountLabel != null)
      _Param.paymentAmountLabel: request.paymentAmountLabel!,
    if (request.title != null) _Param.title: request.title!,
    if (request.cardProxy != null) _Param.token: request.cardProxy!,
    if (request.abn != null) _Param.abn: request.abn!,
    if (request.sku1 != null) _Param.sku1: request.sku1!,
    if (request.sku2 != null) _Param.sku2: request.sku2!,
    if (request.additionalReference != null)
      _Param.additionalReference: request.additionalReference!,
    if (request.contactNumber != null)
      _Param.contactNumber: request.contactNumber!,
    if (request.departureDate != null)
      _Param.departureDate: request.departureDate!,
    if (request.companyName != null) _Param.companyName: request.companyName!,
  };
}

/// Builds the hosted-checkout Authorise URL from [request].
ZpCheckoutUrlResult createZpCheckoutUrl(ZpCheckoutUrlRequest request) {
  final validationFailure = validateZpCheckoutUrlRequest(request);
  if (validationFailure != null) {
    return validationFailure;
  }

  final path = '${request.merchantCode}/$_authorisePath';
  final base = Uri.parse(request.url);
  final url = base.replace(
    path: '${base.path}/$path',
    queryParameters: _buildQueryParams(request),
  );

  return ZpCheckoutUrlSuccess(url.toString());
}
