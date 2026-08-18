/// Checkout domain models and ZenPay status mapping.
///
/// Contains core domain entities for the reference merchant backend:
/// - [CheckoutClient]: Client presentation mode (web, web frame, or mobile).
/// - [MerchantPaymentStatus]: Merchant-facing payment lifecycle states.
/// - [mapZenPayStatus]: Translator from ZenPay integer status codes to [MerchantPaymentStatus].
/// - [CheckoutAttempt]: Central payment attempt entity tracked in [AttemptStore].
/// - [CreateCheckoutBody]: Strongly typed representation of checkout creation requests.
/// - [AppCheckoutSession]: Response model containing the launch URL and payment ID.
/// - [HttpError]: Exception representing controlled HTTP error responses.
library;

import 'package:zenpay_dart/zenpay_dart.dart' show ZpPaymentStatus;

/// Presentation environment from which the checkout session was initiated.
///
/// Identifies the client platform kind to select the appropriate return mechanism
/// without accepting unvalidated return URLs from clients.
enum CheckoutClient {
  /// Standard web browser presentation opening checkout in a new window or tab.
  web,

  /// Embedded web iframe presentation communicating via `window.parent.postMessage`.
  webFrame,

  /// Mobile app presentation redirecting via App Links or Universal Links.
  mobile;

  /// Parses a string wire value (`"web"`, `"webFrame"`, `"mobile"`) into a [CheckoutClient].
  ///
  /// Returns `null` if [value] does not match any known client variant.
  static CheckoutClient? tryParse(String value) {
    for (final client in CheckoutClient.values) {
      if (client.name == value) return client;
    }
    return null;
  }
}

/// Merchant-facing payment lifecycle state returned during checkout status polling.
enum MerchantPaymentStatus {
  /// Session attempt record created in store prior to launch URL generation.
  created,

  /// Session created and launch URL generated; waiting for customer interaction.
  sessionCreated,

  /// Customer browser has returned from ZenPay Hosted Payment Page via `/return`.
  browserReturned,

  /// Payment is currently in progress or awaiting settlement on ZenPay.
  pending,

  /// Payment successfully authorized and settled.
  successful,

  /// Payment attempt was rejected or failed.
  failed,

  /// Customer or merchant cancelled the payment.
  cancelled,

  /// An error occurred during transaction processing on ZenPay.
  error,

  /// Unrecognized or unsupported status code received from ZenPay.
  unknown,
}

/// Resolves a [ZpPaymentStatus] from its integer [value], or returns `null` if unmapped.
ZpPaymentStatus? _zpPaymentStatusFromWireValue(int value) {
  for (final status in ZpPaymentStatus.values) {
    if (status.wireValue == value) return status;
  }
  return null;
}

/// Translates a ZenPay [ZpPaymentStatus] wire status code into a [MerchantPaymentStatus].
///
/// Both `suppressed` and `error` statuses map to [MerchantPaymentStatus.error].
/// Any code not matching a known ZenPay wire value maps to [MerchantPaymentStatus.unknown].
MerchantPaymentStatus mapZenPayStatus(int statusCode) =>
    switch (_zpPaymentStatusFromWireValue(statusCode)) {
      ZpPaymentStatus.pending ||
      ZpPaymentStatus.inProgress => MerchantPaymentStatus.pending,
      ZpPaymentStatus.successful => MerchantPaymentStatus.successful,
      ZpPaymentStatus.failed => MerchantPaymentStatus.failed,
      ZpPaymentStatus.cancelled => MerchantPaymentStatus.cancelled,
      ZpPaymentStatus.error ||
      ZpPaymentStatus.suppressed => MerchantPaymentStatus.error,
      null => MerchantPaymentStatus.unknown,
    };

/// Central entity tracking correlation identifiers, launch parameters, and verified
/// callback results for a single checkout lifecycle.
class CheckoutAttempt {
  CheckoutAttempt({
    required this.merchantUniquePaymentId,
    required this.idempotencyKey,
    required this.orderId,
    required this.mode,
    required this.client,
    required this.amount,
    required this.customerName,
    required this.customerEmail,
    required this.createdAt,
    required this.status,
    this.checkoutUrl,
    this.paymentReference,
    this.preauthReference,
    this.tokenReference,
    this.failureCode,
    this.failureReason,
    this.verifiedCallbackReference,
    this.verifiedCallbackStatusCode,
  });

  /// ZenPay unique identifier correlating this checkout attempt across all flows.
  final String merchantUniquePaymentId;

  /// Client-supplied idempotency key used to prevent duplicate session creation.
  final String idempotencyKey;

  final String orderId;

  /// ZenPay plugin operation mode (0: Make Payment, 1: Tokenise, 2: Custom, 3: PreAuth).
  final int mode;

  /// Client presentation target determining return redirection behavior.
  final CheckoutClient client;

  final num amount;
  final String customerName;
  final String customerEmail;
  final DateTime createdAt;
  final MerchantPaymentStatus status;

  /// Generated ZenPay Hosted Payment Page launch URL, or `null` if not yet generated.
  final String? checkoutUrl;

  /// Transaction reference assigned upon successful payment (modes 0/2).
  final String? paymentReference;

  /// Pre-authorization reference assigned upon successful pre-auth (mode 3).
  final String? preauthReference;

  /// Card/account token reference assigned upon successful tokenisation (mode 1).
  final String? tokenReference;

  final String? failureCode;
  final String? failureReason;

  /// Transaction reference extracted from an authenticated webhook callback.
  final String? verifiedCallbackReference;

  /// Raw integer status code received in an authenticated webhook callback.
  final int? verifiedCallbackStatusCode;

  /// Returns a copy of this [CheckoutAttempt] with the provided fields updated.
  CheckoutAttempt copyWith({
    MerchantPaymentStatus? status,
    String? checkoutUrl,
    String? paymentReference,
    String? preauthReference,
    String? tokenReference,
    String? failureCode,
    String? failureReason,
    String? verifiedCallbackReference,
    int? verifiedCallbackStatusCode,
  }) => CheckoutAttempt(
    merchantUniquePaymentId: merchantUniquePaymentId,
    idempotencyKey: idempotencyKey,
    orderId: orderId,
    mode: mode,
    client: client,
    amount: amount,
    customerName: customerName,
    customerEmail: customerEmail,
    createdAt: createdAt,
    status: status ?? this.status,
    checkoutUrl: checkoutUrl ?? this.checkoutUrl,
    paymentReference: paymentReference ?? this.paymentReference,
    preauthReference: preauthReference ?? this.preauthReference,
    tokenReference: tokenReference ?? this.tokenReference,
    failureCode: failureCode ?? this.failureCode,
    failureReason: failureReason ?? this.failureReason,
    verifiedCallbackReference:
        verifiedCallbackReference ?? this.verifiedCallbackReference,
    verifiedCallbackStatusCode:
        verifiedCallbackStatusCode ?? this.verifiedCallbackStatusCode,
  );
}

/// Strongly typed representation of a validated `POST /api/v1/sessions` request body.
class CreateCheckoutBody {
  const CreateCheckoutBody({
    required this.orderId,
    required this.customerName,
    required this.customerEmail,
    required this.client,
    required this.paymentAmount,
    this.mode,
    this.customerReference,
    this.contactNumber,
  });

  final String orderId;
  final String customerName;
  final String customerEmail;
  final CheckoutClient client;
  final num paymentAmount;
  final int? mode;
  final String? customerReference;
  final String? contactNumber;
}

/// Data transfer object holding the launch data returned to the client application.
class AppCheckoutSession {
  const AppCheckoutSession({
    required this.merchantUniquePaymentId,
    required this.checkoutUrl,
  });

  final String merchantUniquePaymentId;
  final String checkoutUrl;

  /// Serializes this session instance into a JSON-compatible map for HTTP responses.
  Map<String, Object?> toJson() => {
    'merchantUniquePaymentId': merchantUniquePaymentId,
    'checkoutUrl': checkoutUrl,
  };
}

/// Controlled HTTP exception carrying an HTTP [statusCode] and machine-readable [code].
///
/// Handled by the Shelf pipeline to emit standardized JSON error responses of the
/// form `{"error": code}`.
class HttpError implements Exception {
  HttpError(this.statusCode, this.code);

  final int statusCode;
  final String code;

  @override
  String toString() => code;
}
