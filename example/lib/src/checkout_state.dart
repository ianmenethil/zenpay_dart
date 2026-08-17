/// Checkout domain types, ZenPay status mapping, and the in-memory attempt
/// store keyed by merchantUniquePaymentId and idempotency key.
library;

import 'package:zenpay_dart/zenpay_dart.dart' show ZpPaymentStatus;

/// Which client started the attempt. Names the kind only — never a URL — so
/// the broker cannot be turned into an open redirect.
enum CheckoutClient {
  /// New browser tab (`window.open`).
  web,

  /// Iframe — changes how the return reaches the app.
  webFrame,

  /// App Link / Universal Link.
  mobile;

  /// Parses the wire value (`"web"`, `"webFrame"`, `"mobile"`), or `null`.
  static CheckoutClient? tryParse(String value) {
    for (final client in CheckoutClient.values) {
      if (client.name == value) return client;
    }
    return null;
  }
}

/// Merchant-facing checkout status, as returned by the status lookup route.
enum MerchantPaymentStatus {
  created,
  sessionCreated,
  browserReturned,
  pending,
  successful,
  failed,
  cancelled,
  error,
  unknown,
}

/// The [ZpPaymentStatus] whose wire value is [value], or `null` if none
/// matches.
ZpPaymentStatus? _zpPaymentStatusFromWireValue(int value) {
  for (final status in ZpPaymentStatus.values) {
    if (status.wireValue == value) return status;
  }
  return null;
}

/// Maps a ZenPay [ZpPaymentStatus] wire code to a [MerchantPaymentStatus].
///
/// Suppressed and Error both surface as `error` — there is no suppressed
/// state. A code matching no known [ZpPaymentStatus] surfaces as
/// `unknown`.
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

/// A checkout attempt: correlation identifiers, launch parameters, and the
/// mutable status/reference fields a verified callback fills in.
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

  final String merchantUniquePaymentId;
  final String idempotencyKey;
  final String orderId;
  final int mode;
  final CheckoutClient client;
  final num amount;
  final String customerName;
  final String customerEmail;
  final DateTime createdAt;
  final MerchantPaymentStatus status;
  final String? checkoutUrl;
  final String? paymentReference;
  final String? preauthReference;
  final String? tokenReference;
  final String? failureCode;
  final String? failureReason;
  final String? verifiedCallbackReference;
  final int? verifiedCallbackStatusCode;

  /// Returns a copy with the given fields replaced.
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

/// A validated `POST /api/v1/sessions` request body.
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

/// The launch data returned to the merchant app for a created session.
class AppCheckoutSession {
  const AppCheckoutSession({
    required this.merchantUniquePaymentId,
    required this.checkoutUrl,
  });

  final String merchantUniquePaymentId;
  final String checkoutUrl;

  /// Encodes this session for the `POST /api/v1/sessions` response body.
  Map<String, Object?> toJson() => {
    'merchantUniquePaymentId': merchantUniquePaymentId,
    'checkoutUrl': checkoutUrl,
  };
}

/// A controlled HTTP failure: [statusCode] and a machine-readable [code]
/// sent back to the client as `{"error": code}`.
class HttpError implements Exception {
  HttpError(this.statusCode, this.code);

  final int statusCode;
  final String code;

  @override
  String toString() => code;
}

/// Thrown by [AttemptStore] on an internal invariant violation. These are
/// not reachable through normal request handling — freshly generated
/// identifiers do not collide — so they surface as a sanitized 500.
class AttemptStoreError extends Error {
  AttemptStoreError(this.code);

  final String code;

  @override
  String toString() => code;
}

/// In-memory checkout-attempt store, indexed by merchant unique payment id and
/// idempotency key. Attempts do not survive a restart.
///
/// One id index, not two: the separate merchant-side id was removed because
/// `merchantUniquePaymentId` already identifies the attempt and is the
/// identifier `package:zenpay_hcp` actually defines.
class AttemptStore {
  final _byMerchantPaymentId = <String, CheckoutAttempt>{};
  final _byIdempotencyKey = <String, String>{};

  /// Adds a new attempt. Throws [AttemptStoreError] on an id collision.
  void create(CheckoutAttempt attempt) {
    if (_byMerchantPaymentId.containsKey(attempt.merchantUniquePaymentId)) {
      throw AttemptStoreError('DUPLICATE_CHECKOUT_ATTEMPT');
    }
    _byMerchantPaymentId[attempt.merchantUniquePaymentId] = attempt;
    _byIdempotencyKey[attempt.idempotencyKey] = attempt.merchantUniquePaymentId;
  }

  /// Looks up an attempt by its ZenPay merchant unique payment id.
  CheckoutAttempt? getByMerchantPaymentId(String merchantUniquePaymentId) =>
      _byMerchantPaymentId[merchantUniquePaymentId];

  /// Looks up an attempt by the client-supplied idempotency key.
  CheckoutAttempt? getByIdempotencyKey(String key) {
    final id = _byIdempotencyKey[key];
    return id == null ? null : _byMerchantPaymentId[id];
  }

  /// Removes every attempt created before [cutoff]. Returns the count removed.
  int purgeCreatedBefore(DateTime cutoff) {
    var removed = 0;
    for (final attempt in _byMerchantPaymentId.values.toList()) {
      if (attempt.createdAt.isBefore(cutoff)) {
        _byMerchantPaymentId.remove(attempt.merchantUniquePaymentId);
        _byIdempotencyKey.remove(attempt.idempotencyKey);
        removed += 1;
      }
    }
    return removed;
  }

  /// Replaces the stored attempt for [merchantUniquePaymentId] with [next].
  /// Throws [AttemptStoreError] if no such attempt exists.
  CheckoutAttempt replace(
    String merchantUniquePaymentId,
    CheckoutAttempt next,
  ) {
    if (!_byMerchantPaymentId.containsKey(merchantUniquePaymentId)) {
      throw AttemptStoreError('CHECKOUT_ATTEMPT_NOT_FOUND');
    }
    _byMerchantPaymentId[merchantUniquePaymentId] = next;
    return next;
  }
}
