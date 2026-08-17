/// ZenPay HCP wire enums: typed vocabulary for the integer codes ZenPay's
/// Authorise API, launch URL, and callbacks send and accept.
library;

const _fieldPaymentReference = 'paymentReference';
const _fieldPreauthReference = 'preauthReference';
const _fieldToken = 'token';
const _errUnsupportedMode = 'Unsupported mode.';

/// Payment operating mode — controls what the ZenPay Hosted Checkout Plugin
/// does when the customer submits. Sent as an integer in the Authorise
/// fingerprint hash and in the launch URL.
enum ZpPluginMode {
  /// `0` — capture a one-off payment immediately.
  makePayment(0),

  /// `1` — save a card or bank account without charging.
  tokenise(1),

  /// `2` — merchant-defined amount; the hash always uses `"0"` for the
  /// amount field regardless of the displayed amount.
  customPayment(2),

  /// `3` — hold funds without capturing; capture is a separate call.
  preauthorization(3);

  const ZpPluginMode(this.wireValue);

  /// The integer value sent on the wire (hash pipe, launch URL, callback).
  final int wireValue;

  /// Resolves a [ZpPluginMode] from its wire integer [value].
  ///
  /// Throws an [ArgumentError] if [value] does not match a known mode.
  static ZpPluginMode fromWireValue(int value) => values.firstWhere(
    (mode) => mode.wireValue == value,
    orElse: () =>
        throw ArgumentError.value(value, 'value', _errUnsupportedMode),
  );

  /// Whether this mode mandates a strictly positive `paymentAmount`: Make
  /// Payment and Preauthorization. Tokenise allows zero; Custom Payment lets
  /// the customer enter the amount (the hash still uses `"0"`).
  bool get requiresPositiveAmount => switch (this) {
    ZpPluginMode.makePayment ||
    ZpPluginMode.customPayment ||
    ZpPluginMode.preauthorization => true,
    _ => false,
  };

  /// Which callback response field carries this mode's reference:
  /// `paymentReference` (0/2), `preauthReference` (3), `token` (1).
  String get callbackReferenceField => switch (this) {
    ZpPluginMode.makePayment ||
    ZpPluginMode.customPayment => _fieldPaymentReference,
    ZpPluginMode.preauthorization => _fieldPreauthReference,
    ZpPluginMode.tokenise => _fieldToken,
  };
}

/// How the hosted checkout is presented after completion.
enum ZpDisplayMode {
  /// `0` — checkout renders inside a modal iframe. Not used by this
  /// architecture (system browser / redirect); kept only because ZenPay's
  /// API accepts it.
  modal(0),

  /// `1` — browser navigates to `redirectUrl` after payment. The correct
  /// value for a system-browser or redirect-based integration.
  redirectUrl(1);

  const ZpDisplayMode(this.wireValue);

  /// The integer value sent on the wire.
  final int wireValue;
}

/// Customer- vs merchant-facing checkout UI skin.
enum ZpUserMode {
  /// `0` — self-service checkout for end customers.
  customer(0),

  /// `1` — operator/MOTO UI for merchant-initiated payments.
  merchant(1);

  const ZpUserMode(this.wireValue);

  /// The integer value sent on the wire.
  final int wireValue;
}

/// Who pays the ZenPay transaction fee for a payment.
enum ZpOverrideFeePayer {
  /// `0` — use the merchant's account-level default.
  accountDefault(0),

  /// `1` — the merchant absorbs the transaction fee.
  merchant(1),

  /// `2` — the customer pays the transaction fee on top of the amount.
  customer(2);

  const ZpOverrideFeePayer(this.wireValue);

  /// The integer value sent on the wire.
  final int wireValue;
}

/// Numeric HCP payment/preauthorisation status codes ZenPay returns in the
/// browser redirect query string and in the server-to-server callback body.
///
/// There is no status `2` — codes jump from `1` to `3`. [successful] (`3`)
/// is the only success value; status `1` is [error], not success.
enum ZpPaymentStatus {
  /// `0` — pending; a terminal status has not yet been reached.
  pending(0),

  /// `1` — an error occurred; the payment did not complete successfully.
  error(1),

  /// `3` — payment was successful. The only success value.
  successful(3),

  /// `4` — payment was declined or failed.
  failed(4),

  /// `5` — payment was cancelled by the customer or merchant.
  cancelled(5),

  /// `6` — payment was suppressed (e.g. duplicate detection).
  suppressed(6),

  /// `7` — payment is currently in progress; await a later callback.
  inProgress(7);

  const ZpPaymentStatus(this.wireValue);

  /// The integer value sent on the wire.
  final int wireValue;

  /// Resolves a [ZpPaymentStatus] from its wire integer [value], or `null`
  /// if [value] matches no known status.
  static ZpPaymentStatus? tryFromWireValue(int value) => switch (value) {
    0 => pending,
    1 => error,
    3 => successful,
    4 => failed,
    5 => cancelled,
    6 => suppressed,
    7 => inProgress,
    _ => null,
  };

  /// Whether this status indicates a successful payment or
  /// preauthorization. Only [successful] is success — prefer this over a
  /// raw equality check.
  bool get isSuccessful => this == ZpPaymentStatus.successful;
}

/// Whether the raw wire [status] code indicates a successful payment or
/// preauthorization. Equivalent to `ZpPaymentStatus.tryFromWireValue(status)
/// ?.isSuccessful`, for callers holding the raw integer rather than the
/// resolved enum — matches `isZpPaymentSuccessful` on the TypeScript side.
bool isZpPaymentSuccessful(int status) =>
    ZpPaymentStatus.tryFromWireValue(status)?.isSuccessful ?? false;
