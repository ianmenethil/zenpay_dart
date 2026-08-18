/// ZenPay HCP wire enums.
library;

/// Payment operating mode used by ZenPay HCP.
enum ZpPluginMode {
  /// `0` — capture a one-off payment.
  makePayment(0),

  /// `1` — tokenise a card or account without charging it.
  tokenise(1),

  /// `2` — custom payment.
  ///
  /// The actual amount is supplied to ZenPay, but the fingerprint and
  /// callback hash always use `"0"` for the amount field.
  customPayment(2),

  /// `3` — place a preauthorization hold.
  preauthorization(3);

  const ZpPluginMode(this.wireValue);

  /// Integer value sent to ZenPay.
  final int wireValue;

  /// Resolves a mode from its ZenPay wire value.
  ///
  /// Throws [ArgumentError] when [value] is unsupported.
  static ZpPluginMode fromWireValue(int value) => switch (value) {
    0 => makePayment,
    1 => tokenise,
    2 => customPayment,
    3 => preauthorization,
    _ => throw ArgumentError.value(value, 'value', 'Unsupported mode.'),
  };

  /// Whether the Authorise request requires a positive `paymentAmount`.
  ///
  /// Modes 0, 2 and 3 require a positive amount. Tokenise may omit it.
  bool get requiresPositiveAmount => switch (this) {
    ZpPluginMode.tokenise => false,
    ZpPluginMode.makePayment ||
    ZpPluginMode.customPayment ||
    ZpPluginMode.preauthorization => true,
  };

  /// Callback field carrying this mode's ZenPay reference.
  String get callbackReferenceField => switch (this) {
    ZpPluginMode.makePayment ||
    ZpPluginMode.customPayment => 'paymentReference',
    ZpPluginMode.preauthorization => 'preauthReference',
    ZpPluginMode.tokenise => 'token',
  };
}

/// How hosted checkout is presented.
enum ZpDisplayMode {
  /// `0` — modal iframe.
  modal(0),

  /// `1` — browser redirect.
  redirectUrl(1);

  const ZpDisplayMode(this.wireValue);

  /// Integer value sent to ZenPay.
  final int wireValue;
}

/// Customer- or merchant-facing checkout mode.
enum ZpUserMode {
  /// `0` — customer-facing checkout.
  customer(0),

  /// `1` — merchant/operator-facing checkout.
  merchant(1);

  const ZpUserMode(this.wireValue);

  /// Integer value sent to ZenPay.
  final int wireValue;
}

/// Who pays the ZenPay transaction fee.
enum ZpOverrideFeePayer {
  /// `0` — use the merchant account default.
  accountDefault(0),

  /// `1` — merchant pays the fee.
  merchant(1),

  /// `2` — customer pays the fee.
  customer(2);

  const ZpOverrideFeePayer(this.wireValue);

  /// Integer value sent to ZenPay.
  final int wireValue;
}

/// Payment and preauthorization status codes returned by ZenPay.
enum ZpPaymentStatus {
  /// `0` — pending.
  pending(0),

  /// `1` — error.
  error(1),

  /// `3` — successful.
  successful(3),

  /// `4` — failed.
  failed(4),

  /// `5` — cancelled.
  cancelled(5),

  /// `6` — suppressed.
  suppressed(6),

  /// `7` — in progress.
  inProgress(7);

  const ZpPaymentStatus(this.wireValue);

  /// Integer value returned by ZenPay.
  final int wireValue;

  /// Resolves [value] to a known status, or `null`.
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

  /// Whether this status represents a successful transaction.
  bool get isSuccessful => this == ZpPaymentStatus.successful;
}

/// Whether the raw ZenPay [status] represents a successful transaction.
bool isZpPaymentSuccessful(int status) =>
    ZpPaymentStatus.tryFromWireValue(status)?.isSuccessful ?? false;
