/// HMAC-SHA3-512 signed callback URL token creation and verification for stateless backends.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:hashlib/hashlib.dart';

import 'enums.dart';

const _minSecretBytes = 32;
const _signatureBytes = 16;
final _timestampPattern = RegExp(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$');

// Failure reasons
const _reasonMalformed = ZpCallbackUrlTokenFailureReason.malformed;
const _reasonBadSignature = ZpCallbackUrlTokenFailureReason.badSignature;
const _reasonExpired = ZpCallbackUrlTokenFailureReason.expired;

// Delimiters and padding
const _base64Padding = '=';

// Payload dictionary keys
const _keyMode = 'mode';
const _keyMupid = 'merchantUniquePaymentId';
const _keyTimestamp = 'timestamp';
const _keyPaymentAmount = 'paymentAmount';
const _keyIat = 'iat';
const _keyExp = 'exp';

// Minified wire keys
const _wireKeyMode = 'm';
const _wireKeyMupid = 'u';
const _wireKeyTimestamp = 't';
const _wireKeyAmount = 'a';
const _wireKeyIat = 'iat';
const _wireKeyExp = 'exp';

const _wireKeyMap = {
  _keyMode: _wireKeyMode,
  _keyMupid: _wireKeyMupid,
  _keyTimestamp: _wireKeyTimestamp,
  _keyPaymentAmount: _wireKeyAmount,
};

final _reverseWireKeyMap = {
  for (final entry in _wireKeyMap.entries) entry.value: entry.key,
};

const _fixedKeys = {
  _keyMode,
  _keyMupid,
  _keyTimestamp,
  _keyPaymentAmount,
  _keyIat,
  _keyExp,
};

const _errSecretType = 'must be a String or Uint8List';
const _errTimestampFormat = 'must match yyyy-MM-ddTHH:mm:ss';
const _errPaymentAmountType = 'must be a String or a num';

/// Payload stored inside a signed callback URL token.
class ZpCallbackUrlTokenPayload {
  /// Creates a payload for [createZpCallbackUrlToken].
  const ZpCallbackUrlTokenPayload({
    required this.mode,
    required this.merchantUniquePaymentId,
    required this.timestamp,
    this.paymentAmount,
    this.extra = const {},
  });

  /// Payment operating mode — wire key `m`.
  final ZpPluginMode mode;

  /// Per-payment idempotency key — wire key `u`.
  final String merchantUniquePaymentId;

  /// ISO 8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SS`) — wire key `t`.
  final String timestamp;

  /// Payment amount in dollars — wire key `a`.
  final Object? paymentAmount;

  /// Arbitrary extra key-value pairs stored in the token payload.
  final Map<String, Object?> extra;
}

/// Options for token creation, such as expiration.
class ZpCallbackUrlTokenOptions {
  /// Creates options for [createZpCallbackUrlToken].
  const ZpCallbackUrlTokenOptions({this.expiresInSeconds});

  /// Token lifetime in seconds; sets `exp = iat + expiresInSeconds`. `null`
  /// means no expiry.
  final int? expiresInSeconds;
}

/// Result of [verifyZpCallbackUrlToken]: [ZpCallbackUrlTokenVerified] or [ZpCallbackUrlTokenFailure].
sealed class ZpCallbackUrlTokenResult {
  const ZpCallbackUrlTokenResult();

  /// Returns true if verified successfully.
  bool get ok => this is ZpCallbackUrlTokenVerified;

  /// Recovered payload if verified, or null if failed.
  ZpCallbackUrlTokenPayload? get payload => switch (this) {
    ZpCallbackUrlTokenVerified(:final payload) => payload,
    _ => null,
  };

  /// Failure reason if failed, or null if verified.
  ZpCallbackUrlTokenFailureReason? get reason => switch (this) {
    ZpCallbackUrlTokenFailure(:final reason) => reason,
    _ => null,
  };
}

/// A successfully verified and decoded callback URL token.
final class ZpCallbackUrlTokenVerified extends ZpCallbackUrlTokenResult {
  /// Creates a verified callback URL token result.
  const ZpCallbackUrlTokenVerified(this.payload);

  /// The recovered payload from the verified token.
  @override
  final ZpCallbackUrlTokenPayload payload;
}

/// Why a callback URL token failed verification.
enum ZpCallbackUrlTokenFailureReason {
  /// The token could not be decoded into its expected shape.
  malformed,

  /// The signature does not match the given secret.
  badSignature,

  /// The token's `exp` claim is in the past.
  expired,
}

/// A failed callback URL token verification.
final class ZpCallbackUrlTokenFailure extends ZpCallbackUrlTokenResult {
  /// Creates a failed callback URL token verification result.
  const ZpCallbackUrlTokenFailure(this.reason);

  /// Why verification failed.
  @override
  final ZpCallbackUrlTokenFailureReason reason;
}

Uint8List _keyBytes(Object secret) {
  final Uint8List bytes;
  if (secret is String) {
    bytes = Uint8List.fromList(utf8.encode(secret));
  } else if (secret is Uint8List) {
    bytes = secret;
  } else {
    throw ArgumentError.value(secret, 'secret', _errSecretType);
  }
  if (bytes.length < _minSecretBytes) {
    throw RangeError(
      'secret must be at least $_minSecretBytes bytes (got ${bytes.length})',
    );
  }
  return bytes;
}

String _base64UrlEncode(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll(_base64Padding, '');

Uint8List _base64UrlDecode(String value) {
  final padded = value.padRight(((value.length + 3) ~/ 4) * 4, _base64Padding);
  return base64Url.decode(padded);
}

Uint8List _sign(String body, Uint8List key) {
  final mac = sha3_512.hmac.by(key).sign(utf8.encode(body));
  return Uint8List.fromList(mac.bytes.sublist(0, _signatureBytes));
}

Map<String, Object?> _toWire(
  ZpCallbackUrlTokenPayload payload,
  int iat,
  int? exp,
) {
  final wire = <String, Object?>{
    for (final entry in payload.extra.entries) entry.key: entry.value,
    _wireKeyMode: payload.mode.wireValue,
    _wireKeyMupid: payload.merchantUniquePaymentId,
    _wireKeyTimestamp: payload.timestamp,
    _wireKeyIat: iat,
  };
  if (payload.paymentAmount != null) {
    wire[_wireKeyAmount] = payload.paymentAmount;
  }
  if (exp != null) {
    wire[_wireKeyExp] = exp;
  } else {
    wire.remove(_wireKeyExp);
  }
  return wire;
}

bool _isAmountShaped(Object? value) =>
    value == null || value is String || value is num;

/// Mints a signed, stateless callback URL token.
///
/// Sign with your own HMAC [secret] (≥ 32 bytes), separate from the ZenPay
/// password. Embed the result in your launch `callbackUrl` as `?t=<token>`.
String createZpCallbackUrlToken(
  ZpCallbackUrlTokenPayload payload,
  Object secret, [
  ZpCallbackUrlTokenOptions options = const ZpCallbackUrlTokenOptions(),
]) {
  if (!_timestampPattern.hasMatch(payload.timestamp)) {
    throw ArgumentError.value(
      payload.timestamp,
      _keyTimestamp,
      _errTimestampFormat,
    );
  }
  if (!_isAmountShaped(payload.paymentAmount)) {
    throw ArgumentError.value(
      payload.paymentAmount,
      _keyPaymentAmount,
      _errPaymentAmountType,
    );
  }

  final key = _keyBytes(secret);
  final iat = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
  final exp = options.expiresInSeconds == null
      ? null
      : iat + options.expiresInSeconds!;

  final body = _base64UrlEncode(
    utf8.encode(jsonEncode(_toWire(payload, iat, exp))),
  );
  return '$body${_base64UrlEncode(_sign(body, key))}';
}

(String?, ZpCallbackUrlTokenFailure?) _splitAndVerifySignature(
  String token,
  Uint8List key,
) {
  final signatureLength = _base64UrlEncode(Uint8List(_signatureBytes)).length;
  if (token.length <= signatureLength) {
    return (null, const ZpCallbackUrlTokenFailure(_reasonMalformed));
  }
  final body = token.substring(0, token.length - signatureLength);
  final providedSignature = token.substring(token.length - signatureLength);

  final expectedSignature = _sign(body, key);
  final Uint8List providedSignatureBytes;
  try {
    providedSignatureBytes = _base64UrlDecode(providedSignature);
  } on FormatException {
    return (null, const ZpCallbackUrlTokenFailure(_reasonBadSignature));
  }
  if (!HashDigest(expectedSignature).isEqual(providedSignatureBytes)) {
    return (null, const ZpCallbackUrlTokenFailure(_reasonBadSignature));
  }
  return (body, null);
}

Map<String, Object?>? _decodeTokenBody(String body) {
  try {
    final decoded = jsonDecode(utf8.decode(_base64UrlDecode(body)));
    if (decoded is! Map<String, Object?>) return null;
    return <String, Object?>{
      for (final entry in decoded.entries)
        (_reverseWireKeyMap[entry.key] ?? entry.key): entry.value,
    };
  } on FormatException {
    return null;
  }
}

ZpCallbackUrlTokenResult _validateAndBuildPayload(Map<String, Object?> long) {
  final modeRaw = long[_keyMode];
  final mupid = long[_keyMupid];
  final timestamp = long[_keyTimestamp];
  if (modeRaw is! int ||
      mupid is! String ||
      timestamp is! String ||
      !_timestampPattern.hasMatch(timestamp)) {
    return const ZpCallbackUrlTokenFailure(_reasonMalformed);
  }
  final ZpPluginMode mode;
  try {
    mode = ZpPluginMode.fromWireValue(modeRaw);
  } on ArgumentError {
    return const ZpCallbackUrlTokenFailure(_reasonMalformed);
  }

  final paymentAmount = long[_keyPaymentAmount];
  final iat = long[_keyIat];
  final exp = long[_keyExp];
  if (!_isAmountShaped(paymentAmount) ||
      (iat != null && iat is! num) ||
      (exp != null && exp is! num)) {
    return const ZpCallbackUrlTokenFailure(_reasonMalformed);
  }

  if (exp is num) {
    final nowSeconds = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    if (nowSeconds >= exp) {
      return const ZpCallbackUrlTokenFailure(_reasonExpired);
    }
  }

  final extra = <String, Object?>{
    for (final entry in long.entries)
      if (!_fixedKeys.contains(entry.key)) entry.key: entry.value,
  };

  return ZpCallbackUrlTokenVerified(
    ZpCallbackUrlTokenPayload(
      mode: mode,
      merchantUniquePaymentId: mupid,
      timestamp: timestamp,
      paymentAmount: paymentAmount,
      extra: extra,
    ),
  );
}

/// Verifies and decodes a token minted by [createZpCallbackUrlToken].
///
/// Checks the HMAC-SHA3-512 signature (constant-time) and `exp` before
/// decoding. Use the same [secret] used to mint it.
ZpCallbackUrlTokenResult verifyZpCallbackUrlToken(String token, Object secret) {
  final key = _keyBytes(secret);
  final (body, failure) = _splitAndVerifySignature(token, key);
  if (failure != null) return failure;

  final decoded = _decodeTokenBody(body!);
  if (decoded == null) {
    return const ZpCallbackUrlTokenFailure(_reasonMalformed);
  }

  return _validateAndBuildPayload(decoded);
}
