/// HMAC-SHA3-512 signed callback URL token creation and verification for
/// stateless backends.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:hashlib/hashlib.dart';

import 'crypto.dart';
import 'enums.dart';

const _minSecretBytes = 32;
const _signatureBytes = 16;

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

  /// Payment operating mode.
  final ZpPluginMode mode;

  /// Per-payment idempotency key.
  final String merchantUniquePaymentId;

  /// ISO 8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SS`).
  final String timestamp;

  /// Payment amount in dollars.
  final Object? paymentAmount;

  /// Arbitrary extra key-value pairs stored in the token payload.
  final Map<String, Object?> extra;
}

/// Options for token creation, such as expiration.
class ZpCallbackUrlTokenOptions {
  /// Creates options for [createZpCallbackUrlToken].
  const ZpCallbackUrlTokenOptions({this.expiresInSeconds});

  /// Token lifetime in seconds.
  ///
  /// `null` means the token does not expire.
  final int? expiresInSeconds;
}

/// Result of [verifyZpCallbackUrlToken].
///
/// Exhaustively pattern-match with a `switch` over
/// [ZpCallbackUrlTokenVerified] and [ZpCallbackUrlTokenFailure].
sealed class ZpCallbackUrlTokenResult {
  const ZpCallbackUrlTokenResult();
}

/// A successfully verified and decoded callback URL token.
final class ZpCallbackUrlTokenVerified extends ZpCallbackUrlTokenResult {
  /// Creates a verified callback URL token result.
  const ZpCallbackUrlTokenVerified(this.payload);

  /// The recovered token payload.
  final ZpCallbackUrlTokenPayload payload;
}

/// Why a callback URL token failed verification.
enum ZpCallbackUrlTokenFailureReason {
  /// The token could not be decoded into its expected shape.
  malformed,

  /// The signature does not match the supplied secret.
  badSignature,

  /// The token's expiration time is in the past.
  expired,
}

/// A failed callback URL token verification.
final class ZpCallbackUrlTokenFailure extends ZpCallbackUrlTokenResult {
  /// Creates a failed callback URL token verification result.
  const ZpCallbackUrlTokenFailure(this.reason);

  /// Why verification failed.
  final ZpCallbackUrlTokenFailureReason reason;
}

Uint8List _keyBytes(Object secret) {
  final bytes = switch (secret) {
    final String value => Uint8List.fromList(utf8.encode(value)),
    final Uint8List value => value,
    _ => throw ArgumentError.value(
      secret,
      'secret',
      'must be a String or Uint8List',
    ),
  };

  if (bytes.length < _minSecretBytes) {
    throw RangeError(
      'secret must be at least $_minSecretBytes bytes '
      '(got ${bytes.length})',
    );
  }

  return bytes;
}

String _base64UrlEncode(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll(zpBase64Padding, '');

Uint8List _base64UrlDecode(String value) {
  final padded = value.padRight(((value.length + 3) ~/ 4) * 4, zpBase64Padding);

  return base64Url.decode(padded);
}

Uint8List _sign(String body, Uint8List key) {
  final mac = sha3_512.hmac.by(key).sign(utf8.encode(body));

  return Uint8List.fromList(mac.bytes.sublist(0, _signatureBytes));
}

bool _isAmountShaped(Object? value) =>
    value == null || value is String || value is num;

Map<String, Object?>? _decodeBody(String body) {
  try {
    final decoded = jsonDecode(utf8.decode(_base64UrlDecode(body)));

    return decoded is Map<String, Object?> ? decoded : null;
  } on FormatException {
    return null;
  }
}

ZpPluginMode? _parseMode(int value) {
  try {
    return ZpPluginMode.fromWireValue(value);
  } on ArgumentError {
    return null;
  }
}

/// Mints a signed, stateless callback URL token.
///
/// Sign with your own HMAC [secret] of at least 32 bytes, separate from the
/// ZenPay password. Embed the result in the launch `callbackUrl` as
/// `?t=<token>`.
String createZpCallbackUrlToken(
  ZpCallbackUrlTokenPayload payload,
  Object secret, [
  ZpCallbackUrlTokenOptions options = const ZpCallbackUrlTokenOptions(),
]) {
  if (!isValidZpTimestamp(payload.timestamp)) {
    throw ArgumentError.value(
      payload.timestamp,
      'timestamp',
      'must match yyyy-MM-ddTHH:mm:ss',
    );
  }

  if (!_isAmountShaped(payload.paymentAmount)) {
    throw ArgumentError.value(
      payload.paymentAmount,
      'paymentAmount',
      'must be a String or a num',
    );
  }

  final key = _keyBytes(secret);
  final issuedAt = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;

  final expiresInSeconds = options.expiresInSeconds;
  final expiresAt = expiresInSeconds == null
      ? null
      : issuedAt + expiresInSeconds;

  final wire = <String, Object?>{
    ...payload.extra,
    'm': payload.mode.wireValue,
    'u': payload.merchantUniquePaymentId,
    't': payload.timestamp,
    'iat': issuedAt,
    'a': ?payload.paymentAmount,
    'exp': ?expiresAt,
  };

  final body = _base64UrlEncode(utf8.encode(jsonEncode(wire)));

  return '$body${_base64UrlEncode(_sign(body, key))}';
}

/// Verifies and decodes a token minted by [createZpCallbackUrlToken].
///
/// Checks the HMAC-SHA3-512 signature and expiration before returning the
/// decoded payload. Use the same [secret] that was used to mint the token.
ZpCallbackUrlTokenResult verifyZpCallbackUrlToken(String token, Object secret) {
  final key = _keyBytes(secret);

  final signatureLength = _base64UrlEncode(Uint8List(_signatureBytes)).length;

  if (token.length <= signatureLength) {
    return const ZpCallbackUrlTokenFailure(
      ZpCallbackUrlTokenFailureReason.malformed,
    );
  }

  final body = token.substring(0, token.length - signatureLength);

  final providedSignature = token.substring(token.length - signatureLength);

  final Uint8List providedSignatureBytes;

  try {
    providedSignatureBytes = _base64UrlDecode(providedSignature);
  } on FormatException {
    return const ZpCallbackUrlTokenFailure(
      ZpCallbackUrlTokenFailureReason.badSignature,
    );
  }

  if (!HashDigest(_sign(body, key)).isEqual(providedSignatureBytes)) {
    return const ZpCallbackUrlTokenFailure(
      ZpCallbackUrlTokenFailureReason.badSignature,
    );
  }

  final data = _decodeBody(body);

  if (data == null) {
    return const ZpCallbackUrlTokenFailure(
      ZpCallbackUrlTokenFailureReason.malformed,
    );
  }

  final modeValue = data['m'];
  final merchantUniquePaymentId = data['u'];
  final timestamp = data['t'];
  final paymentAmount = data['a'];
  final issuedAt = data['iat'];
  final expiresAt = data['exp'];

  if (modeValue is! int ||
      merchantUniquePaymentId is! String ||
      timestamp is! String ||
      !isValidZpTimestamp(timestamp) ||
      !_isAmountShaped(paymentAmount) ||
      issuedAt is! int ||
      (expiresAt != null && expiresAt is! int)) {
    return const ZpCallbackUrlTokenFailure(
      ZpCallbackUrlTokenFailureReason.malformed,
    );
  }

  final mode = _parseMode(modeValue);

  if (mode == null) {
    return const ZpCallbackUrlTokenFailure(
      ZpCallbackUrlTokenFailureReason.malformed,
    );
  }

  if (expiresAt is int) {
    final now = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;

    if (now >= expiresAt) {
      return const ZpCallbackUrlTokenFailure(
        ZpCallbackUrlTokenFailureReason.expired,
      );
    }
  }

  final extra = Map<String, Object?>.from(data)
    ..remove('m')
    ..remove('u')
    ..remove('t')
    ..remove('a')
    ..remove('iat')
    ..remove('exp');

  return ZpCallbackUrlTokenVerified(
    ZpCallbackUrlTokenPayload(
      mode: mode,
      merchantUniquePaymentId: merchantUniquePaymentId,
      timestamp: timestamp,
      paymentAmount: paymentAmount,
      extra: extra,
    ),
  );
}
