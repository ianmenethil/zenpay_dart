/// Shared cryptographic and ID-generation primitives for ZenPay HCP.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:hashlib/hashlib.dart';
import 'package:hashlib/random.dart';

import 'enums.dart';

final _amountPattern = RegExp(r'^\d+(?:\.\d{1,2})?$');
final _timestampPattern =
    RegExp(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$');

const _zeroCents = ZpCents('0');

/// Padding character stripped from base64url output.
const zpBase64Padding = '=';

/// Pipe delimiter joining fields in ZenPay hash strings.
const zpPipeDelimiter = '|';

/// Minimum length required for ZenPay hash-pipe credential fields.
const zpMinCredentialLength = 5;

/// Error returned when `paymentAmount` is not numeric.
const zpErrPaymentAmountNumber = 'paymentAmount must be a valid number';

/// Error returned when `paymentAmount` must be positive but is not.
const zpErrPaymentAmountPositive = 'paymentAmount must be greater than 0';

/// Strongly typed cents value to prevent accidental dollar hashing.
extension type const ZpCents(String value) {}

/// Strongly typed Merchant Unique Payment ID.
extension type const ZpMupid(String value) {}

/// Strongly typed ZenPay timestamp.
extension type const ZpTimestamp(String value) {}

/// Creates a SHA3-512 hash of [input] as 128-character lowercase hex.
String createSha3_512(String input) => sha3_512.string(input).hex();

/// Compares two SHA3-512 hexadecimal digests using [HashDigest.isEqual].
bool constantTimeHexEqual(String a, String b) =>
    HashDigest(Uint8List.fromList(utf8.encode(a))).isEqual(utf8.encode(b));

/// Converts a dollar [amount] to whole-number cents.
///
/// Accepts non-negative values with at most two decimal places.
/// Returns `null` when [amount] is invalid.
ZpCents? zpAmountToCents(Object? amount) {
  if (amount == null) return null;

  final value = amount.toString().trim();
  if (!_amountPattern.hasMatch(value)) return null;

  final parts = value.split('.');
  final whole = parts[0];
  final fraction = parts.length > 1 ? parts[1] : '';

  return ZpCents(
    (
      BigInt.parse(whole) * BigInt.from(100) +
      BigInt.parse(fraction.padRight(2, '0'))
    ).toString(),
  );
}

/// Resolves the amount used in a ZenPay fingerprint or callback hash.
///
/// Custom Payment always hashes `"0"`. Tokenise hashes `"0"` when no amount
/// is supplied. Other values are converted from dollars to cents.
ZpCents? resolveZpHashAmountField(
  ZpPluginMode mode,
  Object? amount,
) =>
    switch (mode) {
      ZpPluginMode.customPayment => _zeroCents,
      ZpPluginMode.tokenise
          when amount == null || amount.toString().trim().isEmpty =>
        _zeroCents,
      _ => zpAmountToCents(amount),
    };

/// Why [resolveZpHashAmountChecked] failed.
enum ZpAmountFailureReason {
  /// The amount does not parse as a number.
  notANumber,

  /// The mode requires an amount greater than zero.
  notPositive,

  /// The amount is numeric but cannot be represented as valid ZenPay cents.
  unresolvable,
}

/// Validates [amount] for [mode] and resolves the hash-pipe cents value.
(ZpCents?, ZpAmountFailureReason?) resolveZpHashAmountChecked(
  ZpPluginMode mode,
  Object? amount,
) {
  final value = amount?.toString().trim() ?? '';

  if (mode == ZpPluginMode.tokenise && value.isEmpty) {
    return (_zeroCents, null);
  }

  final numericAmount = num.tryParse(value);

  if (numericAmount == null) {
    return (null, ZpAmountFailureReason.notANumber);
  }

  if (mode.requiresPositiveAmount && numericAmount <= 0) {
    return (null, ZpAmountFailureReason.notPositive);
  }

  final cents = resolveZpHashAmountField(mode, amount);

  return cents == null
      ? (null, ZpAmountFailureReason.unresolvable)
      : (cents, null);
}

/// Creates a fresh Merchant Unique Payment ID.
///
/// Generates 16 random bytes encoded as unpadded base64url. Create a new value
/// for every plugin open; do not reuse a previous payment attempt's MUPID.
ZpMupid createZpMupid() => ZpMupid(
  base64Url.encode(randomBytes(16)).replaceAll(zpBase64Padding, ''),
);

/// Creates the UTC timestamp required by ZenPay.
///
/// Create a fresh timestamp for every plugin open and use this exact value in
/// both the fingerprint and Authorise request.
ZpTimestamp createZpTimestamp() => ZpTimestamp(
  DateTime.now().toUtc().toIso8601String().substring(0, 19),
);

/// Whether [timestamp] matches the `yyyy-MM-ddTHH:mm:ss` wire format.
bool isValidZpTimestamp(String timestamp) =>
    _timestampPattern.hasMatch(timestamp);