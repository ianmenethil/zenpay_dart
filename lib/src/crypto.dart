/// Shared cryptographic and ID-generation primitives for ZenPay HCP:
/// SHA3-512 hashing, dollars-to-cents conversion for the hash pipe, and the
/// per-payment identifier and timestamp every launch/fingerprint needs.
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:hashlib/hashlib.dart';
import 'package:hashlib/random.dart';
import 'enums.dart';

final _amountPattern = RegExp(r'^\d+(\.\d{1,2})?$');
final _timestampPattern = RegExp(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$');

const _zeroCents = ZpCents('0');
const _zeroAmount = '0';
const _zeroDecimalAmount = '0.00';
const _emptyAmount = '';
const _base64Padding = '=';
const _decimalDelimiter = '.';

/// Strongly typed cents value to prevent accidental dollar hashing.
extension type const ZpCents(String value) {}

/// Strongly typed Merchant Unique Payment ID.
extension type const ZpMupid(String value) {}

/// Strongly typed timestamp.
extension type const ZpTimestamp(String value) {}

/// SHA3-512 hash of [input], as 128-character lowercase hex.
String createSha3_512(String input) => sha3_512.string(input).hex();

/// Compares two SHA3-512 hex digests in constant time, avoiding a timing
/// side-channel.
bool constantTimeHexEqual(String a, String b) =>
    HashDigest(Uint8List.fromList(utf8.encode(a))).isEqual(utf8.encode(b));

/// Converts a dollar [amount] (string or number, at most 2 decimal places)
/// to a whole-number cents string for the hash pipe.
///
/// Returns `null` if [amount] is not a non-negative number with at most 2
/// decimal places.
ZpCents? zpAmountToCents(Object amount) {
  final trimmed = amount.toString().trim();
  if (!_amountPattern.hasMatch(trimmed)) return null;

  final parts = trimmed.split(_decimalDelimiter);
  final whole = BigInt.parse(parts[0]);
  final fraction = (parts.length > 1 ? parts[1] : '').padRight(2, _zeroAmount);
  return ZpCents(
    (whole * BigInt.from(100) + BigInt.parse(fraction)).toString(),
  );
}

/// Resolves the hash-pipe amount field for [mode] and [amount] (dollars).
///
/// Mode 2 (Custom Payment) always hashes `"0"`; mode 1 (Tokenise) with no
/// amount (empty, `"0"`, or `"0.00"`) also hashes `"0"`. Returns `null` if
/// [amount] cannot be resolved to a valid cents string.
ZpCents? resolveZpHashAmountField(ZpPluginMode mode, Object amount) {
  return switch (mode) {
    ZpPluginMode.customPayment => _zeroCents,
    ZpPluginMode.tokenise => switch (amount.toString().trim()) {
      _emptyAmount || _zeroAmount || _zeroDecimalAmount => _zeroCents,
      _ => zpAmountToCents(amount),
    },
    _ => zpAmountToCents(amount),
  };
}

/// Creates a unique `merchantUniquePaymentId` — base64url of 16 secure
/// random bytes (22 characters, no padding). Generate once per payment and
/// reuse the same value for retries; ZenPay de-duplicates by it.
ZpMupid createZpMupid() =>
    ZpMupid(base64Url.encode(randomBytes(16)).replaceAll(_base64Padding, ''));

/// Creates a slice-19 UTC ISO 8601 timestamp (`YYYY-MM-DDTHH:MM:SS`) — the
/// format ZenPay's Authorise API requires. Generate once per payment and
/// reuse the exact same string in both the fingerprint and the launch URL,
/// or the fingerprint will not match.
ZpTimestamp createZpTimestamp() =>
    ZpTimestamp(DateTime.now().toUtc().toIso8601String().substring(0, 19));

/// Whether [timestamp] matches the `yyyy-MM-ddTHH:mm:ss` shape
/// [createZpTimestamp] produces.
bool isValidZpTimestamp(String timestamp) =>
    _timestampPattern.hasMatch(timestamp);
