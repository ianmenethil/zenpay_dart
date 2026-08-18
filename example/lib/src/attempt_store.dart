/// In-memory repository for [CheckoutAttempt] records.
///
/// Provides in-memory tracking of active and historical checkout attempts
/// during the lifecycle of a payment session. Attempts are indexed by their
/// ZenPay [CheckoutAttempt.merchantUniquePaymentId] and by their client-supplied
/// [CheckoutAttempt.idempotencyKey].
///
/// Because state is maintained in-memory, attempts do not survive process
/// restarts. Expired attempts can be pruned via [AttemptStore.purgeCreatedBefore].
library;

import 'models.dart';

/// Thrown by [AttemptStore] on an internal invariant violation.
///
/// These errors indicate programming or storage anomalies (such as an
/// unexpected identifier collision) rather than client-driven validation
/// failures, and typically surface to clients as sanitized 500 HTTP responses.
class AttemptStoreError extends Error {
  AttemptStoreError(this.code);

  final String code;

  @override
  String toString() => code;
}

/// In-memory checkout-attempt store, indexed by merchant unique payment id and
/// idempotency key.
///
/// Maintains a primary lookup table keyed by `merchantUniquePaymentId` and a
/// secondary index mapping `idempotencyKey` to `merchantUniquePaymentId`.
/// Single-index lookup ensures consistency without maintaining separate
/// conflicting merchant identifiers.
class AttemptStore {
  final _byMerchantPaymentId = <String, CheckoutAttempt>{};
  final _byIdempotencyKey = <String, String>{};

  /// Adds a new [attempt] to the store.
  ///
  /// Maps both [attempt.merchantUniquePaymentId] and [attempt.idempotencyKey].
  ///
  /// Throws [AttemptStoreError] with code `'DUPLICATE_CHECKOUT_ATTEMPT'` if an
  /// attempt with the same [CheckoutAttempt.merchantUniquePaymentId] already exists.
  void create(CheckoutAttempt attempt) {
    if (_byMerchantPaymentId.containsKey(attempt.merchantUniquePaymentId)) {
      throw AttemptStoreError('DUPLICATE_CHECKOUT_ATTEMPT');
    }
    _byMerchantPaymentId[attempt.merchantUniquePaymentId] = attempt;
    _byIdempotencyKey[attempt.idempotencyKey] = attempt.merchantUniquePaymentId;
  }

  /// Looks up an attempt by its ZenPay [merchantUniquePaymentId].
  ///
  /// Returns `null` if no attempt with the given identifier exists.
  CheckoutAttempt? getByMerchantPaymentId(String merchantUniquePaymentId) =>
      _byMerchantPaymentId[merchantUniquePaymentId];

  /// Looks up an attempt by the client-supplied [key].
  ///
  /// Returns `null` if no attempt associated with the idempotency key exists.
  CheckoutAttempt? getByIdempotencyKey(String key) {
    final id = _byIdempotencyKey[key];
    return id == null ? null : _byMerchantPaymentId[id];
  }

  /// Removes every attempt created before the [cutoff] timestamp.
  ///
  /// Prunes both the primary payment ID and secondary idempotency key indexes.
  /// Returns the total number of attempts removed.
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
  ///
  /// Returns the updated [next] attempt.
  ///
  /// Throws [AttemptStoreError] with code `'CHECKOUT_ATTEMPT_NOT_FOUND'` if no
  /// attempt currently exists for [merchantUniquePaymentId].
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
