/// Checkout domain types, ZenPay status mapping, and the in-memory attempt
/// store keyed by `merchantUniquePaymentId` and idempotency key.
///
/// Serves as a barrel library combining [AttemptStore] repository facilities
/// with core checkout domain entities ([CheckoutAttempt], [CreateCheckoutBody],
/// [AppCheckoutSession], [CheckoutClient], [MerchantPaymentStatus], [HttpError]).
library;

export 'attempt_store.dart';
export 'models.dart';
