/// Validation logic for the `POST /api/v1/sessions` request body.
///
/// Ensures incoming JSON request payloads strictly match the expected checkout
/// session schema: rejecting unknown fields, verifying string length boundaries,
/// enforcing valid email formats, checking numeric bounds for amounts, and
/// mapping supported client types and checkout modes.
library;

import 'models.dart';

const _allowedCheckoutKeys = {
  'orderId',
  'customerName',
  'customerEmail',
  'mode',
  'client',
  'paymentAmount',
  'customerReference',
  'contactNumber',
};

final _emailPattern = RegExp(r'^[^\s@]+@[^\s@]+\.[^\s@]+$');

/// Validates and parses a decoded JSON body map into a strongly typed [CreateCheckoutBody].
///
/// Performs comprehensive sanity checks on every supplied field:
/// - Rejects unexpected keys with [HttpError] `(400, 'UNKNOWN_CHECKOUT_FIELD')`.
/// - Requires `orderId` (non-empty string <= 128 characters) or throws `(400, 'INVALID_CHECKOUT_REQUEST')`.
/// - Requires `customerName` (non-empty string <= 250 characters) or throws `(400, 'INVALID_CHECKOUT_REQUEST')`.
/// - Requires `customerEmail` (non-empty string <= 254 characters, matching email regex) or throws `(400, 'INVALID_CHECKOUT_REQUEST')`.
/// - Validates optional `mode` (integer between 0 and 3 inclusive) or throws `(400, 'INVALID_CHECKOUT_MODE')`.
/// - Requires valid `client` matching [CheckoutClient] (`"web"`, `"webFrame"`, `"mobile"`) or throws `(400, 'INVALID_CHECKOUT_CLIENT')`.
/// - Requires `paymentAmount` (number > 0 and <= 999,999) or throws `(400, 'INVALID_CHECKOUT_AMOUNT')`.
/// - Validates optional `customerReference` (non-empty string <= 128 characters) or throws `(400, 'INVALID_CHECKOUT_REFERENCE')`.
/// - Validates optional `contactNumber` (non-empty string <= 32 characters) or throws `(400, 'INVALID_CHECKOUT_CONTACT_NUMBER')`.
///
/// Returns a sanitized [CreateCheckoutBody] instance with trimmed string values.
CreateCheckoutBody parseCreateCheckoutBody(Map<String, Object?> value) {
  for (final key in value.keys) {
    if (!_allowedCheckoutKeys.contains(key)) {
      throw HttpError(400, 'UNKNOWN_CHECKOUT_FIELD');
    }
  }

  final orderId = value['orderId'];
  if (orderId is! String ||
      orderId.trim().isEmpty ||
      orderId.trim().length > 128) {
    throw HttpError(400, 'INVALID_CHECKOUT_REQUEST');
  }
  final customerName = value['customerName'];
  if (customerName is! String ||
      customerName.trim().isEmpty ||
      customerName.trim().length > 250) {
    throw HttpError(400, 'INVALID_CHECKOUT_REQUEST');
  }
  final customerEmail = value['customerEmail'];
  if (customerEmail is! String ||
      customerEmail.trim().isEmpty ||
      customerEmail.trim().length > 254 ||
      !_emailPattern.hasMatch(customerEmail.trim())) {
    throw HttpError(400, 'INVALID_CHECKOUT_REQUEST');
  }
  final modeRaw = value['mode'];
  if (modeRaw != null && (modeRaw is! int || modeRaw < 0 || modeRaw > 3)) {
    throw HttpError(400, 'INVALID_CHECKOUT_MODE');
  }
  final client = switch (value['client']) {
    final String c => CheckoutClient.tryParse(c),
    _ => null,
  };
  if (client == null) throw HttpError(400, 'INVALID_CHECKOUT_CLIENT');
  final paymentAmount = value['paymentAmount'];
  if (paymentAmount is! num || paymentAmount <= 0 || paymentAmount > 999999) {
    throw HttpError(400, 'INVALID_CHECKOUT_AMOUNT');
  }
  final customerReferenceRaw = value['customerReference'];
  if (customerReferenceRaw != null &&
      (customerReferenceRaw is! String ||
          customerReferenceRaw.trim().isEmpty ||
          customerReferenceRaw.trim().length > 128)) {
    throw HttpError(400, 'INVALID_CHECKOUT_REFERENCE');
  }
  final contactNumberRaw = value['contactNumber'];
  if (contactNumberRaw != null &&
      (contactNumberRaw is! String ||
          contactNumberRaw.trim().isEmpty ||
          contactNumberRaw.trim().length > 32)) {
    throw HttpError(400, 'INVALID_CHECKOUT_CONTACT_NUMBER');
  }

  return CreateCheckoutBody(
    orderId: orderId.trim(),
    customerName: customerName.trim(),
    customerEmail: customerEmail.trim(),
    client: client,
    paymentAmount: paymentAmount,
    mode: modeRaw as int?,
    customerReference: (customerReferenceRaw as String?)?.trim(),
    contactNumber: (contactNumberRaw as String?)?.trim(),
  );
}
