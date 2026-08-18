/// Runtime configuration for the reference backend.
///
/// Loads settings from `.env` files overlaid with process environment
/// variables (process environment variables always take precedence). Manages
/// server listening ports, allowed origins, merchant API authentication tokens,
/// TTLs, and ZenPay credentials/endpoints.
library;

import 'dart:io';

import 'package:dotenv/dotenv.dart';

/// ZenPay API credentials and authentication secrets.
///
/// Contains sensitive merchant credentials needed for SHA3-512 fingerprinting
/// and callback verification. Must never be logged or serialized to client responses.
class ZenPayCredentials {
  const ZenPayCredentials({
    required this.merchantCode,
    required this.apiKey,
    required this.username,
    required this.password,
  });

  /// ZenPay merchant identifier assigned to the merchant account.
  final String merchantCode;

  /// ZenPay API key used for cryptographic signature generation and verification.
  final String apiKey;

  /// Merchant username for ZenPay API authentication.
  final String username;

  /// Merchant password or shared secret used in fingerprint generation and callback hashing.
  final String password;
}

/// ZenPay Hosted Payment Page (HCP) endpoint configuration, allowlists, and credentials.
class ZenPayConfig {
  const ZenPayConfig({
    required this.hppEndpointUrl,
    required this.allowedCheckoutHosts,
    required this.credentials,
  });

  /// The full HCP Authorise endpoint URL, including its `/Online/v4` or `/Online/v5` path.
  ///
  /// The SDK appends the merchant code and action to this base URL during checkout
  /// launch URL generation.
  final Uri hppEndpointUrl;

  /// Allowlist of permitted hostnames for generated ZenPay checkout launch URLs.
  ///
  /// Used by launch URL verification to protect against open redirects or malicious
  /// endpoint hijacking.
  final Set<String> allowedCheckoutHosts;

  final ZenPayCredentials credentials;
}

/// Immutable runtime configuration container for the reference backend.
class AppConfig {
  const AppConfig({
    required this.port,
    required this.publicBaseUrl,
    required this.allowedAppOrigin,
    required this.merchantAppBearerToken,
    required this.appReturnUriWeb,
    required this.checkoutStatusTtlMinutes,
    required this.zenPay,
    this.callbackTokenSecret = '',
  });

  final int port;

  /// Canonical public base URL where this backend service is reachable.
  ///
  /// Used for constructing callback URLs, return URLs, and App Links.
  final Uri publicBaseUrl;

  /// Permitted Web origin for CORS preflight headers and postMessage frame targets.
  final String allowedAppOrigin;

  /// Static Bearer token expected in `Authorization: Bearer <token>` headers from client apps.
  final String merchantAppBearerToken;

  /// Browser return URI for web client redirects after payment completion or cancellation.
  final Uri appReturnUriWeb;

  /// In-memory storage time-to-live (in minutes) for historical checkout attempts.
  final int checkoutStatusTtlMinutes;

  final ZenPayConfig zenPay;

  /// HMAC secret for the optional signed `?t=` callback-URL token (see
  /// `security.dart`'s `checkCallbackToken`), separate from the ZenPay
  /// password. Never gates session creation or callback acceptance — see
  /// [callbackTokenSecretConfigured].
  final String callbackTokenSecret;

  /// Whether [callbackTokenSecret] meets `package:zenpay_dart`'s minimum
  /// length (32 bytes) for `createZpCallbackUrlToken`/
  /// `verifyZpCallbackUrlToken`. The callback-URL-token feature is simply
  /// inactive below that — it is best-effort, not required configuration.
  bool get callbackTokenSecretConfigured => callbackTokenSecret.length >= 32;
}

/// Reads a configuration property, giving precedence to OS environment variables
/// over values defined in the `.env` file.
String? _read(DotEnv file, String key) {
  final real = Platform.environment[key];
  if (real != null && real.isNotEmpty) return real;
  return file.isDefined(key) ? file[key] : null;
}

/// Parses an integer string, returning [fallback] if [raw] is null, blank,
/// non-numeric, or evaluates to zero.
int _numberOr(String? raw, int fallback) {
  final n = raw == null ? null : num.tryParse(raw);
  return (n == null || n == 0) ? fallback : n.toInt();
}

/// Loads [AppConfig] from `.env` (if present), overlaid by real process
/// environment variables, which always win over the file.
///
/// Applies default fallbacks for optional or development settings when not explicitly defined.
AppConfig loadConfig() {
  final file = DotEnv(quiet: true)..load();
  String value(String key, String fallback) => _read(file, key) ?? fallback;

  final hosts =
      value('ZENPAY_ALLOWED_CHECKOUT_HOSTS', 'pay.sandbox.travelpay.com.au')
          .split(',')
          .map((h) => h.trim().toLowerCase())
          .where((h) => h.isNotEmpty)
          .toSet();

  return AppConfig(
    port: _numberOr(_read(file, 'PORT'), 7000),
    publicBaseUrl: Uri.parse(value('PUBLIC_BASE_URL', 'http://localhost:7000')),
    allowedAppOrigin: value('ALLOWED_APP_ORIGIN', 'http://localhost:3000'),
    merchantAppBearerToken: value(
      'MERCHANT_APP_BEARER_TOKEN',
      'local-demo-token',
    ),
    appReturnUriWeb: Uri.parse(
      value('APP_RETURN_URI_WEB', 'https://localhost:3000/'),
    ),
    checkoutStatusTtlMinutes: _numberOr(
      _read(file, 'CHECKOUT_STATUS_TTL_MINUTES'),
      60,
    ),
    zenPay: ZenPayConfig(
      hppEndpointUrl: Uri.parse(
        value(
          'ZENPAY_HPP_ENDPOINT_URL',
          'https://pay.sandbox.travelpay.com.au/Online/v5',
        ),
      ),
      allowedCheckoutHosts: hosts,
      credentials: ZenPayCredentials(
        merchantCode: value('ZENPAY_MERCHANT_CODE', ''),
        apiKey: value('ZENPAY_API_KEY', ''),
        username: value('ZENPAY_USERNAME', ''),
        password: value('ZENPAY_PASSWORD', ''),
      ),
    ),
    callbackTokenSecret: value('CALLBACK_TOKEN_SECRET', ''),
  );
}

/// Identifies missing environment variables required for session creation.
///
/// Returns a list of missing configuration key names. An empty list indicates
/// that all prerequisites for initiating checkout sessions are met.
List<String> sessionConfigurationErrors(AppConfig config) => [
  if (config.zenPay.credentials.merchantCode.isEmpty) 'ZENPAY_MERCHANT_CODE',
  if (config.zenPay.credentials.apiKey.isEmpty) 'ZENPAY_API_KEY',
  if (config.zenPay.credentials.username.isEmpty) 'ZENPAY_USERNAME',
  if (config.zenPay.credentials.password.isEmpty) 'ZENPAY_PASSWORD',
];

/// Identifies missing environment variables required for webhook callback verification.
///
/// Returns a list of missing configuration key names. An empty list indicates
/// that all prerequisites for authenticating ZenPay callbacks are met.
List<String> callbackConfigurationErrors(AppConfig config) => [
  if (config.zenPay.credentials.apiKey.isEmpty) 'ZENPAY_API_KEY',
  if (config.zenPay.credentials.username.isEmpty) 'ZENPAY_USERNAME',
  if (config.zenPay.credentials.password.isEmpty) 'ZENPAY_PASSWORD',
];
