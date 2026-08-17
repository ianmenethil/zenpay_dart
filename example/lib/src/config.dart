/// Runtime configuration for the reference backend: `.env` values overlaid
/// by real process environment variables, which always win.
library;

import 'dart:io';

import 'package:dotenv/dotenv.dart';

/// ZenPay API credentials. Never logged.
class ZenPayCredentials {
  const ZenPayCredentials({
    required this.merchantCode,
    required this.apiKey,
    required this.username,
    required this.password,
  });

  final String merchantCode;
  final String apiKey;
  final String username;
  final String password;
}

/// ZenPay HCP endpoint, credentials, and the launch-URL host allowlist.
class ZenPayConfig {
  const ZenPayConfig({
    required this.hppEndpointUrl,
    required this.allowedCheckoutHosts,
    required this.credentials,
  });

  /// The full HCP Authorise endpoint, including its `/Online/v4` or
  /// `/Online/v5` path — `createZpCheckoutUrl` appends the merchant code and
  /// action to it, and `zpAuthoriseRequestSchema` rejects anything else.
  final Uri hppEndpointUrl;
  final Set<String> allowedCheckoutHosts;
  final ZenPayCredentials credentials;
}

/// Immutable runtime configuration for the reference backend.
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
  final Uri publicBaseUrl;
  final String allowedAppOrigin;
  final String merchantAppBearerToken;
  final Uri appReturnUriWeb;
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

String? _read(DotEnv file, String key) {
  final real = Platform.environment[key];
  if (real != null && real.isNotEmpty) return real;
  return file.isDefined(key) ? file[key] : null;
}

/// Mirrors JavaScript's `Number(x) || fallback`: blank, non-numeric, and
/// zero all fall back, matching the ported config's original semantics.
int _numberOr(String? raw, int fallback) {
  final n = raw == null ? null : num.tryParse(raw);
  return (n == null || n == 0) ? fallback : n.toInt();
}

/// Loads [AppConfig] from `.env` (if present), overlaid by real process
/// environment variables, which always win over the file.
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

/// Missing env vars that block session creation.
List<String> sessionConfigurationErrors(AppConfig config) => [
  if (config.zenPay.credentials.merchantCode.isEmpty) 'ZENPAY_MERCHANT_CODE',
  if (config.zenPay.credentials.apiKey.isEmpty) 'ZENPAY_API_KEY',
  if (config.zenPay.credentials.username.isEmpty) 'ZENPAY_USERNAME',
  if (config.zenPay.credentials.password.isEmpty) 'ZENPAY_PASSWORD',
];

/// Missing env vars that block callback verification.
List<String> callbackConfigurationErrors(AppConfig config) => [
  if (config.zenPay.credentials.apiKey.isEmpty) 'ZENPAY_API_KEY',
  if (config.zenPay.credentials.username.isEmpty) 'ZENPAY_USERNAME',
  if (config.zenPay.credentials.password.isEmpty) 'ZENPAY_PASSWORD',
];
