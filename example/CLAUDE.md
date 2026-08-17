# Reference Merchant Backend — Source Architecture & File Guide

This document outlines all source files in the reference merchant backend (`example/`), detailing each file's purpose along with a concise single-line breakdown of every class, function, and enum explaining what it does, why it exists, and where it is used.

---

## 1. `lib/src/checkout_state.dart`

**File Path:** [example/lib/src/checkout_state.dart](file:///g:/_zp-repos/zp-flutter-sdk/backend/example/lib/src/checkout_state.dart)  
**Overview:** Defines the domain models, payment status lifecycle enums, ZenPay status mapping logic, and the in-memory `AttemptStore` tracking active checkout sessions.

- **`enum CheckoutClient`**: Distinguishes client presentation modes (`web`, `webFrame`, `mobile`) to prevent open redirects; used in `POST /api/v1/sessions` and `appReturnUriFor`.
- **`CheckoutClient.tryParse(String value)`**: Parses wire strings (`"web"`, `"webFrame"`, `"mobile"`) into the enum; used in `_parseCreateCheckoutBody` during request validation.
- **`enum MerchantPaymentStatus`**: Models the merchant-facing payment lifecycle states (`created`, `sessionCreated`, `browserReturned`, `pending`, `successful`, `failed`, `cancelled`, `error`, `unknown`); stored on `CheckoutAttempt.status` and returned in status lookup polling.
- **`_zpPaymentStatusFromWireValue(int value)`**: Maps integer status codes from ZenPay's callback format to `ZpPaymentStatus`; used internally by `mapZenPayStatus`.
- **`mapZenPayStatus(int statusCode)`**: Translates ZenPay wire status integers into simplified `MerchantPaymentStatus` values; used in `_handleCallback` when applying callback results.
- **`class CheckoutAttempt`**: Central entity tracking correlation IDs, order metadata, launch URLs, and verified callback results; managed in `AttemptStore` across the full payment lifecycle.
- **`CheckoutAttempt.copyWith(...)`**: Creates an immutable copy with updated status or callback fields; used during state transitions in `createSession`, `_handleCallback`, and `_handleReturn`.
- **`class CreateCheckoutBody`**: Strongly typed model representing a validated `POST /api/v1/sessions` request body; constructed by `_parseCreateCheckoutBody` and consumed by `createSession`.
- **`class AppCheckoutSession`**: Data transfer object holding `merchantUniquePaymentId` and `checkoutUrl`; returned by `createSession` and serialized in `_handleCreateSession`.
- **`class HttpError`**: Exception carrying an HTTP status code and machine-readable error code string; thrown during request processing and converted to JSON errors in `buildHandler`.
- **`class AttemptStoreError`**: Internal error thrown on unexpected storage invariant violations (e.g. ID collisions); caught in `buildHandler` to emit sanitized 500 responses.
- **`class AttemptStore`**: In-memory repository for `CheckoutAttempt` records indexed by payment ID and idempotency key; instantiated in `bin/server.dart` and injected into route handlers.
- **`AttemptStore.create(CheckoutAttempt attempt)`**: Inserts a new attempt record and maps its idempotency key; called by `createSession` when initiating a new checkout.
- **`AttemptStore.getByMerchantPaymentId(String id)`**: Looks up an attempt by ZenPay payment identifier; used in `_handleGetSession`, `_handleCallback`, and `_handleReturn`.
- **`AttemptStore.getByIdempotencyKey(String key)`**: Checks for an existing attempt by idempotency key to prevent duplicate session creation; called at the start of `createSession`.
- **`AttemptStore.purgeCreatedBefore(DateTime cutoff)`**: Prunes expired attempts older than the TTL cutoff to prevent unbounded memory growth; invoked periodically by the cleanup timer in `bin/server.dart`.
- **`AttemptStore.replace(String id, CheckoutAttempt next)`**: Replaces an existing stored attempt with updated state; called after URL generation, browser return, and callback verification.

---

## 2. `lib/src/config.dart`

**File Path:** [example/lib/src/config.dart](file:///g:/_zp-repos/zp-flutter-sdk/backend/example/lib/src/config.dart)  
**Overview:** Manages runtime configuration by loading `.env` properties overlaid with process environment variables.

- **`class ZenPayCredentials`**: Encapsulates merchant credentials (`merchantCode`, `apiKey`, `username`, `password`); stored in `ZenPayConfig` and passed to cryptographic functions in `session_service.dart` and `security.dart`.
- **`class ZenPayConfig`**: Holds ZenPay HCP endpoints, domain host allowlists, and credentials; embedded inside `AppConfig` and used when constructing/validating launch URLs.
- **`class AppConfig`**: Immutable configuration container holding port, base URLs, origins, tokens, TTLs, and ZenPay settings; injected into `buildHandler`, `createSession`, `verifyCallback`, and `bin/server.dart`.
- **`AppConfig.callbackTokenSecretConfigured`**: Boolean getter checking if `callbackTokenSecret` meets the 32-byte minimum for token signing; checked by `_callbackUrlFor`. `checkCallbackToken` performs its own inline length check on the raw secret string rather than calling this getter.
- **`_read(DotEnv file, String key)`**: Resolves a configuration value preferring process environment variables over `.env` entries; used internally by `loadConfig`.
- **`_numberOr(String? raw, int fallback)`**: Parses integer strings with fallback logic for null, zero, or non-numeric values; used in `loadConfig` for `PORT` and `CHECKOUT_STATUS_TTL_MINUTES`.
- **`loadConfig()`**: Reads `.env` and environment variables to construct the validated `AppConfig` instance; called at startup in `bin/server.dart`.
- **`sessionConfigurationErrors(AppConfig config)`**: Returns missing environment variables required for session creation; evaluated in `_handleHealth` and `_handleCreateSession`.
- **`callbackConfigurationErrors(AppConfig config)`**: Returns missing environment variables required for callback verification; evaluated in `_handleHealth` and `_handleCallback`.

---

## 3. `lib/src/rate_limiter.dart`

**File Path:** [example/lib/src/rate_limiter.dart](file:///g:/_zp-repos/zp-flutter-sdk/backend/example/lib/src/rate_limiter.dart)  
**Overview:** Implements a fixed-window request rate limiter to protect backend routes from abuse and brute-force traffic.

- **`class _RateLimitWindow`**: Internal record tracking request count and window reset timestamp; stored per IP key in `FixedWindowRateLimiter._entries`.
- **`class FixedWindowRateLimiter`**: Fixed-window rate limiter keyed by client IP; instantiated in `server_app.dart` to protect merchant API routes (`_appRouteLimiter`) and callback webhooks (`_callbackLimiter`).
- **`FixedWindowRateLimiter.allow(String key, [DateTime? now])`**: Determines whether a request from the given key is permitted under the limit threshold; called by `_requireRateLimit` in `server_app.dart`.

---

## 4. `lib/src/security.dart`

**File Path:** [example/lib/src/security.dart](file:///g:/_zp-repos/zp-flutter-sdk/backend/example/lib/src/security.dart)  
**Overview:** Provides security primitives, timing-safe string comparison, and callback verification against ZenPay cryptographic standards.

- **`constantTimeEqual(String a, String b)`**: Compares strings in constant time using SHA-256 digest equality to prevent timing attacks; used in `_requireMerchantAuthorization` and callback reference verification.
- **`class CallbackFields`**: Immutable data structure holding the 4 fields (`reference`, `statusCode`, `failureCode`, `failureReason`) copied out of a verified `ZpCallbackVerified` — out of ~27 fields the SDK now returns, the rest (business/reconciliation metadata) are not extracted; returned in `CallbackVerification.ok` and applied to `CheckoutAttempt` in `_handleCallback`.
- **`class CallbackVerification`**: Result type representing successful verification (`ok`) or rejection reason (`rejected`); returned by `verifyCallback` to communicate authentication outcomes.
- **`verifyCallback(Map<String, Object?> payload, CheckoutAttempt attempt, ZenPayCredentials credentials)`**: Authenticates an incoming webhook payload's `ValidationCode` HMAC-SHA3-512 signature against attempt details via `package:zenpay_dart`; called in `_handleCallback`.
- **`checkCallbackToken(String? tokenRaw, String secret)`**: Validates the optional signed `?t=` HMAC token on callback URLs for telemetry; called in `_handleCallback` without gating callback acceptance.

---

## 5. `lib/src/server_app.dart`

**File Path:** [example/lib/src/server_app.dart](file:///g:/_zp-repos/zp-flutter-sdk/backend/example/lib/src/server_app.dart)  
**Overview:** Implements the complete HTTP routing surface with Shelf, covering CORS preflight, error sanitization, request logging, and route dispatching.

- **`abstract final class _HeaderNames`**: Standardized HTTP header string constants; used across request parsing and response building in `server_app.dart`.
- **`_requireRateLimit(FixedWindowRateLimiter limiter, String key)`**: Enforces rate limits, throwing `HttpError(429)` if exceeded; guards session, status, and callback endpoints.
- **`_requireMerchantAuthorization(String? authorization, AppConfig config)`**: Validates `Authorization: Bearer <token>` headers with constant-time comparison; guards `_handleCreateSession` and `_handleGetSession`.
- **`_clientIp(shelf.Request request)`**: Extracts client IP from `X-Forwarded-For` or connection info; used for rate-limiting keys and structured request logs.
- **`_readJson(shelf.Request request)`**: Parses JSON request bodies with a 64KB size cap and Content-Type checks; used in `_handleCreateSession` and `_handleCallback`.
- **`_json(int status, Object? body, {String? allowedOrigin})`**: Constructs JSON responses with security headers (`nosniff`, `no-store`, CSP); used by all API endpoints.
- **`_redirect(Uri location)`**: Generates a `303 See Other` response redirecting non-`webFrame` clients back to the merchant — an App Link URI for `mobile`, a plain web origin (`config.appReturnUriWeb`) for `web`; used in `_handleReturn`.
- **`_frameReturnPageHtml(String targetOrigin, String attempt)`**: Generates an HTML response that `postMessage`s completion data to `window.parent` against a fixed target origin; used in `_handleReturn` for `webFrame` clients.
- **`_handleTestPage(AppConfig config)` & `_testPageHtml(AppConfig config)`**: Serves an interactive HTML/JS testing interface at `GET /` for manual checkout flow verification; dispatched for root `GET /`.
- **`_parseCreateCheckoutBody(Map<String, Object?> value)`**: Validates required fields, lengths, email formats, and parameter constraints for session requests; called in `_handleCreateSession`.
- **`_handleHealth(AppConfig config)`**: Answers `GET /api/v1/health` with service availability and configuration readiness indicators; used for health checks and startup polling in `run.ps1`.
- **`_handleAssetlinks()`**: Serves `/.well-known/assetlinks.json` for Android App Links verification; dispatched for `GET /.well-known/assetlinks.json`.
- **`_handleCreateSession(shelf.Request request, AppConfig config, AttemptStore store)`**: Authenticates requests, generates launch URLs via `createSession`, and stores attempts; handles `POST /api/v1/sessions`.
- **`_handleGetSession(shelf.Request request, Uri requestedUri, AppConfig config, AttemptStore store)`**: Returns authoritative payment state and callback details for an attempt; handles `GET /api/v1/sessions/:id`.
- **`_handleCallback(shelf.Request request, AppConfig config, AttemptStore store)`**: Processes ZenPay webhooks, verifies cryptographic signatures, and updates attempt payment status; handles `POST /api/v1/callbacks`.
- **`_handleReturn(Uri requestedUri, AppConfig config, AttemptStore store)`**: Processes ZenPay browser redirects, validates correlation IDs, updates attempt status, and forwards to the app; handles `GET /return`.
- **`_dispatch(shelf.Request request, AppConfig config, AttemptStore store)`**: Routes incoming HTTP requests to their matching route handlers; called by `buildHandler`.
- **`buildHandler(AppConfig config, AttemptStore store)`**: Assembles the top-level Shelf pipeline with CORS preflight, error formatting, and structured logging; passed to `shelf_io.serve` in `bin/server.dart`.
- **`logEvent(String event, [Map<String, Object?> fields, bool isError])`**: Emits structured JSON log lines to stdout/stderr without logging sensitive payment credentials; used across all request and lifecycle events.

---

## 6. `lib/src/session_service.dart`

**File Path:** [example/lib/src/session_service.dart](file:///g:/_zp-repos/zp-flutter-sdk/backend/example/lib/src/session_service.dart)  
**Overview:** Coordinates checkout session creation, idempotency validation, cryptographic fingerprinting, and HCP Authorise launch URL construction.

- **`sessionsPathPrefix`, `returnPath`, `callbacksPath`**: String constants defining backend URL routing paths; used across routing and URL construction.
- **`merchantUniquePaymentIdFromPath(String pathname)`**: Extracts the payment identifier from `/api/v1/sessions/:id` paths; called in `_handleGetSession`.
- **`appReturnUriFor(CheckoutAttempt attempt, AppConfig config)`**: Computes the return URI (App Link for mobile or web origin for browser) based on client mode; used in `_handleReturn`.
- **`_requireIdempotentMatch(CheckoutAttempt existing, CreateCheckoutBody body, int mode)`**: Ensures idempotency key replays match original order and amount details, throwing `HttpError(409)` on conflict; called in `createSession`.
- **`_toAppCheckoutSession(CheckoutAttempt attempt)`**: Converts a stored `CheckoutAttempt` into the `AppCheckoutSession` response model; called in `createSession`.
- **`_fingerprintAmount(CreateCheckoutBody body, int mode)`**: Determines payment amount to hash into the SHA3-512 fingerprint (zero for non-payment modes); used in `_buildCheckoutUrl` and `_callbackUrlFor`.
- **`_isPaymentLike(int mode)`**: Returns whether a checkout mode involves immediate financial transfer (modes 0, 2, 3); helper for fingerprinting and request construction.
- **`_callbackUrlFor(...)`**: Constructs callback URLs with an optional signed `?t=<token>` query parameter; supplied to `_buildAuthoriseRequest`.
- **`_buildAuthoriseRequest(...)`**: Assembles the complete `ZpCheckoutUrlRequest` with fingerprints, callback URLs, redirect URLs, and payment method flags; called in `_buildCheckoutUrl`.
- **`_buildCheckoutUrl(...)`**: Computes the SHA3-512 fingerprint and builds the verified launch URL via `package:zenpay_dart`; called in `createSession`.
- **`createSession(CreateCheckoutBody body, String idempotencyKey, AppConfig config, AttemptStore store)`**: Orchestrates session creation, idempotency checking, attempt persistence, and launch URL generation; called by `_handleCreateSession`.
- **`class ZenPaySessionException`**: Exception thrown when checkout URL generation fails or target URLs violate host allowlists; thrown in `_buildCheckoutUrl` and `resolveCheckoutUrl`.
- **`resolveCheckoutUrl(String endpointUrl, AppConfig config)`**: Validates that generated checkout URLs use HTTPS and point to allowed host domains; called in `_buildCheckoutUrl`.
