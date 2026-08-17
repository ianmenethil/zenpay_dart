# zenpay_dart

Pure-Dart backend SDK for the ZenPay Hosted Checkout Plugin (HCP). Provides SHA3-512 fingerprint generation, launch URL construction, server-to-server callback verification, and signed callback URL tokens — everything a merchant backend needs to integrate with ZenPay's hosted payment page without any browser-side dependencies.

> **Server-side only.** Never import this package from a Flutter mobile app or frontend. Fingerprint generation and callback verification involve merchant credentials that must stay on your server.

---

## Packages

| Package | Path | Description |
| :--- | :--- | :--- |
| `zenpay_dart` | `lib/` | Core SDK: cryptographic fingerprinting, checkout URL builder, callback verifier, callback URL token signer, wire enums. |
| `zenpay_dart_example` | `example/` | Reference merchant backend: Shelf HTTP server demonstrating session creation, status polling, callback handling, and browser-return brokering. |

---

## Architecture

```
lib/
├── zenpay_dart.dart           # Barrel export (public API)
└── src/
    ├── callback.dart          # SHA3-512 callback verification
    ├── callback_token.dart    # HMAC-SHA3-512 signed URL tokens
    ├── checkout_url.dart      # Authorise launch URL construction
    ├── crypto.dart            # SHA3-512, constant-time comparison, ID generation
    ├── enums.dart             # Wire integer enums (modes, statuses, display)
    └── fingerprint.dart       # Outgoing fingerprint (SHA3-512 hash pipe)

example/
├── bin/
│   └── server.dart            # Shelf server entrypoint
├── lib/src/
│   ├── checkout_state.dart    # Domain models, AttemptStore
│   ├── config.dart            # .env + env var configuration
│   ├── rate_limiter.dart      # Fixed-window IP rate limiter
│   ├── security.dart          # Constant-time comparison, callback verification
│   ├── server_app.dart        # HTTP routing, CORS, error handling, logging
│   └── session_service.dart   # Session creation, idempotency, URL building
├── openapi.yaml               # API specification
├── .env.example               # Annotated configuration template
└── test/                      # Integration tests
```

For detailed per-entity documentation of every class, function, and enum:

- **[lib/AGENTS.md](lib/AGENTS.md)** — Core `zenpay_dart` package source guide.
- **[example/AGENTS.md](example/AGENTS.md)** — Reference backend source guide.

---

## Quick Start

### Prerequisites

- Dart SDK ≥ 3.12.0
- A ZenPay sandbox or production merchant account

### 1. Install Dependencies

```bash
dart pub get
cd example && dart pub get && cd ..
```

### 2. Configure the Reference Backend

```bash
cp example/.env.example example/.env
```

Edit `example/.env` with your merchant credentials:

| Variable | Required | Description |
| :--- | :---: | :--- |
| `PORT` | | HTTP listen port (default `7000`). |
| `PUBLIC_BASE_URL` | ✓ | Public HTTPS URL of this server. ZenPay derives `redirectUrl` and `callbackUrl` from it. Use a tunnel for local development: `cloudflared tunnel --url http://localhost:7000`. |
| `ZENPAY_HPP_ENDPOINT_URL` | ✓ | Full HCP Authorise endpoint URL (e.g. `https://pay.sandbox.travelpay.com.au/Online/v5`). |
| `ZENPAY_MERCHANT_CODE` | ✓ | Merchant code for the ZenPay account. |
| `ZENPAY_API_KEY` | ✓ | API key for the ZenPay merchant account. |
| `ZENPAY_USERNAME` | ✓ | Hashed into the SHA3-512 fingerprint; never leaves this backend. |
| `ZENPAY_PASSWORD` | ✓ | Hashed into the SHA3-512 fingerprint; never leaves this backend. |
| `MERCHANT_APP_BEARER_TOKEN` | | Bearer token the client app sends in `Authorization` headers (default `local-demo-token`). |
| `CALLBACK_TOKEN_SECRET` | | Optional HMAC secret for signed per-attempt `?t=` callback URL tokens. At least 32 bytes; blank disables the feature. Generate with `openssl rand -hex 32`. |
| `ALLOWED_APP_ORIGIN` | | Browser origin for CORS (default `http://localhost:3000`). |
| `APP_RETURN_URI_WEB` | | HTTPS URI the return broker redirects web clients to (default `https://localhost:3000/`). |
| `ZENPAY_ALLOWED_CHECKOUT_HOSTS` | | Comma-separated allowlist of checkout URL hosts (default `pay.sandbox.travelpay.com.au`). |
| `CHECKOUT_STATUS_TTL_MINUTES` | | How long to keep in-memory attempts before purging (default `60`). |

### 3. Run the Server

**Using the PowerShell script** (recommended — handles `.env` prompting, startup, health polling, and smoke test):

```pwsh
# Start server + run smoke test:
.\run.ps1

# Start server only, no smoke test:
.\run.ps1 -SkipTest

# Smoke test an already-running instance:
.\run.ps1 -TestOnly

# Start and open the checkout URL in a browser:
.\run.ps1 -OpenCheckoutUrl
```

**Or directly with Dart:**

```bash
cd example && dart run bin/server.dart
```

The server listens on `0.0.0.0:<PORT>` and shuts down cleanly on `Ctrl+C`.

---

## API Endpoints

| Method | Path | Auth | Description |
| :--- | :--- | :---: | :--- |
| `GET` | `/api/v1/health` | | Readiness probe. Reports `sessionReady` and `callbackReady` based on env configuration. |
| `POST` | `/api/v1/sessions` | Bearer | Creates a checkout session. Requires `Idempotency-Key` header (16–128 chars). Returns `merchantUniquePaymentId` and `checkoutUrl`. |
| `GET` | `/api/v1/sessions/{id}` | Bearer | Retrieves authoritative payment status for an attempt. |
| `POST` | `/api/v1/callbacks` | | ZenPay server-to-server webhook. Verifies SHA3-512 `ValidationCode` and optional callback token. |
| `GET` | `/return` | | Browser redirect broker. Validates correlation, then redirects to the merchant app (303 for mobile/web, `postMessage` for iframe/webFrame). |
| `GET` | `/.well-known/assetlinks.json` | | Android App Links verification file. |
| `GET` | `/` | | Interactive HTML test page for manual checkout flow testing. |

---

## Checkout Flow

```
┌─────────────┐         ┌────────────────┐         ┌──────────┐
│  Client App  │──POST──▶│  This Backend   │         │  ZenPay  │
│  (Flutter)   │         │  /api/v1/sessions│         │  HCP     │
└──────┬──────┘         └───────┬────────┘         └─────┬────┘
       │                        │                        │
       │   {checkoutUrl, mupid} │                        │
       │◀───────────────────────┤                        │
       │                        │                        │
       │   Open checkoutUrl     │                        │
       │───────────────────────────────────────────────▶│
       │                        │                        │
       │                        │   POST /api/v1/callbacks
       │                        │◀───────────────────────┤
       │                        │   (SHA3-512 verified)   │
       │                        │                        │
       │   GET /return          │                        │
       │───────────────────────▶│                        │
       │   303 → app return     │                        │
       │◀───────────────────────┤                        │
       │                        │                        │
       │   GET /api/v1/sessions/{mupid}                  │
       │───────────────────────▶│                        │
       │   {status: successful} │                        │
       │◀───────────────────────┤                        │
```

1. **Client creates a session** → backend builds the SHA3-512 fingerprint and constructs the launch URL locally (no outbound call to ZenPay).
2. **Client opens the checkout URL** → customer pays on ZenPay's hosted page.
3. **ZenPay calls back** → backend verifies the `ValidationCode` hash in constant time and updates the attempt.
4. **Browser returns** → backend validates correlation and redirects to the app.
5. **Client polls status** → backend returns the authoritative state from the verified callback.

---

## Security Model

- **SHA3-512 fingerprint** — every launch URL carries a per-transaction fingerprint computed from `apiKey|username|password|mode|amountCents|mupid|timestamp`. ZenPay recomputes this on receipt; a mismatch rejects the request.
- **SHA3-512 callback validation** — incoming callbacks carry a `validationCode` hash over the same fields plus the transaction reference. The SDK recomputes and compares in constant time (`constantTimeHexEqual`).
- **Timing-safe comparisons** — all cryptographic and bearer token comparisons use `HashDigest.isEqual` (constant-time) to prevent timing attacks.
- **No outbound calls at launch** — the checkout URL is constructed entirely from query parameter serialization; there is no HTTP call to ZenPay at session creation time.
- **Callback URL tokens** (optional) — an HMAC-SHA3-512 signed `?t=<token>` on the callback URL, binding it to a specific mode/mupid/timestamp/amount. Best-effort only: never gates callback acceptance.
- **No sensitive data in logs** — passwords, card numbers, CVVs, and secrets are never logged. Only correlation IDs, event types, status codes, and non-sensitive business fields appear in structured JSON logs.

---

## Development

### Verification Pipeline

Run before every commit:

```pwsh
dart format --output=none --set-exit-if-changed .
dart analyze --fatal-infos
dart test
Push-Location example
dart analyze --fatal-infos
dart test
Pop-Location
```

Or as a single command:

```pwsh
dart format --output=none --set-exit-if-changed . ; dart analyze --fatal-infos ; dart test ; Push-Location example ; dart analyze --fatal-infos ; dart test ; Pop-Location
```

### Code Quality

- **Strict analysis**: `strict-casts`, `strict-inference`, `strict-raw-types` — no untyped `dynamic`.
- **Public API docs enforced**: `public_member_api_docs: error` on the core package.
- **Dead code is an error**: unused imports, private members, and locals are compiler errors.
- **Style**: `final` locals, constructors first, `dart format` with 80-character lines.

### Testing

The core package tests cover:
- Fingerprint generation across all four modes
- Callback verification (valid, malformed, rejected) for payment, preauth, and tokenise modes
- Checkout URL construction and validation
- Callback URL token minting, verification, expiry, and tamper detection
- Dollar-to-cents conversion edge cases
- Constant-time comparison correctness

The reference backend tests cover:
- Health endpoint configuration reporting
- Session creation with idempotency enforcement
- Bearer token authentication (constant-time)
- Rate limiting (fixed window per IP)
- Callback signature verification and status mapping
- Callback conflict detection (replay with differing status)
- Return broker correlation and redirect behavior
- Frame return `postMessage` with XSS-safe escaping
- Attempt store TTL purging

---

## License

See [LICENSE](LICENSE).
