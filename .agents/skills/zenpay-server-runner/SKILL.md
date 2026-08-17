---
name: zenpay-server-runner
description: >-
  Guides launching, configuring, and smoke-testing the ZenPay reference backend
  Shelf server and testing checkout session endpoints and callbacks.
---

# ZenPay Reference Server Runner Skill

Covers starting the Shelf-based reference merchant backend in `example/`,
managing `.env` configuration, and running the HTTP smoke-test flow.

---

## 1. Environment Configuration

The server reads its configuration from `example/.env`. If the file does not
exist, copy the annotated template:

```pwsh
Copy-Item example/.env.example example/.env
```

Key variables (see [.env.example](file:///g:/_zp-repos/zp-flutter-sdk/backend/example/.env.example)
for complete documentation):

| Variable | Purpose |
| :--- | :--- |
| `PORT` | HTTP listen port (default `7000`). |
| `PUBLIC_BASE_URL` | Public HTTPS URL of this server. ZenPay derives `redirectUrl` and `callbackUrl` from it. Use a tunnel (`cloudflared tunnel --url http://localhost:7000`) for live callback testing. |
| `ZENPAY_HPP_ENDPOINT_URL` | Full HCP Authorise endpoint URL (e.g. `https://pay.sandbox.travelpay.com.au/Online/v5`). |
| `ZENPAY_MERCHANT_CODE` | Merchant code for the ZenPay account. |
| `ZENPAY_API_KEY` | API key for the ZenPay merchant account. |
| `ZENPAY_USERNAME` | Hashed into the SHA3-512 fingerprint; never leaves this backend. |
| `ZENPAY_PASSWORD` | Hashed into the SHA3-512 fingerprint; never leaves this backend. |
| `MERCHANT_APP_BEARER_TOKEN` | Bearer token the Flutter app sends in `Authorization` headers. |
| `CALLBACK_TOKEN_SECRET` | Optional HMAC secret for per-attempt `?t=` callback URL tokens. At least 32 bytes; blank disables the feature. |

---

## 2. Running the Server

### Option A: Automated Script (`run.ps1`)

The PowerShell script manages `.env` prompting, server lifecycle, health
polling, and an optional checkout session smoke test.

```pwsh
# Start server + run smoke test (creates session, polls status):
.\run.ps1

# Start server only, no smoke test:
.\run.ps1 -SkipTest

# Smoke test an already-running instance:
.\run.ps1 -TestOnly

# Start and open the checkout URL in a browser:
.\run.ps1 -OpenCheckoutUrl
```

### Option B: Direct Dart Launch

```pwsh
Push-Location example; dart run bin/server.dart; Pop-Location
```

The server listens on `InternetAddress.anyIPv4` at the configured `PORT`,
logs a `server_started` event, and shuts down cleanly on `Ctrl+C` (SIGINT).

---

## 3. Server Endpoints

Defined in [openapi.yaml](file:///g:/_zp-repos/zp-flutter-sdk/backend/example/openapi.yaml):

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Readiness check. Reports `sessionReady` and `callbackReady` flags based on env configuration. |
| `POST` | `/api/v1/sessions` | Creates a checkout session. Requires `Authorization: Bearer <token>` and `Idempotency-Key` header. Returns `checkoutUrl` and `merchantUniquePaymentId`. |
| `GET` | `/api/v1/sessions/{merchantUniquePaymentId}` | Retrieves authoritative payment state for an attempt. |
| `POST` | `/api/v1/callbacks` | Receives ZenPay server-to-server callbacks. Verifies HMAC-SHA3-512 `ValidationCode` and optional callback token. |
| `GET` | `/return` | Browser redirect broker. Validates correlation, then redirects to the merchant app (303 for mobile, HTML `postMessage` for iframe/web). |
| `GET` | `/.well-known/assetlinks.json` | Android App Links verification file. |
