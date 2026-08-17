# ZenPay Dart Backend Agent Guidelines

Guidelines and standards for working within `packages/zenpay_dart` (pure Dart SDK) and the reference merchant backend (`example/`).

---

## Component Architecture Guides

Detailed source file guides with per-entity documentation:

- **[lib/CLAUDE.md](lib/CLAUDE.md)** — Core `zenpay_dart` package architecture (callback verifiers, tokens, URL builders, crypto, enums).
- **[example/CLAUDE.md](example/CLAUDE.md)** — Reference Shelf backend architecture (attempt store, config, rate limiting, routing, session service).

---

## 1. Non-Negotiable Security & Cryptographic Rules

1. **Timing-Safe Equality**:
   - All cryptographic hash (SHA3-512 `ValidationCode`), HMAC-SHA3-512 callback tokens, and bearer token comparisons **must** use timing-safe comparison methods (`constantTimeHexEqual`, `constantTimeEqual`, or constant-time digest comparison) to prevent timing attacks.
2. **Credential & Secret Protection**:
   - Never hardcode ZenPay API keys, merchant passwords, shared secrets, or live credentials.
   - Do not log sensitive fields (passwords, cardholder numbers, CVV, authentication secrets).
   - Safe to log for debugging: `merchantUniquePaymentId`, merchant codes, checkout launch URLs (without raw secrets), customer reference IDs, and callback event types.
3. **Launch URL Generation**:
   - Launch URLs must be constructed locally using query parameter serialization without making outbound network requests at launch time.
4. **Callback & State Verification**:
   - Only validated callback payloads or authenticated direct ZenPay REST status checks can confirm payment completion. Client redirects or browser dismissals are strictly provisional.

---

## 2. Dart Strictness & Code Quality

Adhere strictly to [analysis_options.yaml](file:///g:/_zp-repos/zp-flutter-sdk/backend/analysis_options.yaml):

1. **Strict Type Safety**:
   - `strict-casts: true`, `strict-inference: true`, `strict-raw-types: true`.
   - Never use untyped `dynamic` or `avoid_dynamic_calls`. Use explicit generics and model types.
2. **Public API Documentation**:
   - `public_member_api_docs: error` is enforced on the core package. Every exported class, method, enum, getter, and typedef in `lib/` must have a comprehensive doc comment explaining its parameters, return values, and failure modes.
3. **Dead Code & Unused Elements**:
   - Unused private members, unused imports, and unused local variables are compiler errors (`error`). Clean them up immediately rather than adding suppression comments.
4. **Style**:
   - Always prefer `final` locals.
   - Sort constructors first.
   - Follow standard `dart format` (80-character line width default).

---

## 3. Verification Commands

Before completing any change, ensure all checks pass cleanly across both packages:

### Root Package (`zenpay_dart`)

```pwsh
dart format --output=none --set-exit-if-changed .
dart analyze --fatal-infos
dart test
```

### Reference Backend (`example/`)

```pwsh
Push-Location example
dart analyze --fatal-infos
dart test
Pop-Location
```

### All-In-One Pipeline

```pwsh
dart format --output=none --set-exit-if-changed . ; dart analyze --fatal-infos ; dart test ; Push-Location example ; dart analyze --fatal-infos ; dart test ; Pop-Location
```
