---
name: zenpay-verify
description: >-
  Runs static analysis, code formatting checks, and the full test suite across
  the ZenPay Dart library and the example reference backend.
---

# ZenPay Backend Verification Skill

Run the full verification suite across the `zenpay_dart` core library and the
`example/` reference Shelf backend. Every step must exit zero.

---

## 1. Root Package (`zenpay_dart`)

Run from the repository root (`g:\_zp-repos\zp-flutter-sdk\backend`):

### A. Format Check

```pwsh
dart format --output=none --set-exit-if-changed .
```

### B. Static Analysis

```pwsh
dart analyze --fatal-infos
```

### C. Run Tests

```pwsh
dart test
```

---

## 2. Reference Backend (`example/`)

### A. Static Analysis

```pwsh
Push-Location example; dart analyze --fatal-infos; Pop-Location
```

### B. Run Tests

```pwsh
Push-Location example; dart test; Pop-Location
```

---

## 3. All-In-One Pipeline

```pwsh
dart format --output=none --set-exit-if-changed . ; dart analyze --fatal-infos ; dart test ; Push-Location example ; dart analyze --fatal-infos ; dart test ; Pop-Location
```
