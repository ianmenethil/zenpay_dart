/// HTML page templates served by the reference backend.
///
/// Contains the response generators for:
/// - The iframe return landing page (`frameReturnPageHtml`), which securely
///   communicates payment completion data back to the hosting merchant web
///   app using `window.parent.postMessage` against a strictly validated target origin.
/// - The manual test bench page (`testPageHtml`) served at `GET /`, enabling
///   interactive verification of the end-to-end checkout flow in a web browser.
library;

import 'dart:convert';

import 'config.dart';

/// Generates an HTML response page that transmits the checkout result to the parent frame.
///
/// Uses `window.parent.postMessage` with the provided [targetOrigin] (never `'*'`)
/// to prevent cross-origin message interception. The [attempt] identifier is encoded
/// in JSON with `<` characters escaped to mitigate HTML/script injection risks.
String frameReturnPageHtml(String targetOrigin, String attempt) {
  final payload = jsonEncode({
    'merchantUniquePaymentId': attempt,
  }).replaceAll('<', '\\u003c');
  final origin = jsonEncode(targetOrigin).replaceAll('<', '\\u003c');
  return '<!doctype html>\n'
      '<meta charset="utf-8">\n'
      '<title>Returning to app</title>\n'
      '<script>\n'
      '  parent.postMessage($payload, $origin);\n'
      '</script>';
}

/// Generates the interactive HTML/JS testing interface served at `GET /`.
///
/// Provides a developer web interface for testing the full payment lifecycle:
/// creating sessions with [config], launching checkout windows, and polling
/// payment status until a terminal state is reached.
String testPageHtml(AppConfig config) {
  final tokenJson = jsonEncode(
    config.merchantAppBearerToken,
  ).replaceAll('<', '\\u003c');
  return '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ZenPay Reference Backend Test</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --error: #ef4444;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 2rem 1rem;
      display: flex;
      justify-content: center;
    }
    .container {
      max-width: 640px;
      width: 100%;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2rem;
      box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3);
    }
    h1 { font-size: 1.5rem; margin-top: 0; margin-bottom: 0.5rem; }
    p.subtitle { color: var(--text-muted); font-size: 0.9rem; margin-top: 0; margin-bottom: 1.5rem; }
    .btn {
      background: var(--primary);
      color: white;
      border: none;
      padding: 0.75rem 1.5rem;
      font-size: 1rem;
      font-weight: 600;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.2s;
      width: 100%;
    }
    .btn:hover { background: var(--primary-hover); }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .status-panel {
      margin-top: 1.5rem;
      padding: 1rem;
      border-radius: 8px;
      background: var(--bg);
      border: 1px solid var(--border);
      display: none;
    }
    .status-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
    .status-row:last-child { margin-bottom: 0; }
    .label { color: var(--text-muted); font-size: 0.85rem; }
    .value { font-weight: 600; font-size: 0.95rem; font-family: monospace; }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.65rem;
      border-radius: 9999px;
      font-size: 0.8rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-sessionCreated { background: rgba(59, 130, 246, 0.2); color: #60a5fa; }
    .badge-browserReturned { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
    .badge-successful { background: rgba(34, 197, 94, 0.2); color: #4ade80; }
    .badge-failed, .badge-cancelled, .badge-error { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .error-box {
      margin-top: 1.5rem;
      padding: 1rem;
      border-radius: 8px;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid var(--error);
      color: #fca5a5;
      font-family: monospace;
      font-size: 0.9rem;
      display: none;
      word-break: break-all;
    }
    .info-box { margin-top: 1rem; font-size: 0.8rem; color: var(--text-muted); line-height: 1.4; }
  </style>
</head>
<body>
  <div class="container">
    <h1>ZenPay Reference Backend Test</h1>
    <p class="subtitle">Create a checkout session and test the payment flow in browser.</p>

    <button id="create-btn" class="btn" onclick="createCheckout()">Create Test Checkout</button>

    <div id="error-box" class="error-box"></div>

    <div id="status-panel" class="status-panel">
      <div class="status-row">
        <span class="label">Status</span>
        <span id="status-badge" class="badge"></span>
      </div>
      <div class="status-row">
        <span class="label">Payment ID</span>
        <span id="mupid-val" class="value"></span>
      </div>
      <div class="status-row">
        <span class="label">Poll Count</span>
        <span id="poll-val" class="value">0 / 40</span>
      </div>
    </div>

    <div class="info-box">
      Note: Local development bearer token embedded in test page JS.
    </div>
  </div>

  <script>
    const BEARER_TOKEN = $tokenJson;
    let pollInterval = null;
    let pollCount = 0;

    async function createCheckout() {
      const btn = document.getElementById('create-btn');
      const errBox = document.getElementById('error-box');
      const panel = document.getElementById('status-panel');
      const mupidVal = document.getElementById('mupid-val');

      errBox.style.display = 'none';
      panel.style.display = 'none';
      btn.disabled = true;

      if (pollInterval) clearInterval(pollInterval);
      pollCount = 0;

      const idempotencyKey = 'test-' + Date.now();
      const orderId = 'ord-' + Date.now();

      try {
        const response = await fetch('/api/v1/sessions', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + BEARER_TOKEN,
            'Idempotency-Key': idempotencyKey,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            orderId: orderId,
            customerName: 'Test Customer',
            customerEmail: 'test@example.com',
            client: 'web',
            paymentAmount: 10.00
          })
        });

        const data = await response.json().catch(() => ({ error: 'NON_JSON_RESPONSE' }));

        if (!response.ok) {
          errBox.textContent = 'Error (' + response.status + '): ' + (data.error || JSON.stringify(data));
          errBox.style.display = 'block';
          btn.disabled = false;
          return;
        }

        window.open(data.checkoutUrl, '_blank');

        panel.style.display = 'block';
        mupidVal.textContent = data.merchantUniquePaymentId;
        updateBadge('sessionCreated');

        pollStatus(data.merchantUniquePaymentId);
        pollInterval = setInterval(() => pollStatus(data.merchantUniquePaymentId), 3000);

      } catch (err) {
        errBox.textContent = 'Network / Request Error: ' + err.message;
        errBox.style.display = 'block';
      } finally {
        btn.disabled = false;
      }
    }

    function updateBadge(status) {
      const badge = document.getElementById('status-badge');
      badge.textContent = status;
      badge.className = 'badge badge-' + status;
    }

    async function pollStatus(mupid) {
      pollCount++;
      document.getElementById('poll-val').textContent = pollCount + ' / 40';

      try {
        const response = await fetch('/api/v1/sessions/' + encodeURIComponent(mupid), {
          headers: {
            'Authorization': 'Bearer ' + BEARER_TOKEN
          }
        });
        if (response.ok) {
          const data = await response.json();
          updateBadge(data.status);

          const terminal = ['successful', 'failed', 'cancelled', 'error'];
          if (terminal.includes(data.status) || pollCount >= 40) {
            clearInterval(pollInterval);
            pollInterval = null;
          }
        }
      } catch (e) {
        // Ignore transient poll errors
      }
    }
  </script>
</body>
</html>''';
}
