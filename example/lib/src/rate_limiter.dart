/// Fixed-window request rate limiter for API protection.
///
/// Implements an in-memory sliding fixed-window algorithm keyed by client
/// identifier (typically remote IP address). Used to guard merchant API endpoints
/// and webhook callback receivers against abuse, denial-of-service, and brute-force traffic.
library;

class _RateLimitWindow {
  _RateLimitWindow(this.count, this.resetsAt);

  int count;
  DateTime resetsAt;
}

/// A fixed-window request-rate limiter, keyed by an arbitrary string
/// (typically client IP address).
///
/// Maintains separate window counters per key. Requests arriving after a key's
/// window expiration automatically reset the counter for a new period.
class FixedWindowRateLimiter {
  FixedWindowRateLimiter(this.limit, this.window);

  final int limit;
  final Duration window;
  final _entries = <String, _RateLimitWindow>{};

  /// Evaluates whether a request associated with [key] is permitted at timestamp [now].
  ///
  /// Increments the request counter if under the threshold and returns `true`.
  /// Returns `false` if the request quota for the current window has been exhausted.
  ///
  /// The optional [now] parameter defaults to [DateTime.now] and is available for
  /// deterministic unit testing of window rollover behavior.
  bool allow(String key, [DateTime? now]) {
    final time = now ?? DateTime.now();
    final current = _entries[key];
    if (current == null || !current.resetsAt.isAfter(time)) {
      _entries[key] = _RateLimitWindow(1, time.add(window));
      return true;
    }
    if (current.count >= limit) return false;
    current.count += 1;
    return true;
  }
}
