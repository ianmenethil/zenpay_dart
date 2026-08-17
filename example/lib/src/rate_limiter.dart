/// Fixed-window request rate limiter.
library;

class _RateLimitWindow {
  _RateLimitWindow(this.count, this.resetsAt);
  int count;
  DateTime resetsAt;
}

/// A fixed-window request-rate limiter, keyed by an arbitrary string
/// (typically client IP).
class FixedWindowRateLimiter {
  FixedWindowRateLimiter(this.limit, this.window);

  final int limit;
  final Duration window;
  final _entries = <String, _RateLimitWindow>{};

  /// Returns whether a request under [key] is allowed at [now].
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
