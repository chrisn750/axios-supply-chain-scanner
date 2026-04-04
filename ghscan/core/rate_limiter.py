"""
Thread-safe rate limiter for GitHub API requests.
"""

import threading
import time


class RateLimiter:
    """
    Enforces a max-requests-per-second ceiling shared across all threads.
    Uses a compute-then-sleep pattern that doesn't hold the lock while sleeping.
    """
    def __init__(self, max_per_second=10):
        self._lock = threading.Lock()
        self._min_interval = 1.0 / max_per_second
        self._next_allowed = 0.0

    def acquire(self):
        with self._lock:
            now = time.time()
            wait = self._next_allowed - now
            # Reserve our slot immediately so other threads schedule after us
            self._next_allowed = max(now, self._next_allowed) + self._min_interval

        # Sleep outside the lock so other threads can compute their wait times
        if wait > 0:
            time.sleep(wait)
