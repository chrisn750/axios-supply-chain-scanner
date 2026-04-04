"""
Thread-safe rate limiter for GitHub API requests.
"""

import threading
import time


class RateLimiter:
    """
    Enforces a max-requests-per-second ceiling shared across all threads.
    """
    def __init__(self, max_per_second=10):
        self._lock = threading.Lock()
        self._min_interval = 1.0 / max_per_second
        self._last_call = 0.0

    def acquire(self):
        with self._lock:
            now = time.time()
            wait = self._min_interval - (now - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.time()
