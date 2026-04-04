"""
Thread-safe progress bar for terminal output.
"""

import sys
import threading
import time


class ProgressBar:
    """Simple terminal progress bar using carriage return."""

    def __init__(self, total, width=40, enabled=True):
        self._total = total
        self._width = width
        self._enabled = enabled and hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
        self._current = 0
        self._findings = 0
        self._lock = threading.Lock()
        self._start_time = time.time()

    def update(self, findings_delta=0):
        with self._lock:
            self._current += 1
            self._findings += findings_delta
            if self._enabled:
                self._render()

    def _render(self):
        pct = self._current / max(self._total, 1)
        filled = int(self._width * pct)
        bar = "#" * filled + "-" * (self._width - filled)

        elapsed = time.time() - self._start_time
        if self._current > 0 and elapsed > 0:
            rate = self._current / elapsed
            remaining = (self._total - self._current) / rate if rate > 0 else 0
            eta = self._format_time(remaining)
        else:
            eta = "..."

        line = (
            f"\r  [{bar}] {self._current}/{self._total} "
            f"| {self._findings} finding(s) | ETA {eta}"
        )
        sys.stderr.write(line)
        sys.stderr.flush()

    def finish(self):
        if self._enabled:
            elapsed = self._format_time(time.time() - self._start_time)
            sys.stderr.write(
                f"\r  [{'#' * self._width}] {self._total}/{self._total} "
                f"| {self._findings} finding(s) | Done in {elapsed}\n"
            )
            sys.stderr.flush()

    @staticmethod
    def _format_time(seconds):
        if seconds < 60:
            return f"{int(seconds)}s"
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m{secs:02d}s"
