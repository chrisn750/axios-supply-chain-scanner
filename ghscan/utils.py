"""
Shared utility functions for ghscan.
"""

import threading
import time

_print_lock = threading.Lock()


def thread_print(*args, **kwargs):
    """Thread-safe print wrapper."""
    with _print_lock:
        print(*args, **kwargs)


def sleep_with_progress(seconds, reason="", update_interval=15):
    """
    Sleep for ``seconds``, printing a countdown line every ``update_interval``
    seconds so long-running waits are visible in the terminal.
    """
    if seconds <= 0:
        return

    end_time = time.time() + seconds
    label = f" ({reason})" if reason else ""

    thread_print(f"\n  [SLEEPING] {seconds}s{label}", flush=True)

    while True:
        remaining = end_time - time.time()
        if remaining <= 0:
            break

        sleep_chunk = min(update_interval, remaining)
        time.sleep(sleep_chunk)

        remaining = end_time - time.time()
        if remaining > 1:
            thread_print(f"  [SLEEPING] {int(remaining)}s remaining...", flush=True)

    thread_print(f"  [RESUMING]\n", flush=True)
