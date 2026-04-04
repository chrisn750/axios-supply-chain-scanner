"""
Atomic checkpoint save/load/clear for scan resumption.
"""

import json
import os
import tempfile
import threading

from ghscan.utils import thread_print

_checkpoint_lock = threading.Lock()


def progress_path(output_path):
    base, _ = os.path.splitext(output_path)
    return base + ".progress.json"


def load_progress(output_path):
    """Load checkpoint data. Returns (scanned_repo_names_set, findings_list)."""
    pp = progress_path(output_path)
    if not os.path.exists(pp):
        return set(), []
    try:
        with open(pp) as f:
            data = json.load(f)
        scanned = set(data.get("scanned_repos", []))
        findings = data.get("findings", [])
        thread_print(
            f"[RESUME] Checkpoint found: {len(scanned)} repos already scanned, "
            f"{len(findings)} finding(s) so far.\n", flush=True)
        return scanned, findings
    except Exception as e:
        thread_print(f"[WARN] Could not load progress file: {e}", flush=True)
        return set(), []


def save_progress(output_path, scanned_repos, findings):
    """Atomic checkpoint write: write to temp file, then os.replace()."""
    pp = progress_path(output_path)
    with _checkpoint_lock:
        tmp_path = None
        try:
            dir_name = os.path.dirname(os.path.abspath(pp))
            with tempfile.NamedTemporaryFile(
                mode="w", dir=dir_name, suffix=".tmp", delete=False
            ) as tf:
                json.dump({
                    "scanned_repos": list(scanned_repos),
                    "findings": findings,
                }, tf)
                tf.flush()
                os.fsync(tf.fileno())
                tmp_path = tf.name
            os.replace(tmp_path, pp)
        except Exception as e:
            thread_print(f"\n  [WARN] Could not save checkpoint: {e}", flush=True)
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass


def clear_progress(output_path):
    pp = progress_path(output_path)
    if os.path.exists(pp):
        os.remove(pp)


def get_checkpoint_lock():
    """Return the module-level checkpoint lock for thread-safe findings updates."""
    return _checkpoint_lock
