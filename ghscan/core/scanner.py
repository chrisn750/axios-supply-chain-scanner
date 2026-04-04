"""
Core scan orchestrator — enumerates repos, coordinates plugins, manages concurrency.
"""

import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from ghscan.core.github_client import (
    make_session, fetch_file, get_repo_tree, list_all_repos,
)
from ghscan.core.rate_limiter import RateLimiter
from ghscan.core.checkpoint import (
    load_progress, save_progress, get_checkpoint_lock,
)
from ghscan.core.results import RepoScanResult
from ghscan.cli.progress import ProgressBar
from ghscan.utils import thread_print

SAVE_EVERY = 25

SEVERITY_EMOJI = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\u26aa",
    "info": "\U0001f535",
}


def _build_expanded_paths_cache(plugins):
    """
    Build a cache of expanded paths per plugin, plus the deduplicated union.
    Returns (all_paths_set, {plugin_id: set_of_paths}).
    """
    all_paths = set()
    per_plugin = {}
    for plugin in plugins:
        paths = set()
        for req in plugin.file_requests():
            paths.update(req.expand_paths())
        per_plugin[id(plugin)] = paths
        all_paths.update(paths)
    return all_paths, per_plugin


def _filter_paths_by_tree(paths, file_tree):
    """Remove paths that don't exist in the file tree."""
    if file_tree is None:
        return paths
    return paths & file_tree


def scan_repo(session, repo, rate_limiter, plugins):
    """
    Scan a single repo with all active plugins.
    Returns (result_dict_or_none, had_plugin_errors).
    """
    full_name = repo["full_name"]
    repo_id = repo.get("id")
    default_branch = repo.get("default_branch", "main")
    html_url = repo["html_url"]
    pushed_at = repo.get("pushed_at", "")

    # 1. Fetch file tree (one API call)
    file_tree = get_repo_tree(session, full_name, default_branch, rate_limiter)

    # 2. Plugin pre-filtering
    active_plugins = []
    for plugin in plugins:
        if plugin.should_scan_repo(repo, file_tree):
            active_plugins.append(plugin)

    if not active_plugins:
        return None, False

    # 3. Merge and deduplicate file requests (cached per call)
    all_paths, per_plugin_paths = _build_expanded_paths_cache(active_plugins)
    paths_to_fetch = _filter_paths_by_tree(all_paths, file_tree)

    # 4. Batch fetch all unique files
    all_files = {}
    for path in paths_to_fetch:
        all_files[path] = fetch_file(session, full_name, path, rate_limiter)

    # 5. Distribute to plugins and collect findings
    all_findings = []
    had_errors = False
    for plugin in active_plugins:
        # Build view from cached paths — no re-expansion needed
        plugin_paths = per_plugin_paths[id(plugin)]
        file_view = {p: all_files.get(p) for p in plugin_paths}
        try:
            findings = plugin.evaluate(repo, file_view, file_tree)
            for finding in findings:
                all_findings.append({
                    "plugin_name": finding.plugin_name,
                    "severity": finding.severity,
                    "title": finding.title,
                    "score": finding.score,
                    "details": finding.details,
                    "recommendations": finding.recommendations,
                })
        except Exception as e:
            had_errors = True
            meta = plugin.metadata()
            thread_print(
                f"  [ERROR] Plugin {meta.name} failed on {full_name}: {e}", flush=True)

    # Free file contents now that all plugins have evaluated
    all_files.clear()

    if not all_findings:
        return None, had_errors

    result = RepoScanResult(
        repo=full_name,
        repo_id=repo_id,
        url=html_url,
        default_branch=default_branch,
        pushed_at=pushed_at,
        findings=all_findings,
    )
    return result.to_dict(), had_errors


def scan_org(org, token, output_path, plugins, max_workers=5,
             verbose=False, quiet=False):
    """
    Scan all repos in the org using a thread pool.
    Rate limiting is shared across all workers.
    """
    session = make_session(token)
    rate_limiter = RateLimiter(max_per_second=max_workers * 2)
    repos = list_all_repos(session, org, rate_limiter)
    total = len(repos)

    if total == 0:
        thread_print("[*] No repositories found to scan.", flush=True)
        return []

    scanned_names, findings = load_progress(output_path)
    checkpoint_lock = get_checkpoint_lock()

    progress_bar = ProgressBar(total, enabled=not quiet)

    # Graceful shutdown: on Ctrl+C, cancel pending futures and save checkpoint
    shutdown_event = threading.Event()

    original_sigint = signal.getsignal(signal.SIGINT)

    def _handle_sigint(signum, frame):
        if shutdown_event.is_set():
            # Second Ctrl+C — force exit
            signal.signal(signal.SIGINT, original_sigint)
            raise KeyboardInterrupt
        shutdown_event.set()
        thread_print(
            "\n  [INTERRUPT] Shutting down gracefully... "
            "(press Ctrl+C again to force quit)", flush=True)

    signal.signal(signal.SIGINT, _handle_sigint)

    thread_local = threading.local()

    def get_thread_session():
        if not hasattr(thread_local, "session"):
            thread_local.session = make_session(token)
        return thread_local.session

    def scan_one(idx_repo):
        idx, repo = idx_repo
        name = repo["full_name"]

        # Check shutdown before starting work
        if shutdown_event.is_set():
            return name, None, False, True  # skipped due to shutdown

        # Check if already scanned — under lock to prevent duplicate work
        with checkpoint_lock:
            if name in scanned_names:
                if verbose and not quiet:
                    thread_print(
                        f"  [{idx:4d}/{total}] {name}  [skipped -- already scanned]",
                        flush=True)
                return name, None, False, True  # already_handled=True

        if not quiet:
            thread_print(f"  [{idx:4d}/{total}] {name}", end="  ", flush=True)

        sess = get_thread_session()
        result, had_errors = scan_repo(sess, repo, rate_limiter, plugins)

        if not quiet:
            if result:
                max_sev = result.get("max_severity", "info")
                emoji = SEVERITY_EMOJI.get(max_sev, "")
                n_findings = len(result.get("findings", []))
                thread_print(
                    f"{emoji} {max_sev.upper()} ({n_findings} finding(s))", flush=True)
            else:
                thread_print("--  clean", flush=True)

        return name, result, had_errors, False

    if not quiet:
        thread_print(
            f"[*] Scanning {total} repos ({max_workers} workers)...\n", flush=True)

    completed = 0
    work_items = [(i, repo) for i, repo in enumerate(repos, 1)]

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_item = {
                executor.submit(scan_one, item): item for item in work_items
            }

            for future in as_completed(future_to_item):
                try:
                    name, result, had_errors, already_handled = future.result()
                except Exception as e:
                    item = future_to_item[future]
                    name = item[1]["full_name"]
                    thread_print(
                        f"\n  [ERROR] Exception scanning {name}: {e}", flush=True)
                    result = None
                    had_errors = True
                    already_handled = False

                if already_handled:
                    # Already in scanned_names (resume) or shutdown skip
                    completed += 1
                    progress_bar.update(0)
                    continue

                with checkpoint_lock:
                    # Only mark as scanned if no plugin errors occurred.
                    # This way on resume the repo will be re-scanned.
                    if not had_errors:
                        scanned_names.add(name)
                    if result:
                        findings.append(result)
                    completed += 1

                findings_delta = len(result.get("findings", [])) if result else 0
                progress_bar.update(findings_delta)

                if completed % SAVE_EVERY == 0:
                    save_progress(output_path, scanned_names, findings)
                    if not quiet:
                        thread_print(
                            f"\n  [CHECKPOINT] Saved "
                            f"({completed}/{total} repos scanned)\n",
                            flush=True)

                if shutdown_event.is_set():
                    # Cancel remaining futures
                    for f in future_to_item:
                        f.cancel()
                    break

    finally:
        # Always save progress on exit (normal, Ctrl+C, or exception)
        progress_bar.finish()
        save_progress(output_path, scanned_names, findings)
        signal.signal(signal.SIGINT, original_sigint)

    if shutdown_event.is_set():
        thread_print(
            f"\n  [INTERRUPTED] Checkpoint saved. "
            f"Rerun the same command to resume.\n", flush=True)

    return findings
