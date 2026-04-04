"""
Core scan orchestrator — enumerates repos, coordinates plugins, manages concurrency.
"""

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
from ghscan.utils import thread_print

SAVE_EVERY = 25

SEVERITY_EMOJI = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\u26aa",
    "info": "\U0001f535",
}


def _merge_file_requests(plugins):
    """
    Gather file_requests() from all plugins, deduplicate, and return
    a set of all concrete paths to fetch.
    """
    all_paths = set()
    for plugin in plugins:
        for req in plugin.file_requests():
            all_paths.update(req.expand_paths())
    return all_paths


def _filter_paths_by_tree(paths, file_tree):
    """Remove paths that don't exist in the file tree."""
    if file_tree is None:
        return paths
    return {p for p in paths if p in file_tree}


def _build_plugin_file_view(plugin, all_files):
    """Build the file dict a plugin expects from the full fetched file set."""
    view = {}
    for req in plugin.file_requests():
        for path in req.expand_paths():
            view[path] = all_files.get(path)
    return view


def scan_repo(session, repo, rate_limiter, plugins):
    """
    Scan a single repo with all active plugins.
    Returns a RepoScanResult dict, or None if no findings.
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
        return None

    # 3. Merge and deduplicate file requests
    all_paths = _merge_file_requests(active_plugins)
    paths_to_fetch = _filter_paths_by_tree(all_paths, file_tree)

    # 4. Batch fetch all unique files
    all_files = {}
    for path in paths_to_fetch:
        all_files[path] = fetch_file(session, full_name, path, rate_limiter)

    # 5. Distribute to plugins and collect findings
    all_findings = []
    for plugin in active_plugins:
        file_view = _build_plugin_file_view(plugin, all_files)
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
            meta = plugin.metadata()
            thread_print(
                f"  [ERROR] Plugin {meta.name} failed on {full_name}: {e}", flush=True)

    if not all_findings:
        return None

    result = RepoScanResult(
        repo=full_name,
        repo_id=repo_id,
        url=html_url,
        default_branch=default_branch,
        pushed_at=pushed_at,
        findings=all_findings,
    )
    return result.to_dict()


def scan_org(org, token, output_path, plugins, max_workers=5, verbose=False):
    """
    Scan all repos in the org using a thread pool.
    Rate limiting is shared across all workers.
    """
    session = make_session(token)
    rate_limiter = RateLimiter(max_per_second=max_workers * 2)
    repos = list_all_repos(session, org, rate_limiter)
    total = len(repos)

    scanned_names, findings = load_progress(output_path)
    checkpoint_lock = get_checkpoint_lock()

    thread_local = threading.local()

    def get_thread_session():
        if not hasattr(thread_local, "session"):
            thread_local.session = make_session(token)
        return thread_local.session

    def scan_one(idx_repo):
        idx, repo = idx_repo
        name = repo["full_name"]

        if name in scanned_names:
            if verbose:
                thread_print(
                    f"  [{idx:4d}/{total}] {name}  [skipped -- already scanned]",
                    flush=True)
            return name, None

        thread_print(f"  [{idx:4d}/{total}] {name}", end="  ", flush=True)

        sess = get_thread_session()
        result = scan_repo(sess, repo, rate_limiter, plugins)

        if result:
            max_sev = result.get("max_severity", "info")
            emoji = SEVERITY_EMOJI.get(max_sev, "")
            n_findings = len(result.get("findings", []))
            thread_print(f"{emoji} {max_sev.upper()} ({n_findings} finding(s))", flush=True)
        else:
            thread_print("--  clean", flush=True)

        return name, result

    thread_print(f"[*] Scanning {total} repos ({max_workers} workers)...\n", flush=True)

    completed = 0
    work_items = [(i, repo) for i, repo in enumerate(repos, 1)]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_item = {
            executor.submit(scan_one, item): item for item in work_items
        }

        for future in as_completed(future_to_item):
            try:
                name, result = future.result()
            except Exception as e:
                item = future_to_item[future]
                name = item[1]["full_name"]
                thread_print(f"\n  [ERROR] Exception scanning {name}: {e}", flush=True)
                result = None

            with checkpoint_lock:
                scanned_names.add(name)
                if result:
                    findings.append(result)
                completed += 1

            if completed % SAVE_EVERY == 0:
                save_progress(output_path, scanned_names, findings)
                thread_print(
                    f"\n  [CHECKPOINT] Saved ({completed}/{total} repos scanned)\n",
                    flush=True)

    save_progress(output_path, scanned_names, findings)
    return findings
