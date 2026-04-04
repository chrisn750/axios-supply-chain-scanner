"""
GitHub API client — session management, rate-limit-aware requests, file fetching.
"""

import base64
import time
from urllib.parse import quote

import requests

from ghscan.utils import thread_print, sleep_with_progress

GITHUB_API = "https://api.github.com"
PER_PAGE = 100


def make_session(token):
    """Create a requests.Session with GitHub API auth headers."""
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    return s


def safe_get(session, url, params, rate_limiter):
    """GET with automatic rate-limit back-off, retry, and progress display."""
    for attempt in range(4):
        rate_limiter.acquire()
        try:
            resp = session.get(url, params=params, timeout=20)
        except requests.RequestException as e:
            thread_print(f"\n  [NETWORK ERROR] {e} — retrying in 10s", flush=True)
            sleep_with_progress(10, reason="network error")
            continue

        remaining = int(resp.headers.get("X-RateLimit-Remaining", 999))

        if remaining < 10:
            reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(reset_ts - int(time.time()), 5)
            thread_print(f"\n  [RATE LIMIT] {remaining} requests remaining", flush=True)
            sleep_with_progress(wait, reason="GitHub rate limit reset")

        if resp.status_code == 200:
            return resp

        if resp.status_code == 404:
            return resp

        if resp.status_code in (403, 429):
            body = {}
            try:
                if resp.headers.get("content-type", "").startswith("application/json"):
                    body = resp.json()
            except Exception:
                pass
            msg = body.get("message", "")

            is_rate_limit = (
                resp.status_code == 429
                or "rate limit" in msg.lower()
                or "abuse" in msg.lower()
                or "secondary" in msg.lower()
            )

            if is_rate_limit:
                reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset_ts - int(time.time()), 30 * (attempt + 1))
                thread_print(f"\n  [RATE LIMITED] Waiting {wait}s (attempt {attempt+1}/4)",
                             flush=True)
                sleep_with_progress(wait, reason="rate limit reset")
                continue
            else:
                thread_print(f"\n  [HTTP 403] Access denied: {msg}", flush=True)
                return resp

        if resp.status_code in (500, 502, 503):
            wait = 30 * (attempt + 1)
            thread_print(f"\n  [HTTP {resp.status_code}] Server error", flush=True)
            sleep_with_progress(wait, reason=f"HTTP {resp.status_code} back-off")
            continue

        if resp.status_code == 409:
            return None  # empty repo

        thread_print(f"\n  [HTTP {resp.status_code}] Unexpected status for {url}", flush=True)
        return None

    thread_print(f"\n  [EXHAUSTED] Gave up after 4 attempts for {url}", flush=True)
    return None


def fetch_file(session, repo_full_name, path, rate_limiter):
    """Fetch and decode a file from the repo default branch. Returns text or None."""
    url = f"{GITHUB_API}/repos/{repo_full_name}/contents/{quote(path)}"
    resp = safe_get(session, url, {}, rate_limiter)
    if resp is None:
        thread_print(f"  [WARN] Failed to fetch {path} from {repo_full_name} "
                     f"(retries exhausted)", flush=True)
        return None
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        thread_print(f"  [WARN] Unexpected HTTP {resp.status_code} fetching {path} "
                     f"from {repo_full_name}", flush=True)
        return None
    data = resp.json()
    if isinstance(data, list):  # path is a directory
        return None
    raw = data.get("content", "")
    if data.get("encoding") == "base64":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return None
    return raw


def get_repo_tree(session, repo_full_name, default_branch, rate_limiter):
    """
    Fetch the full recursive file tree in a single API call.
    Returns a set of file paths, or None if the tree is truncated or
    the request fails (caller should fall back to per-file approach).
    """
    url = f"{GITHUB_API}/repos/{repo_full_name}/git/trees/{default_branch}"
    resp = safe_get(session, url, {"recursive": "1"}, rate_limiter)
    if resp is None or resp.status_code != 200:
        return None
    data = resp.json()
    if data.get("truncated"):
        return None
    return {item["path"] for item in data.get("tree", []) if item["type"] == "blob"}


def list_all_repos(session, org, rate_limiter):
    """Return all non-archived repos in org, paginated."""
    repos = []
    page = 1
    thread_print(f"[*] Enumerating repos in {org} (excluding archived)...", flush=True)
    while True:
        resp = safe_get(session, f"{GITHUB_API}/orgs/{org}/repos",
                        {"per_page": PER_PAGE, "page": page, "type": "all"}, rate_limiter)
        if resp is None or resp.status_code != 200:
            thread_print(
                f"\n  [ERROR] Failed to fetch repo list "
                f"(HTTP {getattr(resp, 'status_code', '?')})", flush=True)
            break
        batch = resp.json()
        if not batch:
            break
        active = [r for r in batch if not r.get("archived", False)]
        skipped = len(batch) - len(active)
        repos.extend(active)
        thread_print(
            f"  Page {page}: {len(batch)} fetched, {skipped} archived skipped "
            f"(running total: {len(repos)})", flush=True)
        if len(batch) < PER_PAGE:
            break
        page += 1
    thread_print(f"  -> {len(repos)} active repos\n", flush=True)
    return repos


def validate_token(token):
    """
    Validate a GitHub token by calling GET /user.
    Returns (success, username, rate_limit) or (False, error_msg, None).
    """
    session = make_session(token)
    try:
        resp = session.get(f"{GITHUB_API}/user", timeout=10)
    except requests.RequestException as e:
        return False, str(e), None

    if resp.status_code != 200:
        return False, f"HTTP {resp.status_code}", None

    user_data = resp.json()
    username = user_data.get("login", "unknown")
    rate_limit = int(resp.headers.get("X-RateLimit-Limit", 0))
    return True, username, rate_limit
