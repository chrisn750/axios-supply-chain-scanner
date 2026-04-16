#!/usr/bin/env python3
"""
axios Supply Chain Exposure Scanner
====================================
Vulnerability: axios@1.14.1 and axios@0.30.4 (published March 31, 2026)
Attribution:   UNC1069 (North Korea-nexus, Google GTIG)

PURPOSE
-------
This tool is an IR triage aid, not a compromise detector.

The malicious axios versions were resolved during CI/CD builds and
self-destructed afterward — scanning source code for confirmed IOCs
will largely come up empty. Instead, this script identifies repos
whose dependency configuration could have caused CI to resolve the
malicious versions during the ~3hr attack window, so analysts know
which build logs to pull and review.

A clean result does NOT mean a repo was unaffected. Build log review
is the only definitive clearance method.

SCORING MODEL (0-100)
---------------------
  Axios range risk      0-40  (how likely the spec resolves to bad version)
  Lockfile factor       0-30  (no lockfile = guaranteed fresh resolution)
  CI/CD detected        0-20  (pipeline config found in repo)
  Repo activity         0-10  (was anyone building around March 31?)

TIERS
-----
  CRITICAL  75-100   High confidence CI ran and resolved bad version
  HIGH      50-74    Meaningful exposure — prioritize log review
  MEDIUM    25-49    Possible exposure — review after higher tiers
  LOW        0-24    Unlikely affected — deprioritize

RESUME
------
Progress is checkpointed every 25 repos to <output>.progress.json.
Rerun the same command to resume. Deleted automatically on completion.

CONCURRENCY
-----------
Use --workers to control parallelism (default: 5, max: 15).
Rate limiting is shared across all workers to stay under GitHub's
5,000 requests/hour budget.

Usage:
  export GITHUB_TOKEN=ghp_your_token
  python3 axios-supply-chain-scanner.py --org <org> [OPTIONS]

Requirements:
  pip install requests
  pip install pyyaml   (optional — improves pnpm-lock.yaml parsing)
"""

import argparse
import base64
import json
import os
import re
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

try:
    import requests
except ImportError:
    print("[ERROR] Missing dependency — run: pip install requests")
    sys.exit(1)

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_API = "https://api.github.com"
PER_PAGE   = 100
SAVE_EVERY = 25

ATTACK_WINDOW_START = datetime(2026, 3, 31,  0, 21, tzinfo=timezone.utc)
ATTACK_WINDOW_END   = datetime(2026, 3, 31,  3, 30, tzinfo=timezone.utc)

BAD_VERSIONS = {"1.14.1", "0.30.4"}

# Adjacent safe versions — lockfile pinned here is only safe if CI used `npm ci`
SAFE_ADJACENT_VERSIONS = {"1.14.0", "0.30.3"}

CI_CONFIG_PATHS = [
    ".github/workflows",        # GitHub Actions (directory)
    "Jenkinsfile",
    ".travis.yml",
    ".circleci/config.yml",
    "azure-pipelines.yml",
    ".gitlab-ci.yml",
    "bitbucket-pipelines.yml",
    "Dockerfile",
    "docker-compose.yml",
]

TARGET_SUBDIRS = ["", "app", "src", "client", "server", "frontend", "backend", "api"]

TIER_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

TIER_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}

TIER_GUIDANCE = {
    "CRITICAL": (
        "Pull CI/CD build logs for 2026-03-31 00:21-03:30 UTC.\n"
        "  Search for: 'added axios 1.14.1' or 'added axios 0.30.4' in npm output.\n"
        "  If found: escalate to full IR — rotate all secrets, check for outbound\n"
        "  connections to sfrclak.com:8000 / 142.11.206.73."
    ),
    "HIGH": (
        "Review CI/CD build logs for the attack window.\n"
        "  Determine whether CI used `npm install` (unsafe) or `npm ci` (safer).\n"
        "  If `npm install` was used: treat as CRITICAL and escalate."
    ),
    "MEDIUM": (
        "Lower priority for log review. Confirm CI command used and whether\n"
        "  any builds ran during the window before deprioritising."
    ),
    "LOW": (
        "Unlikely affected. Verify and close after higher tiers are cleared."
    ),
}


# ---------------------------------------------------------------------------
# Thread-safe rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Enforces a max-requests-per-second ceiling shared across all threads.
    Also handles GitHub rate-limit header awareness.
    """
    def __init__(self, max_per_second=10):
        self._lock         = threading.Lock()
        self._min_interval = 1.0 / max_per_second
        self._last_call    = 0.0

    def acquire(self):
        with self._lock:
            now  = time.time()
            wait = self._min_interval - (now - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.time()


# ---------------------------------------------------------------------------
# Sleep with progress display
# ---------------------------------------------------------------------------

_print_lock = threading.Lock()


def thread_print(*args, **kwargs):
    """Thread-safe print wrapper."""
    with _print_lock:
        print(*args, **kwargs)


def sleep_with_progress(seconds, reason="", update_interval=15):
    """
    Sleep for `seconds`, printing a countdown line every `update_interval`
    seconds so long-running waits are visible in the terminal.
    """
    if seconds <= 0:
        return

    end_time = time.time() + seconds
    label    = f" ({reason})" if reason else ""

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


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def make_session(token):
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
            wait     = max(reset_ts - int(time.time()), 5)
            thread_print(f"\n  [RATE LIMIT] {remaining} requests remaining", flush=True)
            sleep_with_progress(wait, reason="GitHub rate limit reset")

        if resp.status_code == 200:
            return resp

        if resp.status_code == 404:
            return resp

        if resp.status_code in (403, 429):
            # Distinguish rate limits from permission errors
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
                # Permission error — retrying won't help
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
    url  = f"{GITHUB_API}/repos/{repo_full_name}/contents/{quote(path)}"
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


# ---------------------------------------------------------------------------
# Git Trees API — fetch entire repo file tree in one call
# ---------------------------------------------------------------------------

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
        return None  # Tree too large; fall back to per-file approach
    return {item["path"] for item in data.get("tree", []) if item["type"] == "blob"}


# ---------------------------------------------------------------------------
# Axios version range scoring
# ---------------------------------------------------------------------------

def range_can_resolve_bad(spec):
    """
    Given an npm version spec, return (score, reason).
    Score > 0 means the spec could resolve to a bad version.
    Score = 0 means it definitively cannot — caller should skip the repo.
    """
    if not isinstance(spec, str):
        return 0, "non-string spec"

    spec = spec.strip()

    # Exact bad pin
    if spec in BAD_VERSIONS:
        return 40, f"exact pin to compromised version ({spec})"

    # Wildcards
    if spec in ("*", "latest", "x", ""):
        return 38, f"wildcard/latest resolves to npm latest ({spec!r})"

    # --- OR ranges: "^1.13.0 || ^2.0.0" — score each alternative, take worst ---
    if "||" in spec:
        parts = [p.strip() for p in spec.split("||")]
        best_score, best_reason = 0, ""
        for part in parts:
            s, r = range_can_resolve_bad(part)
            if s > best_score:
                best_score, best_reason = s, r
        return best_score, f"OR range — worst component: {best_reason}"

    # --- Hyphen ranges: "1.0.0 - 2.0.0" ---
    hm = re.match(r'^(\d+\.\d+\.\d+)\s+-\s+(\d+\.\d+\.\d+)$', spec)
    if hm:
        lo = tuple(int(x) for x in hm.group(1).split('.'))
        hi = tuple(int(x) for x in hm.group(2).split('.'))
        for bad_v in BAD_VERSIONS:
            bad_t = tuple(int(x) for x in bad_v.split('.'))
            if lo <= bad_t <= hi:
                return 35, f"hyphen range {spec!r} includes {bad_v}"
        return 0, f"hyphen range {spec!r} excludes both bad versions"

    # --- AND ranges (space-separated): ">=1.0.0 <2.0.0" ---
    #     AND means intersection: ALL components must include a bad version.
    #     If any component definitively excludes bad versions (score=0),
    #     the intersection also excludes them → return 0.
    stripped = spec.strip()
    if " " in stripped and not stripped.startswith(("http", "git")):
        parts = stripped.split()
        if all(re.match(r'^[<>=~^]', p) for p in parts):
            scores_reasons = []
            for part in parts:
                s, r = range_can_resolve_bad(part)
                scores_reasons.append((s, r))
            # If any component is definitively safe, the intersection is safe
            if any(s == 0 for s, _ in scores_reasons):
                safe_part = next(r for s, r in scores_reasons if s == 0)
                return 0, f"AND range {spec!r} — excluded by: {safe_part}"
            # All components could resolve bad — take the minimum score
            min_score = min(s for s, _ in scores_reasons)
            min_reason = next(r for s, r in scores_reasons if s == min_score)
            return min_score, f"AND range {spec!r} — narrowest: {min_reason}"

    clean = spec.lstrip("=").strip()

    # Git/URL specs — resolution unknowable statically
    if clean.startswith(("http", "git")):
        return 15, "git/URL spec — resolution unknowable statically"

    # Caret: ^MAJOR.MINOR.PATCH
    m = re.match(r"^\^(\d+)\.(\d+)\.(\d+)", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        # For 1.x: ^ locks major only → resolves <2.0.0 → includes 1.14.1
        if major == 1 and (minor, patch) <= (14, 1):
            return 35, f"^{major}.{minor}.{patch} resolves <2.0.0, includes 1.14.1"
        # For 0.x: ^ locks major AND minor → ^0.30.x resolves <0.31.0 → includes 0.30.4
        if major == 0 and minor == 30 and patch <= 4:
            return 35, f"^{major}.{minor}.{patch} resolves <0.31.0, includes 0.30.4"
        return 0, f"^{major}.{minor}.{patch} — range excludes both bad versions"

    # Caret without patch: ^MAJOR.MINOR
    m = re.match(r"^\^(\d+)\.(\d+)$", clean)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if major == 1 and minor <= 14:
            return 35, f"^{major}.{minor} resolves <2.0.0, includes 1.14.1"
        if major == 0 and minor == 30:
            return 35, f"^{major}.{minor} resolves <0.31.0, includes 0.30.4"
        return 0, f"^{major}.{minor} — excludes both bad versions"

    # Caret major only: ^MAJOR
    m = re.match(r"^\^(\d+)$", clean)
    if m:
        major = int(m.group(1))
        if major == 1:
            return 35, f"^{major} resolves <2.0.0, includes 1.14.1"
        if major == 0:
            return 25, f"^{major} resolves <1.0.0, includes 0.30.4"
        return 0, f"^{major} — excludes both bad versions"

    # Tilde: ~MAJOR.MINOR.PATCH — locks to same minor
    m = re.match(r"^~(\d+)\.(\d+)\.(\d+)", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if major == 1 and minor == 14 and patch <= 1:
            return 35, f"~{major}.{minor}.{patch} resolves 1.14.x, includes 1.14.1"
        if major == 0 and minor == 30 and patch <= 4:
            return 35, f"~{major}.{minor}.{patch} resolves 0.30.x, includes 0.30.4"
        return 0, f"~{major}.{minor}.{patch} — locked minor excludes bad versions"

    # Tilde without patch: ~MAJOR.MINOR
    m = re.match(r"^~(\d+)\.(\d+)$", clean)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if major == 1 and minor == 14:
            return 35, f"~{major}.{minor} resolves 1.14.x, includes 1.14.1"
        if major == 0 and minor == 30:
            return 35, f"~{major}.{minor} resolves 0.30.x, includes 0.30.4"
        return 0, f"~{major}.{minor} — locked minor excludes bad versions"

    # >=X.Y.Z (open upper bound)
    m = re.match(r"^>=(\d+)\.(\d+)\.(\d+)$", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        # Check each bad version independently
        includes_114_1 = (major, minor, patch) <= (1, 14, 1)
        includes_030_4 = (major, minor, patch) <= (0, 30, 4)
        if includes_114_1 or includes_030_4:
            hit = []
            if includes_114_1:
                hit.append("1.14.1")
            if includes_030_4:
                hit.append("0.30.4")
            return 25, f">={major}.{minor}.{patch} — open upper bound, includes {', '.join(hit)}"
        return 0, f">={major}.{minor}.{patch} — lower bound above bad versions"

    # <X.Y.Z
    m = re.match(r"^<(\d+)\.(\d+)\.(\d+)$", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        # <X.Y.Z includes anything below; check if bad versions are below
        includes_114_1 = (1, 14, 1) < (major, minor, patch)
        includes_030_4 = (0, 30, 4) < (major, minor, patch)
        if includes_114_1 or includes_030_4:
            hit = []
            if includes_114_1:
                hit.append("1.14.1")
            if includes_030_4:
                hit.append("0.30.4")
            return 20, f"<{major}.{minor}.{patch} — includes {', '.join(hit)}"
        return 0, f"<{major}.{minor}.{patch} — excludes bad versions"

    # <=X.Y.Z
    m = re.match(r"^<=(\d+)\.(\d+)\.(\d+)$", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        includes_114_1 = (1, 14, 1) <= (major, minor, patch)
        includes_030_4 = (0, 30, 4) <= (major, minor, patch)
        if includes_114_1 or includes_030_4:
            hit = []
            if includes_114_1:
                hit.append("1.14.1")
            if includes_030_4:
                hit.append("0.30.4")
            return 20, f"<={major}.{minor}.{patch} — includes {', '.join(hit)}"
        return 0, f"<={major}.{minor}.{patch} — excludes bad versions"

    # >X.Y.Z
    m = re.match(r"^>(\d+)\.(\d+)\.(\d+)$", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        # >X.Y.Z includes anything strictly above
        includes_114_1 = (major, minor, patch) < (1, 14, 1)
        includes_030_4 = (major, minor, patch) < (0, 30, 4)
        if includes_114_1 or includes_030_4:
            return 25, f">{major}.{minor}.{patch} — open upper bound, may include bad versions"
        return 0, f">{major}.{minor}.{patch} — excludes bad versions"

    # Exact safe pin: X.Y.Z (including pre-release tags)
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", clean)
    if m:
        ver = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
        if ver in BAD_VERSIONS:
            return 40, f"exact pin to compromised version ({ver})"
        return 0, f"exact pin to safe version ({ver})"

    # x-ranges: 1.14.x
    m = re.match(r"^(\d+)\.(\d+)\.x$", clean, re.IGNORECASE)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if major == 1 and minor == 14:
            return 35, f"{major}.{minor}.x — patch wildcard, includes 1.14.1"
        if major == 0 and minor == 30:
            return 35, f"{major}.{minor}.x — patch wildcard, includes 0.30.4"
        return 0, f"{major}.{minor}.x — excludes bad versions"

    # x-ranges: 1.x or 1.x.x
    m = re.match(r"^(\d+)\.x(?:\.x)?$", clean, re.IGNORECASE)
    if m:
        major = int(m.group(1))
        if major == 1:
            return 25, f"{major}.x — minor wildcard, includes 1.14.1"
        if major == 0:
            return 25, f"{major}.x — minor wildcard, includes 0.30.4"
        return 0, f"{major}.x — excludes bad versions"

    # Unrecognised — flag conservatively
    return 15, f"unrecognised spec {spec!r} — manual review needed"


# ---------------------------------------------------------------------------
# Lockfile scoring and version extraction
# ---------------------------------------------------------------------------

def lockfile_score(lockfile_ver):
    """Return (score, reason) based on the axios version found in a lockfile."""
    if lockfile_ver is None:
        return 30, "no lockfile — every npm install does fresh resolution"
    if lockfile_ver in BAD_VERSIONS:
        return 30, f"lockfile resolves axios@{lockfile_ver} — confirmed bad version in lock"
    if lockfile_ver in SAFE_ADJACENT_VERSIONS:
        return 15, (f"lockfile pins axios@{lockfile_ver} — safe only if CI used `npm ci`; "
                    f"vulnerable if `npm install` was used")
    return 5, f"lockfile pins axios@{lockfile_ver} — likely safe, verify CI command"


def _extract_pnpm_lockfile_version_yaml(content):
    """Extract axios version from pnpm-lock.yaml using YAML parser."""
    try:
        data = _yaml.safe_load(content)
        if not isinstance(data, dict):
            return None

        # pnpm v9+: importers → '.' → dependencies → axios → version
        importers = data.get("importers")
        if isinstance(importers, dict):
            for importer in importers.values():
                if not isinstance(importer, dict):
                    continue
                for dep_section in ("dependencies", "devDependencies",
                                    "optionalDependencies"):
                    deps = importer.get(dep_section)
                    if not isinstance(deps, dict):
                        continue
                    axios_dep = deps.get("axios")
                    if isinstance(axios_dep, dict):
                        ver = axios_dep.get("version", "")
                        m = re.match(r'(\d+\.\d+\.\d+)', str(ver))
                        if m:
                            return m.group(1)
                    elif isinstance(axios_dep, str):
                        m = re.match(r'(\d+\.\d+\.\d+)', axios_dep)
                        if m:
                            return m.group(1)

        # pnpm v6: packages dict with /axios/X.Y.Z or /axios@X.Y.Z keys
        packages = data.get("packages")
        if isinstance(packages, dict):
            for key in packages:
                m = re.match(r'^/axios/(\d+\.\d+\.\d+)$', str(key))
                if m:
                    return m.group(1)
                m = re.match(r'^/axios@(\d+\.\d+\.\d+)$', str(key))
                if m:
                    return m.group(1)

        # pnpm v9 snapshots: axios@X.Y.Z as a top-level key in snapshots
        snapshots = data.get("snapshots")
        if isinstance(snapshots, dict):
            for key in snapshots:
                m = re.match(r'^axios@(\d+\.\d+\.\d+)$', str(key))
                if m:
                    return m.group(1)

    except Exception:
        pass
    return None


def _extract_pnpm_lockfile_version_regex(content):
    """Fallback: extract axios version from pnpm-lock.yaml using regex."""
    # pnpm v6: /axios/1.14.1 at start of line or indented
    m = re.search(r'(?:^|\n)\s*/axios/(\d+\.\d+\.\d+)', content)
    if m:
        return m.group(1)
    # pnpm v9: axios@1.14.1: at start of line
    m = re.search(r'(?:^|\n)\s*axios@(\d+\.\d+\.\d+):', content)
    if m:
        return m.group(1)
    return None


def extract_lockfile_axios_version(content, filename):
    """
    Return the resolved axios version from a lockfile, or None.
    Strict key/path matching — never returns the version of a different package.
    """
    if filename == "package-lock.json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None

        # v2/v3: flat packages dict
        for pkg_path, pkg_data in data.get("packages", {}).items():
            if not isinstance(pkg_data, dict) or not pkg_path:
                continue
            parts    = pkg_path.replace("\\", "/").split("node_modules/")
            pkg_name = parts[-1].rstrip("/") if parts else ""
            if pkg_name == "axios":
                return pkg_data.get("version")

        # v1: nested dependencies dict
        dep = data.get("dependencies", {}).get("axios", {})
        if isinstance(dep, dict):
            return dep.get("version")

    elif filename == "yarn.lock":
        in_axios = False
        for line in content.splitlines():
            if line and not line[0].isspace() and line.endswith(":"):
                specs = [s.strip().strip('"') for s in line.rstrip(":").split(",")]
                names = set()
                for s in specs:
                    s   = s.strip()
                    idx = s.find("@", 1) if s.startswith("@") else s.find("@")
                    names.add(s[:idx] if idx != -1 else s)
                in_axios = "axios" in names
            elif not line.strip():
                in_axios = False
            elif in_axios and line.strip().startswith("version"):
                parts = line.strip().split()
                if len(parts) >= 2:
                    return parts[1].strip('"')

    elif filename == "pnpm-lock.yaml":
        if HAS_YAML:
            ver = _extract_pnpm_lockfile_version_yaml(content)
            if ver:
                return ver
        # Regex fallback (always available, tighter than original)
        return _extract_pnpm_lockfile_version_regex(content)

    return None


# ---------------------------------------------------------------------------
# package.json axios spec extraction
# ---------------------------------------------------------------------------

def extract_axios_specs(content):
    """
    Return list of (section, spec) tuples for axios in package.json.
    Only returns entries whose key is literally 'axios'.
    """
    results = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return results
    for section in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        if "axios" in deps and isinstance(deps["axios"], str):
            results.append((section, deps["axios"]))
    return results


# ---------------------------------------------------------------------------
# Repo enumeration
# ---------------------------------------------------------------------------

def list_all_repos(session, org, rate_limiter):
    """Return all non-archived repos in org, paginated."""
    repos = []
    page  = 1
    thread_print(f"[1/2] Enumerating repos in {org} (excluding archived)...", flush=True)
    while True:
        resp = safe_get(session, f"{GITHUB_API}/orgs/{org}/repos",
                        {"per_page": PER_PAGE, "page": page, "type": "all"}, rate_limiter)
        if resp is None or resp.status_code != 200:
            thread_print(
                f"\n  [ERROR] Failed to fetch repo list "
                f"(HTTP {getattr(resp, 'status_code', '?')})", flush=True)
            break
        batch  = resp.json()
        if not batch:
            break
        active  = [r for r in batch if not r.get("archived", False)]
        skipped = len(batch) - len(active)
        repos.extend(active)
        thread_print(
            f"  Page {page}: {len(batch)} fetched, {skipped} archived skipped "
            f"(running total: {len(repos)})", flush=True)
        if len(batch) < PER_PAGE:
            break
        page += 1
    thread_print(f"  → {len(repos)} active repos\n", flush=True)
    return repos


# ---------------------------------------------------------------------------
# Activity scoring
# ---------------------------------------------------------------------------

def activity_score(pushed_at_str):
    """
    Score based on how recently the repo was active near the attack window.
    Asymmetric: repos pushed *after* the window were definitely active;
    repos pushed *before* have decreasing likelihood of CI runs during the window.
    """
    if not pushed_at_str:
        return 0, "no push timestamp available"
    try:
        pushed = datetime.fromisoformat(pushed_at_str.replace("Z", "+00:00"))
    except ValueError:
        return 0, "unparseable push timestamp"

    # Pushed during the attack window itself
    if ATTACK_WINDOW_START <= pushed <= ATTACK_WINDOW_END:
        return 10, "pushed during the attack window"

    # Pushed after the window — repo was active, CI likely ran during window too
    if pushed > ATTACK_WINDOW_END:
        days_after = (pushed - ATTACK_WINDOW_END).days
        if days_after <= 7:
            return 10, f"pushed {days_after}d after attack window — likely active CI"
        if days_after <= 30:
            return 7,  f"pushed {days_after}d after attack window — probably active CI"
        return 4, f"pushed {days_after}d after attack window — may have been active"

    # Pushed before the window — decreasing confidence
    days_before = (ATTACK_WINDOW_START - pushed).days
    if days_before <= 7:
        return 10, f"last push {days_before}d before attack window — likely active CI"
    if days_before <= 30:
        return 6,  f"last push {days_before}d before attack window — possibly active CI"
    if days_before <= 90:
        return 3,  f"last push {days_before}d before attack window — CI may have been quiet"
    return 0, f"last push {days_before}d before attack window — unlikely CI was running"


# ---------------------------------------------------------------------------
# CI detection (uses tree if available, falls back to API)
# ---------------------------------------------------------------------------

def detect_ci(session, repo_full_name, rate_limiter, file_tree=None):
    """
    Check for common CI config files. Returns (score, [detected_configs]).
    Uses the pre-fetched file tree when available to avoid extra API calls.
    """
    detected = []
    for cfg in CI_CONFIG_PATHS:
        if file_tree is not None:
            # Check tree: exact match or prefix match for directories
            if cfg in file_tree or any(p.startswith(cfg + "/") for p in file_tree):
                detected.append(cfg)
        else:
            url  = f"{GITHUB_API}/repos/{repo_full_name}/contents/{quote(cfg)}"
            resp = safe_get(session, url, {}, rate_limiter)
            if resp is not None and resp.status_code == 200:
                detected.append(cfg)

    if not detected:
        return 0, []
    score = 20 if any(".github/workflows" in d for d in detected) else 15
    return score, detected


def fetch_recent_committers(session, repo_full_name, rate_limiter, limit=5):
    """
    Return recent commit identity signals for a repository's default branch.
    Best-effort only: author/committer emails may be private or unavailable.
    """
    if limit <= 0:
        return []

    url = f"{GITHUB_API}/repos/{repo_full_name}/commits"
    resp = safe_get(session, url, {"per_page": max(1, min(limit, 100))}, rate_limiter)
    if resp is None or resp.status_code != 200:
        return []

    committers = []
    for item in resp.json():
        commit = item.get("commit", {}) or {}
        author = commit.get("author", {}) or {}
        committer = commit.get("committer", {}) or {}
        gh_author = item.get("author") or {}
        gh_committer = item.get("committer") or {}
        committers.append({
            "sha": item.get("sha"),
            "author_date": author.get("date"),
            "author_name": author.get("name"),
            "author_email": author.get("email"),
            "committer_date": committer.get("date"),
            "committer_name": committer.get("name"),
            "committer_email": committer.get("email"),
            "author_login": gh_author.get("login"),
            "author_id": gh_author.get("id"),
            "committer_login": gh_committer.get("login"),
            "committer_id": gh_committer.get("id"),
            "author_association": item.get("author_association"),
        })
    return committers


# ---------------------------------------------------------------------------
# Per-repo scan
# ---------------------------------------------------------------------------

def scan_repo(session, repo, rate_limiter, include_identity=False, recent_committers=5):
    """
    Scan a single repo. Returns a result dict, or None if axios is not
    present or all specs are definitively safe.
    """
    full_name      = repo["full_name"]
    repo_id        = repo.get("id")
    default_branch = repo.get("default_branch", "main")
    html_url       = repo["html_url"]
    pushed_at      = repo.get("pushed_at", "")
    owner          = repo.get("owner", {}) or {}

    # 0. Fetch file tree to minimise API calls
    file_tree = get_repo_tree(session, full_name, default_branch, rate_limiter)

    # Quick exit: if we got a tree and there's no package.json anywhere, skip
    if file_tree is not None:
        has_any_pkg_json = any(p.endswith("/package.json") or p == "package.json"
                               for p in file_tree)
        if not has_any_pkg_json:
            return None

    # 1. Find package.json files and extract axios specs
    axios_entries = []
    dirs_with_axios = set()

    for subdir in TARGET_SUBDIRS:
        path = f"{subdir}/package.json".lstrip("/") if subdir else "package.json"

        # Skip if tree is available and file doesn't exist
        if file_tree is not None and path not in file_tree:
            continue

        content = fetch_file(session, full_name, path, rate_limiter)
        if content is None:
            continue
        for section, spec in extract_axios_specs(content):
            score, reason = range_can_resolve_bad(spec)
            if score == 0:
                continue
            axios_entries.append({
                "file":         path,
                "section":      section,
                "spec":         spec,
                "range_score":  score,
                "range_reason": reason,
            })
            # Track which directories have axios for lockfile search
            pkg_dir = os.path.dirname(path)
            dirs_with_axios.add(pkg_dir)

    if not axios_entries:
        return None

    best        = max(axios_entries, key=lambda e: e["range_score"])
    range_score = best["range_score"]

    # 2. Find lockfile in the same directories where axios was found
    lockfile_ver  = None
    lockfile_file = None

    for search_dir in sorted(dirs_with_axios):
        for lf_name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            lf_path = f"{search_dir}/{lf_name}".lstrip("/") if search_dir else lf_name

            # Skip if tree is available and file doesn't exist
            if file_tree is not None and lf_path not in file_tree:
                continue

            content = fetch_file(session, full_name, lf_path, rate_limiter)
            if content is not None:
                ver = extract_lockfile_axios_version(content, lf_name)
                if ver:
                    lockfile_ver  = ver
                    lockfile_file = lf_path
                    break
        if lockfile_ver:
            break

    lf_score, lf_reason = lockfile_score(lockfile_ver)

    # 3. CI detection (uses tree data when available — zero extra API calls)
    ci_score, ci_configs = detect_ci(session, full_name, rate_limiter,
                                      file_tree=file_tree)

    # 4. Activity score
    act_score, act_reason = activity_score(pushed_at)

    # 5. Total and tier
    total = range_score + lf_score + ci_score + act_score
    if total >= 75:
        tier = "CRITICAL"
    elif total >= 50:
        tier = "HIGH"
    elif total >= 25:
        tier = "MEDIUM"
    else:
        tier = "LOW"

    owner_identity = None
    committer_info = []
    if include_identity:
        owner_identity = {
            "login": owner.get("login"),
            "id": owner.get("id"),
            "type": owner.get("type"),
        }
        committer_info = fetch_recent_committers(
            session, full_name, rate_limiter, limit=recent_committers
        )

    return {
        "repo":           full_name,
        "repo_id":        repo_id,
        "url":            html_url,
        "default_branch": default_branch,
        "pushed_at":      pushed_at,
        "scanned_at":     datetime.now(timezone.utc).isoformat(),
        "tier":           tier,
        "total_score":    total,
        "scoring": {
            "range_score":  range_score,
            "range_reason": best["range_reason"],
            "lf_score":     lf_score,
            "lf_reason":    lf_reason,
            "ci_score":     ci_score,
            "ci_configs":   ci_configs,
            "act_score":    act_score,
            "act_reason":   act_reason,
        },
        "axios_entries":  axios_entries,
        "lockfile_file":  lockfile_file,
        "lockfile_ver":   lockfile_ver,
        "owner_identity": owner_identity,
        "recent_committers": committer_info,
    }


# ---------------------------------------------------------------------------
# Progress / checkpointing (atomic writes, thread-safe)
# ---------------------------------------------------------------------------

_checkpoint_lock = threading.Lock()


def progress_path(output_path):
    base, _ = os.path.splitext(output_path)
    return base + ".progress.json"


def load_progress(output_path):
    pp = progress_path(output_path)
    if not os.path.exists(pp):
        return set(), []
    try:
        with open(pp) as f:
            data = json.load(f)
        scanned  = set(data.get("scanned_repos", []))
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
            os.replace(tmp_path, pp)  # Atomic on POSIX
        except Exception as e:
            thread_print(f"\n  [WARN] Could not save checkpoint: {e}", flush=True)
            # Clean up temp file if it exists
            try:
                if 'tmp_path' in locals():
                    os.unlink(tmp_path)
            except OSError:
                pass


def clear_progress(output_path):
    pp = progress_path(output_path)
    if os.path.exists(pp):
        os.remove(pp)


# ---------------------------------------------------------------------------
# Org scan (concurrent)
# ---------------------------------------------------------------------------

def scan_org(org, token, output_path, max_workers=5,
             include_identity=False, recent_committers=5):
    """
    Scan all repos in the org using a thread pool.
    Rate limiting is shared across all workers.
    """
    session      = make_session(token)
    rate_limiter = RateLimiter(max_per_second=max_workers * 2)
    repos        = list_all_repos(session, org, rate_limiter)
    total        = len(repos)

    scanned_names, findings = load_progress(output_path)

    # Each thread gets its own session for connection pooling
    thread_local = threading.local()

    def get_thread_session():
        if not hasattr(thread_local, "session"):
            thread_local.session = make_session(token)
        return thread_local.session

    def scan_one(idx_repo):
        idx, repo = idx_repo
        name = repo["full_name"]

        # Check if already scanned (thread-safe read — set membership is safe)
        if name in scanned_names:
            thread_print(
                f"  [{idx:4d}/{total}] {name}  [skipped — already scanned]", flush=True)
            return name, None

        thread_print(f"  [{idx:4d}/{total}] {name}", end="  ", flush=True)

        sess   = get_thread_session()
        result = scan_repo(
            sess,
            repo,
            rate_limiter,
            include_identity=include_identity,
            recent_committers=recent_committers,
        )

        if result:
            emoji = TIER_EMOJI.get(result["tier"], "")
            thread_print(f"{emoji} {result['tier']} (score: {result['total_score']})",
                         flush=True)
        else:
            thread_print("—  no axios exposure", flush=True)

        return name, result

    thread_print(f"[2/2] Scanning {total} repos ({max_workers} workers)...\n", flush=True)

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

            with _checkpoint_lock:
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


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(findings, org):
    if not findings:
        print("\n  No axios exposure found in any active repo.")
        return

    findings_sorted = sorted(findings,
                             key=lambda f: (TIER_ORDER.get(f["tier"], 9), -f["total_score"]))
    counts = {t: sum(1 for f in findings if f["tier"] == t)
              for t in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}

    print("\n" + "=" * 72)
    print("  AXIOS SUPPLY CHAIN EXPOSURE SCAN — RESULTS")
    print(f"  Org       : github.com/{org}")
    print(f"  Timestamp : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Window    : 2026-03-31 00:21-03:30 UTC (~3 hours)")
    print(f"  Bad vers  : axios@1.14.1 and axios@0.30.4")
    print("=" * 72)
    print(f"\n  🔴 CRITICAL : {counts['CRITICAL']:3d}    Immediate log review")
    print(f"  🟠 HIGH     : {counts['HIGH']:3d}    Review build logs — check CI command used")
    print(f"  🟡 MEDIUM   : {counts['MEDIUM']:3d}    Review after CRITICAL/HIGH cleared")
    print(f"  ⚪ LOW      : {counts['LOW']:3d}    Verify and deprioritise")
    print(f"\n  Total repos with axios exposure : {len(findings)}")

    current_tier = None
    for f in findings_sorted:
        if f["tier"] != current_tier:
            current_tier = f["tier"]
            print(f"\n  {'─'*68}")
            print(f"  {TIER_EMOJI[current_tier]} {current_tier} — {TIER_GUIDANCE[current_tier]}")
            print(f"  {'─'*68}")

        s = f["scoring"]
        ci_label = ("configs: " + ", ".join(s["ci_configs"])) if s["ci_configs"] else "no CI config detected"
        print(f"""
  [{f['total_score']:3d}/100] {f['repo']}
  URL    : {f['url']}
  Pushed : {f['pushed_at']}
  Score breakdown:
    Range  {s['range_score']:2d}/40  {s['range_reason']}
    Lock   {s['lf_score']:2d}/30  {s['lf_reason']}
    CI     {s['ci_score']:2d}/20  {ci_label}
    Active {s['act_score']:2d}/10  {s['act_reason']}
  Axios entries:""")
        for entry in f["axios_entries"]:
            print(f"    {entry['file']} → {entry['section']}[\"axios\"] = \"{entry['spec']}\"")
        if f["lockfile_file"]:
            print(f"  Lockfile : {f['lockfile_file']} pins axios@{f['lockfile_ver']}")
        else:
            print(f"  Lockfile : none found")
        owner_identity = f.get("owner_identity")
        if owner_identity:
            print(
                "  Owner    : "
                f"{owner_identity.get('login')} "
                f"(id={owner_identity.get('id')}, type={owner_identity.get('type')})"
            )
        recent_committers = f.get("recent_committers", [])
        if recent_committers:
            print("  Recent committers:")
            for c in recent_committers:
                author = c.get("author_login") or c.get("author_name") or "unknown-author"
                committer = c.get("committer_login") or c.get("committer_name") or "unknown-committer"
                author_email = c.get("author_email") or "n/a"
                committer_email = c.get("committer_email") or "n/a"
                assoc = c.get("author_association") or "UNKNOWN"
                print(
                    f"    {c.get('sha', '')[:12]} "
                    f"author={author} <{author_email}> "
                    f"committer={committer} <{committer_email}> "
                    f"assoc={assoc}"
                )

    print(f"\n  {'─'*68}")
    print("  NOTE: A clean result does not mean a repo was unaffected. If CI ran")
    print("  `npm install` with a loose range during the window, no evidence will")
    print("  remain in source. Build log review is the only definitive clearance.")
    print("=" * 72)


def save_json(findings, output_path, org):
    findings_sorted = sorted(findings,
                             key=lambda f: (TIER_ORDER.get(f["tier"], 9), -f["total_score"]))
    out = {
        "scan_metadata": {
            "org":               org,
            "timestamp_utc":     datetime.now(timezone.utc).isoformat(),
            "attack_window_utc": "2026-03-31T00:21:00Z to 2026-03-31T03:30:00Z",
            "bad_versions":      sorted(BAD_VERSIONS),
            "purpose": (
                "IR triage — identifies repos for CI log review, "
                "not confirmed compromise"
            ),
        },
        "summary": {
            "total_exposed_repos": len(findings),
            "by_tier": {t: sum(1 for f in findings if f["tier"] == t)
                        for t in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        },
        "findings": findings_sorted,
    }
    with open(output_path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"  [OUTPUT] Results written to {output_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Scan a GitHub org to scope IR exposure from the axios "
            "supply chain attack (2026-03-31)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--org", required=True,
        help="GitHub organization name to scan (e.g. my-org)"
    )
    parser.add_argument(
        "--token", default=os.getenv("GITHUB_TOKEN"),
        help="GitHub personal access token. Falls back to $GITHUB_TOKEN env var. "
             "Required scopes: public_repo (public only) or repo (includes private)."
    )
    parser.add_argument(
        "--output", default="axios_exposure.json",
        help="Path to write JSON results (default: axios_exposure.json)"
    )
    parser.add_argument(
        "--workers", type=int, default=5,
        help="Number of concurrent scanning threads (default: 5, max: 15)"
    )
    parser.add_argument(
        "--subdirs", nargs="*", default=None,
        help=(
            "Subdirectories to check for package.json "
            "(default: '' app src client server frontend backend api)"
        ),
    )
    parser.add_argument(
        "--ci-paths", nargs="*", default=None,
        help="CI config paths to detect (overrides built-in list)",
    )
    parser.add_argument(
        "--include-identity", action="store_true",
        help=(
            "Include repo owner and recent committer identity metadata in findings. "
            "May increase API usage."
        ),
    )
    parser.add_argument(
        "--recent-committers", type=int, default=5,
        help=(
            "Number of recent commits to inspect per exposed repo when "
            "--include-identity is set (default: 5, max: 20)."
        ),
    )
    args = parser.parse_args()

    if not args.token:
        print("[ERROR] GitHub token required.")
        print("  Set the GITHUB_TOKEN environment variable or pass --token.")
        print("  Required scopes: public_repo (public repos) or repo (includes private)")
        print("  Generate at: https://github.com/settings/tokens")
        sys.exit(1)

    # Clamp workers
    args.workers = max(1, min(args.workers, 15))
    args.recent_committers = max(1, min(args.recent_committers, 20))

    # Resolve output path to prevent path confusion
    args.output = os.path.realpath(args.output)

    # Apply CLI overrides for subdirs and CI paths
    global TARGET_SUBDIRS, CI_CONFIG_PATHS
    if args.subdirs is not None:
        TARGET_SUBDIRS = args.subdirs
    if args.ci_paths is not None:
        CI_CONFIG_PATHS = args.ci_paths

    print("[AXIOS SUPPLY CHAIN EXPOSURE SCANNER]")
    print(f"  Org        : https://github.com/{args.org}/")
    print(f"  Output     : {args.output}")
    print(f"  Workers    : {args.workers}  |  Checkpoint every {SAVE_EVERY} repos")
    print(f"  Identity   : {'enabled' if args.include_identity else 'disabled'}")
    if args.include_identity:
        print(f"  Committers : {args.recent_committers} recent commits per exposed repo")
    print(f"  Bad vers   : axios@1.14.1, axios@0.30.4")
    print(f"  Window     : 2026-03-31 00:21-03:30 UTC")
    if HAS_YAML:
        print(f"  pnpm-lock  : YAML parser available (pyyaml)")
    else:
        print(f"  pnpm-lock  : regex fallback (install pyyaml for better parsing)")
    print()

    findings = scan_org(args.org, args.token, args.output,
                        max_workers=args.workers,
                        include_identity=args.include_identity,
                        recent_committers=args.recent_committers)
    print_report(findings, args.org)
    save_json(findings, args.output, args.org)
    clear_progress(args.output)
    print("\n  [DONE] Progress file cleared.\n")


if __name__ == "__main__":
    main()
