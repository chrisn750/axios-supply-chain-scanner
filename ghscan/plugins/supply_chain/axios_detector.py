"""
axios Supply Chain Exposure Detector
=====================================
Detects exposure to the axios npm supply chain compromise (2026-03-31).

Vulnerability: axios@1.14.1 and axios@0.30.4
Attribution:   UNC1069 (North Korea-nexus, Google GTIG)

This plugin identifies repos whose dependency configuration could have
caused CI to resolve the malicious axios versions during the ~3hr attack
window, so analysts know which build logs to pull and review.
"""

import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from ghscan.plugin_api import (
    FileRequest, PluginFinding, PluginMeta, ScanPlugin,
)

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ---------------------------------------------------------------------------
# Axios-specific constants
# ---------------------------------------------------------------------------

ATTACK_WINDOW_START = datetime(2026, 3, 31, 0, 21, tzinfo=timezone.utc)
ATTACK_WINDOW_END = datetime(2026, 3, 31, 3, 30, tzinfo=timezone.utc)

BAD_VERSIONS = {"1.14.1", "0.30.4"}
SAFE_ADJACENT_VERSIONS = {"1.14.0", "0.30.3"}

CI_CONFIG_PATHS = [
    ".github/workflows",
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
TIER_EMOJI = {"CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0", "MEDIUM": "\U0001f7e1", "LOW": "\u26aa"}

TIER_GUIDANCE = {
    "CRITICAL": (
        "Pull CI/CD build logs for 2026-03-31 00:21-03:30 UTC.\n"
        "  Search for: 'added axios 1.14.1' or 'added axios 0.30.4' in npm output.\n"
        "  If found: escalate to full IR -- rotate all secrets, check for outbound\n"
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
# Version range scoring
# ---------------------------------------------------------------------------

def _range_can_resolve_bad(spec):
    """
    Given an npm version spec, return (score, reason).
    Score > 0 means the spec could resolve to a bad version.
    Score = 0 means it definitively cannot.
    """
    if not isinstance(spec, str):
        return 0, "non-string spec"

    spec = spec.strip()

    if spec in BAD_VERSIONS:
        return 40, f"exact pin to compromised version ({spec})"

    if spec in ("*", "latest", "x", ""):
        return 38, f"wildcard/latest resolves to npm latest ({spec!r})"

    # OR ranges
    if "||" in spec:
        parts = [p.strip() for p in spec.split("||")]
        best_score, best_reason = 0, ""
        for part in parts:
            s, r = _range_can_resolve_bad(part)
            if s > best_score:
                best_score, best_reason = s, r
        return best_score, f"OR range -- worst component: {best_reason}"

    # Hyphen ranges
    hm = re.match(r'^(\d+\.\d+\.\d+)\s+-\s+(\d+\.\d+\.\d+)$', spec)
    if hm:
        lo = tuple(int(x) for x in hm.group(1).split('.'))
        hi = tuple(int(x) for x in hm.group(2).split('.'))
        for bad_v in BAD_VERSIONS:
            bad_t = tuple(int(x) for x in bad_v.split('.'))
            if lo <= bad_t <= hi:
                return 35, f"hyphen range {spec!r} includes {bad_v}"
        return 0, f"hyphen range {spec!r} excludes both bad versions"

    # AND ranges (space-separated)
    stripped = spec.strip()
    if " " in stripped and not stripped.startswith(("http", "git")):
        parts = stripped.split()
        if all(re.match(r'^[<>=~^]', p) for p in parts):
            scores_reasons = []
            for part in parts:
                s, r = _range_can_resolve_bad(part)
                scores_reasons.append((s, r))
            if any(s == 0 for s, _ in scores_reasons):
                safe_part = next(r for s, r in scores_reasons if s == 0)
                return 0, f"AND range {spec!r} -- excluded by: {safe_part}"
            min_score = min(s for s, _ in scores_reasons)
            min_reason = next(r for s, r in scores_reasons if s == min_score)
            return min_score, f"AND range {spec!r} -- narrowest: {min_reason}"

    clean = spec.lstrip("=").strip()

    if clean.startswith(("http", "git")):
        return 15, "git/URL spec -- resolution unknowable statically"

    # Caret: ^MAJOR.MINOR.PATCH
    m = re.match(r"^\^(\d+)\.(\d+)\.(\d+)", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if major == 1 and (minor, patch) <= (14, 1):
            return 35, f"^{major}.{minor}.{patch} resolves <2.0.0, includes 1.14.1"
        if major == 0 and minor == 30 and patch <= 4:
            return 35, f"^{major}.{minor}.{patch} resolves <0.31.0, includes 0.30.4"
        return 0, f"^{major}.{minor}.{patch} -- range excludes both bad versions"

    # Caret without patch
    m = re.match(r"^\^(\d+)\.(\d+)$", clean)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if major == 1 and minor <= 14:
            return 35, f"^{major}.{minor} resolves <2.0.0, includes 1.14.1"
        if major == 0 and minor == 30:
            return 35, f"^{major}.{minor} resolves <0.31.0, includes 0.30.4"
        return 0, f"^{major}.{minor} -- excludes both bad versions"

    # Caret major only
    m = re.match(r"^\^(\d+)$", clean)
    if m:
        major = int(m.group(1))
        if major == 1:
            return 35, f"^{major} resolves <2.0.0, includes 1.14.1"
        if major == 0:
            return 25, f"^{major} resolves <1.0.0, includes 0.30.4"
        return 0, f"^{major} -- excludes both bad versions"

    # Tilde: ~MAJOR.MINOR.PATCH
    m = re.match(r"^~(\d+)\.(\d+)\.(\d+)", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if major == 1 and minor == 14 and patch <= 1:
            return 35, f"~{major}.{minor}.{patch} resolves 1.14.x, includes 1.14.1"
        if major == 0 and minor == 30 and patch <= 4:
            return 35, f"~{major}.{minor}.{patch} resolves 0.30.x, includes 0.30.4"
        return 0, f"~{major}.{minor}.{patch} -- locked minor excludes bad versions"

    # Tilde without patch
    m = re.match(r"^~(\d+)\.(\d+)$", clean)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if major == 1 and minor == 14:
            return 35, f"~{major}.{minor} resolves 1.14.x, includes 1.14.1"
        if major == 0 and minor == 30:
            return 35, f"~{major}.{minor} resolves 0.30.x, includes 0.30.4"
        return 0, f"~{major}.{minor} -- locked minor excludes bad versions"

    # >=X.Y.Z
    m = re.match(r"^>=(\d+)\.(\d+)\.(\d+)$", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        includes_114_1 = (major, minor, patch) <= (1, 14, 1)
        includes_030_4 = (major, minor, patch) <= (0, 30, 4)
        if includes_114_1 or includes_030_4:
            hit = []
            if includes_114_1:
                hit.append("1.14.1")
            if includes_030_4:
                hit.append("0.30.4")
            return 25, f">={major}.{minor}.{patch} -- open upper bound, includes {', '.join(hit)}"
        return 0, f">={major}.{minor}.{patch} -- lower bound above bad versions"

    # <X.Y.Z
    m = re.match(r"^<(\d+)\.(\d+)\.(\d+)$", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        includes_114_1 = (1, 14, 1) < (major, minor, patch)
        includes_030_4 = (0, 30, 4) < (major, minor, patch)
        if includes_114_1 or includes_030_4:
            hit = []
            if includes_114_1:
                hit.append("1.14.1")
            if includes_030_4:
                hit.append("0.30.4")
            return 20, f"<{major}.{minor}.{patch} -- includes {', '.join(hit)}"
        return 0, f"<{major}.{minor}.{patch} -- excludes bad versions"

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
            return 20, f"<={major}.{minor}.{patch} -- includes {', '.join(hit)}"
        return 0, f"<={major}.{minor}.{patch} -- excludes bad versions"

    # >X.Y.Z
    m = re.match(r"^>(\d+)\.(\d+)\.(\d+)$", clean)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        includes_114_1 = (major, minor, patch) < (1, 14, 1)
        includes_030_4 = (major, minor, patch) < (0, 30, 4)
        if includes_114_1 or includes_030_4:
            return 25, f">{major}.{minor}.{patch} -- open upper bound, may include bad versions"
        return 0, f">{major}.{minor}.{patch} -- excludes bad versions"

    # Exact safe pin
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
            return 35, f"{major}.{minor}.x -- patch wildcard, includes 1.14.1"
        if major == 0 and minor == 30:
            return 35, f"{major}.{minor}.x -- patch wildcard, includes 0.30.4"
        return 0, f"{major}.{minor}.x -- excludes bad versions"

    # x-ranges: 1.x or 1.x.x
    m = re.match(r"^(\d+)\.x(?:\.x)?$", clean, re.IGNORECASE)
    if m:
        major = int(m.group(1))
        if major == 1:
            return 25, f"{major}.x -- minor wildcard, includes 1.14.1"
        if major == 0:
            return 25, f"{major}.x -- minor wildcard, includes 0.30.4"
        return 0, f"{major}.x -- excludes bad versions"

    return 15, f"unrecognised spec {spec!r} -- manual review needed"


# ---------------------------------------------------------------------------
# Lockfile scoring and version extraction
# ---------------------------------------------------------------------------

def _lockfile_score(lockfile_ver):
    """Return (score, reason) based on the axios version found in a lockfile."""
    if lockfile_ver is None:
        return 30, "no lockfile -- every npm install does fresh resolution"
    if lockfile_ver in BAD_VERSIONS:
        return 30, f"lockfile resolves axios@{lockfile_ver} -- confirmed bad version in lock"
    if lockfile_ver in SAFE_ADJACENT_VERSIONS:
        return 15, (f"lockfile pins axios@{lockfile_ver} -- safe only if CI used `npm ci`; "
                    f"vulnerable if `npm install` was used")
    return 5, f"lockfile pins axios@{lockfile_ver} -- likely safe, verify CI command"


def _extract_pnpm_lockfile_version_yaml(content):
    """Extract axios version from pnpm-lock.yaml using YAML parser."""
    try:
        data = _yaml.safe_load(content)
        if not isinstance(data, dict):
            return None

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

        packages = data.get("packages")
        if isinstance(packages, dict):
            for key in packages:
                m = re.match(r'^/axios/(\d+\.\d+\.\d+)$', str(key))
                if m:
                    return m.group(1)
                m = re.match(r'^/axios@(\d+\.\d+\.\d+)$', str(key))
                if m:
                    return m.group(1)

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
    m = re.search(r'(?:^|\n)\s*/axios/(\d+\.\d+\.\d+)', content)
    if m:
        return m.group(1)
    m = re.search(r'(?:^|\n)\s*axios@(\d+\.\d+\.\d+):', content)
    if m:
        return m.group(1)
    return None


def _extract_lockfile_axios_version(content, filename):
    """
    Return the resolved axios version from a lockfile, or None.
    Strict key/path matching.
    """
    if filename == "package-lock.json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None

        for pkg_path, pkg_data in data.get("packages", {}).items():
            if not isinstance(pkg_data, dict) or not pkg_path:
                continue
            parts = pkg_path.replace("\\", "/").split("node_modules/")
            pkg_name = parts[-1].rstrip("/") if parts else ""
            if pkg_name == "axios":
                return pkg_data.get("version")

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
                    s = s.strip()
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
        return _extract_pnpm_lockfile_version_regex(content)

    return None


# ---------------------------------------------------------------------------
# package.json parsing
# ---------------------------------------------------------------------------

def _extract_axios_specs(content):
    """Return list of (section, spec) tuples for axios in package.json."""
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
# Activity scoring
# ---------------------------------------------------------------------------

def _activity_score(pushed_at_str):
    """Score based on how recently the repo was active near the attack window."""
    if not pushed_at_str:
        return 0, "no push timestamp available"
    try:
        pushed = datetime.fromisoformat(pushed_at_str.replace("Z", "+00:00"))
    except ValueError:
        return 0, "unparseable push timestamp"

    if ATTACK_WINDOW_START <= pushed <= ATTACK_WINDOW_END:
        return 10, "pushed during the attack window"

    if pushed > ATTACK_WINDOW_END:
        days_after = (pushed - ATTACK_WINDOW_END).days
        if days_after <= 7:
            return 10, f"pushed {days_after}d after attack window -- likely active CI"
        if days_after <= 30:
            return 7, f"pushed {days_after}d after attack window -- probably active CI"
        return 4, f"pushed {days_after}d after attack window -- may have been active"

    days_before = (ATTACK_WINDOW_START - pushed).days
    if days_before <= 7:
        return 10, f"last push {days_before}d before attack window -- likely active CI"
    if days_before <= 30:
        return 6, f"last push {days_before}d before attack window -- possibly active CI"
    if days_before <= 90:
        return 3, f"last push {days_before}d before attack window -- CI may have been quiet"
    return 0, f"last push {days_before}d before attack window -- unlikely CI was running"


# ---------------------------------------------------------------------------
# CI detection
# ---------------------------------------------------------------------------

def _detect_ci(file_tree):
    """
    Check for common CI config files using the file tree.
    Returns (score, [detected_configs]).
    """
    if file_tree is None:
        return 0, []

    # Partition CI paths into exact-match files vs directory prefixes
    _EXACT_CI_PATHS = {p for p in CI_CONFIG_PATHS if "/" not in p}
    _DIR_CI_PREFIXES = [p + "/" for p in CI_CONFIG_PATHS if "/" in p or p == ".github/workflows"]

    detected = []
    # Exact matches are O(1) set lookups
    for cfg in _EXACT_CI_PATHS:
        if cfg in file_tree:
            detected.append(cfg)

    # Directory prefix matches: single pass through file_tree
    for path in file_tree:
        for prefix in _DIR_CI_PREFIXES:
            if path.startswith(prefix):
                cfg = prefix.rstrip("/")
                if cfg not in detected:
                    detected.append(cfg)
                break  # this path matched; move to next file_tree entry

    if not detected:
        return 0, []
    score = 20 if any(".github/workflows" in d for d in detected) else 15
    return score, detected


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class AxiosSupplyChainPlugin(ScanPlugin):
    """Detect exposure to the axios npm supply chain compromise (2026-03-31)."""

    def metadata(self) -> PluginMeta:
        return PluginMeta(
            name="axios-supply-chain",
            description="Detect exposure to the axios npm supply chain compromise (2026-03-31)",
            version="1.0.0",
            author="ghscan contributors",
            category="supply-chain",
            severity="critical",
            tags=["npm", "supply-chain", "axios", "incident-response"],
        )

    def file_requests(self) -> List[FileRequest]:
        return [
            FileRequest(path="package.json", subdirs=TARGET_SUBDIRS),
            FileRequest(path="package-lock.json", subdirs=TARGET_SUBDIRS),
            FileRequest(path="yarn.lock", subdirs=TARGET_SUBDIRS),
            FileRequest(path="pnpm-lock.yaml", subdirs=TARGET_SUBDIRS),
        ]

    def should_scan_repo(self, repo_info: dict, file_tree: Optional[Set[str]]) -> bool:
        if file_tree is not None:
            # O(1) check for root-level package.json first
            if "package.json" in file_tree:
                return True
            # Check known subdirs before falling back to full scan
            for subdir in TARGET_SUBDIRS:
                if subdir and f"{subdir}/package.json" in file_tree:
                    return True
            return False
        return True

    def evaluate(self, repo_info: dict, files: Dict[str, Optional[str]],
                 file_tree: Optional[Set[str]]) -> List[PluginFinding]:
        pushed_at = repo_info.get("pushed_at", "")

        # 1. Find axios specs in package.json files
        axios_entries = []
        dirs_with_axios = set()

        for subdir in TARGET_SUBDIRS:
            path = f"{subdir}/package.json" if subdir else "package.json"
            content = files.get(path)
            if content is None:
                continue
            for section, spec in _extract_axios_specs(content):
                score, reason = _range_can_resolve_bad(spec)
                if score == 0:
                    continue
                axios_entries.append({
                    "file": path,
                    "section": section,
                    "spec": spec,
                    "range_score": score,
                    "range_reason": reason,
                })
                pkg_dir = os.path.dirname(path)
                dirs_with_axios.add(pkg_dir)

        if not axios_entries:
            return []

        best = max(axios_entries, key=lambda e: e["range_score"])
        range_score = best["range_score"]

        # 2. Find lockfile in directories where axios was found
        lockfile_ver = None
        lockfile_file = None

        for search_dir in sorted(dirs_with_axios):
            for lf_name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                lf_path = f"{search_dir}/{lf_name}".lstrip("/") if search_dir else lf_name
                content = files.get(lf_path)
                if content is not None:
                    ver = _extract_lockfile_axios_version(content, lf_name)
                    if ver:
                        lockfile_ver = ver
                        lockfile_file = lf_path
                        break
            if lockfile_ver:
                break

        lf_score, lf_reason = _lockfile_score(lockfile_ver)

        # 3. CI detection
        ci_score, ci_configs = _detect_ci(file_tree)

        # 4. Activity score
        act_score, act_reason = _activity_score(pushed_at)

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

        severity = tier.lower()

        return [PluginFinding(
            plugin_name="axios-supply-chain",
            severity=severity,
            title=f"axios supply chain exposure ({tier})",
            score=total,
            details={
                "tier": tier,
                "total_score": total,
                "scoring": {
                    "range_score": range_score,
                    "range_reason": best["range_reason"],
                    "lf_score": lf_score,
                    "lf_reason": lf_reason,
                    "ci_score": ci_score,
                    "ci_configs": ci_configs,
                    "act_score": act_score,
                    "act_reason": act_reason,
                },
                "axios_entries": axios_entries,
                "lockfile_file": lockfile_file,
                "lockfile_ver": lockfile_ver,
                "guidance": TIER_GUIDANCE.get(tier, ""),
            },
            recommendations=[
                TIER_GUIDANCE.get(tier, "Review build logs for the attack window."),
            ],
        )]
