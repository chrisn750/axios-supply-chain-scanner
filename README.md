# axios Supply Chain Exposure Scanner

**IR triage tool for the axios npm supply chain compromise (March 31, 2026)**

Scans a GitHub organization's repositories to identify which ones could have resolved the malicious `axios@1.14.1` or `axios@0.30.4` packages during the ~3-hour attack window, so your team knows which CI/CD build logs to pull first.

> This tool identifies *exposure*, not *compromise*. The malicious versions self-destructed after execution — no artifacts remain in source. Build log review is the only definitive clearance method.

---

## Background

On March 31, 2026 (00:21–03:30 UTC), threat actor UNC1069 published two compromised versions of the `axios` npm package:

| Version | Lineage | Duration on registry |
|---|---|---|
| `1.14.1` | Latest 1.x release | ~3 hours |
| `0.30.4` | Latest 0.x release | ~3 hours |

Any CI/CD pipeline that ran `npm install` (not `npm ci`) with a loose version range during this window would have resolved the malicious version. The payload exfiltrated environment variables and secrets to `sfrclak.com:8000` / `142.11.206.73`, then deleted itself from `node_modules`.

Because the malware is not present in source trees or lockfiles after the fact, the only way to confirm whether a repo was affected is to review CI build logs from the attack window for lines like `added axios 1.14.1`.

This scanner identifies which repos to check first.

---

## Quick start

```bash
# Install dependencies
pip install requests
pip install pyyaml  # optional — improves pnpm-lock.yaml parsing

# Set your GitHub token
export GITHUB_TOKEN=ghp_your_token_here

# Scan an org
python3 axios-supply-chain-scanner.py --org my-org
```

Results are written to `axios_exposure.json` and printed to the terminal.

### Required token scopes

| Scope | Covers |
|---|---|
| `public_repo` | Public repositories only |
| `repo` | Public + private repositories |

Generate a token at [github.com/settings/tokens](https://github.com/settings/tokens).

---

## How it works

For each non-archived repository in the org, the scanner:

1. **Fetches the file tree** in a single API call (Git Trees API) to determine which files exist without per-file round trips.
2. **Reads `package.json`** in the root and common subdirectories (`app/`, `src/`, `client/`, `server/`, `frontend/`, `backend/`, `api/`) looking for `axios` in any dependency section.
3. **Evaluates the version spec** against the two compromised versions. Handles carets, tildes, wildcards, x-ranges, `>=`/`<`/`<=`/`>` comparisons, hyphen ranges, OR ranges (`||`), AND ranges (space-separated), and pre-release tags.
4. **Checks for lockfiles** (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) in the same directories where axios was found, and extracts the pinned axios version if present.
5. **Detects CI/CD configuration** (GitHub Actions, Jenkins, Travis, CircleCI, Azure Pipelines, GitLab CI, Bitbucket Pipelines, Dockerfile, docker-compose) using the tree data — no additional API calls.
6. **Scores repo activity** based on `pushed_at` relative to the attack window, with asymmetric weighting (repos pushed *after* the window score higher than those pushed the same distance *before*).

Repos without axios in any dependency section are skipped entirely.

---

## Scoring model

Each repo with axios exposure is scored 0–100 across four dimensions:

| Component | Max | What it measures |
|---|---|---|
| **Range risk** | 40 | Could the version spec resolve to a compromised version? |
| **Lockfile factor** | 30 | Is there a lockfile? What version does it pin? |
| **CI/CD detected** | 20 | Are pipeline configs present in the repo? |
| **Activity** | 10 | Was the repo actively being built around March 31? |

### Tier thresholds

| Tier | Score | Interpretation |
|---|---|---|
| 🔴 CRITICAL | 75–100 | High confidence CI resolved the bad version. Pull build logs immediately. |
| 🟠 HIGH | 50–74 | Meaningful exposure. Check whether CI used `npm install` vs `npm ci`. |
| 🟡 MEDIUM | 25–49 | Possible exposure. Review after CRITICAL and HIGH are cleared. |
| ⚪ LOW | 0–24 | Unlikely affected. Verify and deprioritize. |

### Scoring details

**Range risk (0–40)**

| Spec pattern | Score | Example |
|---|---|---|
| Exact pin to bad version | 40 | `1.14.1` |
| Wildcard / latest | 38 | `*`, `latest` |
| Caret/tilde/x-range including bad version | 35 | `^1.13.0`, `~0.30.0`, `1.14.x` |
| Open-ended `>=` including bad version | 25 | `>=1.0.0` |
| `<`/`<=` including bad version | 20 | `<2.0.0` |
| Git/URL spec (unknowable) | 15 | `git+https://...` |
| Unrecognized (flagged for manual review) | 15 | complex or unusual spec |
| Definitively excludes both bad versions | 0 | `^2.0.0`, `1.13.0` |

**Lockfile factor (0–30)**

| Condition | Score |
|---|---|
| No lockfile found | 30 |
| Lockfile pins a compromised version | 30 |
| Lockfile pins an adjacent safe version (1.14.0, 0.30.3) | 15 |
| Lockfile pins any other version | 5 |

A lockfile pinning a safe version is only protective if CI used `npm ci`. If CI used `npm install`, the lockfile may have been ignored.

**CI/CD detected (0–20)**

| Condition | Score |
|---|---|
| GitHub Actions workflows found | 20 |
| Other CI config found | 15 |
| No CI config detected | 0 |

**Activity (0–10)**

| Condition | Score |
|---|---|
| Pushed during the attack window | 10 |
| Pushed ≤7 days before or after | 10 |
| Pushed 8–30 days after | 7 |
| Pushed 8–30 days before | 6 |
| Pushed 31–90 days before | 3 |
| Pushed >30 days after | 4 |
| Pushed >90 days before | 0 |

---

## CLI reference

```
python3 axios-supply-chain-scanner.py --org <ORG> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--org` | *(required)* | GitHub organization name |
| `--token` | `$GITHUB_TOKEN` | GitHub personal access token |
| `--output` | `axios_exposure.json` | Path for JSON results |
| `--workers` | `5` | Concurrent scanning threads (1–15) |
| `--subdirs` | `'' app src client server frontend backend api` | Subdirectories to check for `package.json` |
| `--ci-paths` | *(built-in list)* | CI config paths to detect |

### Examples

```bash
# Scan with more parallelism
python3 axios-supply-chain-scanner.py --org my-org --workers 10

# Scan only root and frontend directories
python3 axios-supply-chain-scanner.py --org my-org --subdirs '' frontend client

# Write results to a specific path
python3 axios-supply-chain-scanner.py --org my-org --output /tmp/scan-results.json

# Use a specific token
python3 axios-supply-chain-scanner.py --org my-org --token ghp_abc123
```

---

## Output format

### Terminal output

The scanner prints a prioritized report grouped by tier, with score breakdowns and actionable guidance for each tier. Example:

```
  [CHECKPOINT] Saved (50/120 repos scanned)

  🔴 CRITICAL — Pull CI/CD build logs for 2026-03-31 00:21-03:30 UTC.
  ──────────────────────────────────────────────────────────────────────

  [ 85/100] my-org/web-app
  URL    : https://github.com/my-org/web-app
  Pushed : 2026-03-31T02:15:00Z
  Score breakdown:
    Range  35/40  ^1.13.0 resolves <2.0.0, includes 1.14.1
    Lock   30/30  no lockfile — every npm install does fresh resolution
    CI     20/20  configs: .github/workflows
    Active 10/10  pushed during the attack window
  Axios entries:
    package.json → dependencies["axios"] = "^1.13.0"
  Lockfile : none found
```

### JSON output

The JSON file contains machine-readable results suitable for ingestion into SIEM, ticketing, or orchestration systems:

```json
{
  "scan_metadata": {
    "org": "my-org",
    "timestamp_utc": "2026-04-01T15:30:00+00:00",
    "attack_window_utc": "2026-03-31T00:21:00Z to 2026-03-31T03:30:00Z",
    "bad_versions": ["0.30.4", "1.14.1"],
    "purpose": "IR triage — identifies repos for CI log review, not confirmed compromise"
  },
  "summary": {
    "total_exposed_repos": 12,
    "by_tier": {
      "CRITICAL": 2,
      "HIGH": 4,
      "MEDIUM": 3,
      "LOW": 3
    }
  },
  "findings": [
    {
      "repo": "my-org/web-app",
      "repo_id": 123456789,
      "url": "https://github.com/my-org/web-app",
      "default_branch": "main",
      "pushed_at": "2026-03-31T02:15:00Z",
      "scanned_at": "2026-04-01T15:30:12+00:00",
      "tier": "CRITICAL",
      "total_score": 85,
      "scoring": { ... },
      "axios_entries": [ ... ],
      "lockfile_file": null,
      "lockfile_ver": null
    }
  ]
}
```

Each finding includes `repo_id` (GitHub's numeric ID) and `scanned_at` (ISO 8601) for deduplication and audit trails.

---

## Resume and checkpointing

Progress is saved every 25 repos to `<output>.progress.json`. If the scan is interrupted, rerun the same command to resume from where it left off:

```bash
# These two invocations together scan all repos exactly once
python3 axios-supply-chain-scanner.py --org my-org --output results.json
# (interrupted)
python3 axios-supply-chain-scanner.py --org my-org --output results.json
# (resumes from checkpoint)
```

Checkpoint writes are atomic (temp file → fsync → rename) to prevent corruption if the process is killed mid-write. The progress file is deleted automatically on successful completion.

---

## Performance

The scanner is optimized to minimize GitHub API calls:

| Optimization | Effect |
|---|---|
| Git Trees API | Fetches the entire file tree in 1 call per repo. Repos without any `package.json` are skipped with zero content fetches. |
| Tree-based existence checks | CI detection and lockfile search use tree data instead of per-file API calls. |
| Concurrent workers | `--workers` controls parallelism (default 5). Shared rate limiter prevents exceeding GitHub's 5,000 req/hour budget. |
| Early exit | Repos with no `package.json`, no axios dependency, or only safe version pins are skipped as early as possible. |

**Typical API calls per repo:**

| Repo type | Calls |
|---|---|
| No `package.json` anywhere | 1 (tree only) |
| Has `package.json` but no axios | 2–3 (tree + 1–2 content fetches) |
| Has axios with lockfile | 3–5 (tree + package.json + lockfile) |
| Truncated tree (very large repo) | Falls back to per-file approach (~10–40 calls) |

For a 500-repo mixed-language org where ~20% of repos use Node.js and ~5% use axios, expect roughly 1,500–2,500 API calls total — well within the hourly rate limit, finishing in under 10 minutes with 5 workers.

---

## Limitations

**What this tool does not do:**

- **Confirm compromise.** A CRITICAL score means "check the build logs," not "this repo was compromised." Build log review is the only definitive method.
- **Scan build logs.** It identifies *which* repos to investigate. Pulling and parsing CI logs is a separate step.
- **Detect transitive dependencies.** If axios is pulled in transitively by another package, this scanner won't find it unless it also appears in a lockfile. Use `npm ls axios` or `npm audit` on individual repos for transitive analysis.
- **Scan non-GitHub hosting.** Only GitHub organizations are supported via the REST API.
- **Guarantee complete coverage.** Monorepos with deeply nested `package.json` files outside the checked subdirectories may be missed. Use `--subdirs` to add custom paths.

**Known edge cases in version scoring:**

- AND ranges (`>=1.0.0 <2.0.0`) are evaluated using intersection semantics: if any component definitively excludes both bad versions, the range scores 0. This is correct but may undercount in rare cases where the component analysis is individually ambiguous but the intersection is safe.
- Pre-release tags (`1.14.1-beta.1`) are matched by their base version. In npm semver, pre-releases of `1.14.1` sort *before* `1.14.1` and are only matched by ranges that explicitly include pre-release comparators — the scanner may slightly over-flag these.
- The pnpm-lock.yaml parser uses `pyyaml` when available for structured parsing and falls back to regex. The regex fallback is conservative and may miss unusual lockfile layouts. Install `pyyaml` for best coverage.

---

## Security considerations

- **Token handling.** The GitHub token is passed via environment variable (preferred) or `--token` CLI flag. It is never logged, printed, or written to output files. Per-thread sessions use `Authorization` headers that are not exposed in standard exception tracebacks.
- **Output files.** Results are written using `json.dump()` to the path specified by `--output`, which is resolved via `os.path.realpath()` before use. No user-controlled data is interpolated into file paths.
- **No outbound connections** other than `api.github.com`. The tool does not phone home, fetch external resources, or resolve any npm packages.

---

## Dependencies

| Package | Required | Purpose |
|---|---|---|
| `requests` | Yes | GitHub API HTTP calls |
| `pyyaml` | No | Structured parsing of `pnpm-lock.yaml` (falls back to regex) |

Standard library modules used: `argparse`, `base64`, `json`, `os`, `re`, `sys`, `tempfile`, `threading`, `time`, `concurrent.futures`, `datetime`, `urllib.parse`.

Python 3.8+ required.

---

## What to do with results

### CRITICAL tier

1. Pull CI/CD build logs for the attack window (2026-03-31 00:21–03:30 UTC).
2. Search logs for `added axios 1.14.1` or `added axios 0.30.4`.
3. If found: escalate to full incident response — rotate all secrets accessible to the build environment, audit outbound connections to `sfrclak.com:8000` / `142.11.206.73`.

### HIGH tier

1. Determine whether CI used `npm install` (vulnerable) or `npm ci` (safer).
2. If `npm install`: treat as CRITICAL.
3. If `npm ci` with a lockfile pinning a safe version: lower priority but still verify.

### MEDIUM tier

1. Confirm whether any CI builds ran during the window.
2. Review after CRITICAL and HIGH repos are cleared.

### LOW tier

1. Verify and close after higher tiers are cleared.

---

## License

Internal IR tooling. Adjust as appropriate for your organization's distribution policies.
