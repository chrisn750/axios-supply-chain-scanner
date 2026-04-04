"""
Scan result data structures and aggregation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class RepoScanResult:
    """Aggregated scan result for a single repo across all plugins."""
    repo: str
    repo_id: int
    url: str
    default_branch: str
    pushed_at: str
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def max_score(self):
        if not self.findings:
            return 0
        return max(f.get("score", 0) for f in self.findings)

    @property
    def max_severity(self):
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if not self.findings:
            return "info"
        return max(
            (f.get("severity", "info") for f in self.findings),
            key=lambda s: severity_order.get(s, 0)
        )

    def to_dict(self):
        return {
            "repo": self.repo,
            "repo_id": self.repo_id,
            "url": self.url,
            "default_branch": self.default_branch,
            "pushed_at": self.pushed_at,
            "scanned_at": self.scanned_at,
            "max_score": self.max_score,
            "max_severity": self.max_severity,
            "findings": self.findings,
        }


def aggregate_summary(all_results):
    """Build a summary dict from a list of RepoScanResult dicts."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    plugin_counts = {}

    for result in all_results:
        for finding in result.get("findings", []):
            sev = finding.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            pname = finding.get("plugin_name", "unknown")
            plugin_counts[pname] = plugin_counts.get(pname, 0) + 1

    return {
        "total_repos_with_findings": len(all_results),
        "by_severity": severity_counts,
        "by_plugin": plugin_counts,
    }
