"""
JSON report writer.
"""

import json
from datetime import datetime, timezone

from ghscan.core.results import aggregate_summary


def save_json(findings, output_path, org, plugins):
    """Write scan results to a JSON file."""
    findings_sorted = sorted(
        findings,
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                f.get("max_severity", "info"), 9
            ),
            -f.get("max_score", 0),
        ),
    )

    summary = aggregate_summary(findings)

    out = {
        "scan_metadata": {
            "org": org,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "plugins": [p.metadata().name for p in plugins],
            "plugin_versions": {
                p.metadata().name: p.metadata().version for p in plugins
            },
        },
        "summary": summary,
        "findings": findings_sorted,
    }

    with open(output_path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"  [OUTPUT] JSON results written to {output_path}")
