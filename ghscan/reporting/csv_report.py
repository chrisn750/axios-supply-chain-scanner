"""
CSV report writer.
"""

import csv


def save_csv(findings, output_path):
    """Write scan results to a CSV file — one row per finding."""
    rows = []
    for result in findings:
        for finding in result.get("findings", []):
            rows.append({
                "repo": result.get("repo", ""),
                "url": result.get("url", ""),
                "pushed_at": result.get("pushed_at", ""),
                "plugin": finding.get("plugin_name", ""),
                "severity": finding.get("severity", ""),
                "score": finding.get("score", 0),
                "title": finding.get("title", ""),
            })

    if not rows:
        print(f"  [OUTPUT] No findings to write to CSV.")
        return

    fieldnames = ["repo", "url", "pushed_at", "plugin", "severity", "score", "title"]
    try:
        with open(output_path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"  [OUTPUT] CSV results written to {output_path}")
    except (IOError, OSError) as e:
        print(f"  [ERROR] Failed to write CSV report to {output_path}: {e}")
