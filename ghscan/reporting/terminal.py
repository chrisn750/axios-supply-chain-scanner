"""
Terminal report renderer — colored output with per-plugin detail sections.
"""

from datetime import datetime, timezone

from ghscan.cli.colors import (
    bold, bold_cyan, bold_green, bold_red, bold_yellow, cyan, dim, green,
    red, severity_color, yellow,
)
from ghscan.core.results import aggregate_summary


SEVERITY_EMOJI = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\u26aa",
    "info": "\U0001f535",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def print_report(findings, org, plugins):
    """Print a colored terminal report of scan findings."""
    if not findings:
        print(f"\n  {bold_green('No findings')} across any active repos.")
        return

    # Sort by max severity then max score descending
    findings_sorted = sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("max_severity", "info"), 9),
            -f.get("max_score", 0),
        ),
    )

    summary = aggregate_summary(findings)
    sev_counts = summary["by_severity"]
    plugin_counts = summary["by_plugin"]

    print()
    print("=" * 72)
    print(bold_cyan("  GHSCAN SECURITY SCAN RESULTS"))
    print(f"  Org       : github.com/{org}")
    print(f"  Timestamp : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Plugins   : {', '.join(p.metadata().name for p in plugins)}")
    print("=" * 72)

    # Severity summary
    print()
    for sev in ("critical", "high", "medium", "low", "info"):
        count = sev_counts.get(sev, 0)
        emoji = SEVERITY_EMOJI.get(sev, "")
        label = severity_color(sev, f"{sev.upper():10s}")
        print(f"  {emoji} {label}: {count:3d}")

    # Per-plugin breakdown
    if len(plugin_counts) > 1:
        print(f"\n  {bold('By plugin:')}")
        for pname, count in sorted(plugin_counts.items()):
            print(f"    {pname}: {count} finding(s)")

    print(f"\n  Total repos with findings: {bold(str(len(findings)))}")

    # Detail per repo
    current_sev = None
    for result in findings_sorted:
        max_sev = result.get("max_severity", "info")

        if max_sev != current_sev:
            current_sev = max_sev
            print(f"\n  {'~' * 68}")
            emoji = SEVERITY_EMOJI.get(current_sev, "")
            print(f"  {emoji} {severity_color(current_sev, current_sev.upper())}")
            print(f"  {'~' * 68}")

        print(f"\n  {bold(result['repo'])}")
        print(f"  URL    : {result['url']}")
        print(f"  Pushed : {result.get('pushed_at', 'unknown')}")

        for finding in result.get("findings", []):
            pname = finding.get("plugin_name", "unknown")
            sev = finding.get("severity", "info")
            score = finding.get("score", 0)
            title = finding.get("title", "")

            emoji = SEVERITY_EMOJI.get(sev, "")
            print(f"\n    {emoji} [{score:3d}] {severity_color(sev, title)}  ({dim(pname)})")

            details = finding.get("details", {})
            scoring = details.get("scoring")
            if scoring:
                print(f"    Score breakdown:")
                print(f"      Range  {scoring.get('range_score', 0):2d}/40  {scoring.get('range_reason', '')}")
                print(f"      Lock   {scoring.get('lf_score', 0):2d}/30  {scoring.get('lf_reason', '')}")
                ci_label = (
                    "configs: " + ", ".join(scoring.get("ci_configs", []))
                ) if scoring.get("ci_configs") else "no CI config detected"
                print(f"      CI     {scoring.get('ci_score', 0):2d}/20  {ci_label}")
                print(f"      Active {scoring.get('act_score', 0):2d}/10  {scoring.get('act_reason', '')}")

            axios_entries = details.get("axios_entries")
            if axios_entries:
                print(f"    Axios entries:")
                for entry in axios_entries:
                    print(f"      {entry['file']} -> {entry['section']}[\"axios\"] = \"{entry['spec']}\"")

            lf_file = details.get("lockfile_file")
            if lf_file:
                print(f"    Lockfile : {lf_file} pins axios@{details.get('lockfile_ver')}")
            elif "lockfile_file" in details:
                print(f"    Lockfile : none found")

            recs = finding.get("recommendations", [])
            if recs:
                print(f"    Guidance:")
                for rec in recs:
                    for line in rec.split("\n"):
                        print(f"      {line}")

    print(f"\n  {'~' * 68}")
    print(dim("  NOTE: A clean result does not mean a repo was unaffected."))
    print(dim("  Build log review is the only definitive clearance method."))
    print("=" * 72)
