"""
Entry point for `python -m ghscan`.
"""

import os
import sys

from ghscan import __version__
from ghscan.cli.colors import bold, bold_cyan, dim
from ghscan.core.scanner import scan_org
from ghscan.core.checkpoint import clear_progress
from ghscan.reporting.terminal import print_report
from ghscan.reporting.json_report import save_json
from ghscan.reporting.csv_report import save_csv


def run_scan(config):
    """Execute the scan with the given configuration dict."""
    token = config["token"]
    org = config["org"]
    plugins = config["plugins"]
    workers = config["workers"]
    output_format = config["output_format"]
    output_file = config["output_file"]
    verbose = config.get("verbose", False)

    # Print scan header
    print()
    print(bold_cyan("[GHSCAN]") + f" GitHub Organization Security Scanner v{__version__}")
    print(f"  Org      : https://github.com/{org}/")
    print(f"  Plugins  : {', '.join(p.metadata().name for p in plugins)}")
    print(f"  Workers  : {workers}")
    if output_file:
        print(f"  Output   : {output_file} ({output_format.upper()})")
    else:
        print(f"  Output   : terminal only")
    print()

    # Determine output path for checkpointing
    checkpoint_path = output_file if output_file else os.path.join(
        os.getcwd(), ".ghscan_checkpoint.json"
    )

    # Run the scan
    findings = scan_org(
        org=org,
        token=token,
        output_path=checkpoint_path,
        plugins=plugins,
        max_workers=workers,
        verbose=verbose,
    )

    # Report results
    print_report(findings, org, plugins)

    # Write output file
    if output_file:
        if output_format == "json":
            save_json(findings, output_file, org, plugins)
        elif output_format == "csv":
            save_csv(findings, output_file)

    # Clear checkpoint
    clear_progress(checkpoint_path)
    print(dim("\n  [DONE] Progress file cleared.\n"))


def main():
    """Main entry point — decides between interactive and CLI mode."""
    # If no arguments beyond the script name, or explicitly no --org, use interactive
    has_args = len(sys.argv) > 1

    if has_args:
        # Check for --no-interactive or the presence of --org
        from ghscan.cli.args import parse_args
        config = parse_args()
        if config is None:
            sys.exit(1)
    else:
        # Interactive mode
        from ghscan.cli.interactive import run_interactive
        config = run_interactive()
        if config is None:
            sys.exit(0)

    run_scan(config)


if __name__ == "__main__":
    main()
