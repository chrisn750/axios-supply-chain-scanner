"""
argparse-based CLI for non-interactive / scripted usage.
"""

import argparse
import os
import sys

from ghscan import __version__
from ghscan.plugin_api.loader import discover_plugins


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ghscan",
        description="GitHub Organization Security Scanner — plugin-based repo scanning tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version", action="version", version=f"ghscan {__version__}",
    )
    parser.add_argument(
        "--org", default=None,
        help="GitHub organization name to scan (e.g., my-org)",
    )
    parser.add_argument(
        "--token", default=os.getenv("GITHUB_TOKEN"),
        help="GitHub personal access token. Falls back to $GITHUB_TOKEN env var.",
    )
    parser.add_argument(
        "--output", default="scan_results.json",
        help="Path to write results (default: scan_results.json)",
    )
    parser.add_argument(
        "--format", choices=["json", "csv", "terminal"], default="json",
        dest="output_format",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--workers", type=int, default=5,
        help="Number of concurrent scanning threads (default: 5, max: 15)",
    )
    parser.add_argument(
        "--plugins", default="all",
        help="Comma-separated plugin names to use, or 'all' (default: all)",
    )
    parser.add_argument(
        "--list-plugins", action="store_true",
        help="List available plugins and exit",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show scan configuration without running",
    )
    parser.add_argument(
        "--no-interactive", action="store_true",
        help="Disable interactive mode (use CLI args only)",
    )
    return parser


def resolve_plugins(plugin_arg):
    """
    Resolve the --plugins argument to a list of plugin instances.
    Returns (plugins_list, error_message).
    """
    discovered = discover_plugins()
    all_plugins = [plugin for _category, plugin in discovered]

    if not all_plugins:
        return [], "No plugins found in plugins directory."

    if plugin_arg == "all":
        return all_plugins, None

    requested = {name.strip() for name in plugin_arg.split(",")}
    selected = []
    found_names = set()

    for plugin in all_plugins:
        meta = plugin.metadata()
        if meta.name in requested:
            selected.append(plugin)
            found_names.add(meta.name)

    missing = requested - found_names
    if missing:
        return selected, f"Warning: plugins not found: {', '.join(sorted(missing))}"

    return selected, None


def list_plugins_and_exit():
    """Print available plugins and exit."""
    discovered = discover_plugins()
    if not discovered:
        print("No plugins found.")
        sys.exit(0)

    categories = {}
    for category, plugin in discovered:
        if category not in categories:
            categories[category] = []
        categories[category].append(plugin)

    print("\nAvailable plugins:\n")
    for category, plugins in sorted(categories.items()):
        print(f"  {category}/")
        for plugin in plugins:
            meta = plugin.metadata()
            print(f"    {meta.name:25s} {meta.description:50s} v{meta.version}")
        print()
    sys.exit(0)


def parse_args():
    """
    Parse CLI arguments and return a config dict compatible with run_scan().
    Returns None if validation fails.
    """
    parser = build_parser()
    args = parser.parse_args()

    if args.list_plugins:
        list_plugins_and_exit()

    if not args.token:
        print("[ERROR] GitHub token required.")
        print("  Set the GITHUB_TOKEN environment variable or pass --token.")
        sys.exit(1)

    args.workers = max(1, min(args.workers, 15))

    if not args.org and not args.dry_run:
        print("[ERROR] --org is required. Specify a GitHub organization to scan.")
        sys.exit(1)

    if args.output_format != "terminal":
        args.output = os.path.realpath(args.output)
    else:
        args.output = ""

    plugins, error = resolve_plugins(args.plugins)
    if error and not plugins:
        print(f"[ERROR] {error}")
        sys.exit(1)
    if error:
        print(f"[WARN] {error}")

    if not plugins:
        print("[ERROR] No plugins selected.")
        sys.exit(1)

    if args.dry_run:
        print("\n[DRY RUN] Scan configuration:")
        print(f"  Org      : {args.org}")
        print(f"  Plugins  : {', '.join(p.metadata().name for p in plugins)}")
        print(f"  Workers  : {args.workers}")
        print(f"  Output   : {args.output or 'terminal only'} ({args.output_format})")
        print(f"  Verbose  : {args.verbose}")
        print("\nNo scan performed.")
        sys.exit(0)

    return {
        "token": args.token,
        "org": args.org,
        "plugins": plugins,
        "workers": args.workers,
        "output_format": args.output_format,
        "output_file": args.output,
        "verbose": args.verbose,
        "quiet": args.quiet,
    }
