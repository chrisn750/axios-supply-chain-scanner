"""
Interactive CLI wizard — step-by-step guided setup for ghscan.
"""

import os
import sys

from ghscan import __version__
from ghscan.cli.colors import (
    bold, bold_cyan, bold_green, bold_red, bold_yellow, cyan, dim, green, yellow,
)
from ghscan.config import load_config, save_config
from ghscan.core.github_client import validate_token
from ghscan.plugin_api.loader import discover_plugins


BANNER = r"""
   ╔═══════════════════════════════════════════════════════╗
   ║                                                       ║
   ║    ██████╗ ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗ ║
   ║   ██╔════╝ ██║  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║ ║
   ║   ██║  ███╗███████║███████╗██║     ███████║██╔██╗ ██║  ║
   ║   ██║   ██║██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║  ║
   ║   ╚██████╔╝██║  ██║███████║╚██████╗██║  ██║██║ ╚████║  ║
   ║    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝║
   ║                                                       ║
   ║        GitHub Organization Security Scanner           ║
   ║                                                       ║
   ╚═══════════════════════════════════════════════════════╝
"""


def _prompt(message, default=None):
    """Prompt user for input with an optional default."""
    if default is not None:
        suffix = f" [{default}]: "
    else:
        suffix = ": "
    try:
        value = input(f"  {message}{suffix}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return value if value else default


def _prompt_int(message, default, min_val=1, max_val=100):
    """Prompt for an integer within bounds."""
    while True:
        raw = _prompt(message, str(default))
        try:
            val = int(raw)
            if min_val <= val <= max_val:
                return val
            print(f"    {yellow(f'Please enter a number between {min_val} and {max_val}.')}")
        except (ValueError, TypeError):
            print(f"    {yellow('Please enter a valid number.')}")


def _prompt_choice(message, choices, default=None):
    """Prompt user to choose from a list of options."""
    choices_str = "/".join(choices)
    while True:
        raw = _prompt(f"{message} ({choices_str})", default)
        if raw and raw.lower() in [c.lower() for c in choices]:
            return raw.lower()
        print(f"    {yellow(f'Please choose one of: {choices_str}')}")


def run_interactive():
    """
    Run the interactive setup wizard.
    Returns a config dict with all settings needed to run a scan, or None to abort.
    """
    config = load_config()

    # Banner
    print(bold_cyan(BANNER))
    print(f"  {dim(f'v{__version__}')}\n")

    # Step 1: GitHub Token
    print(bold("  [1/5] GitHub Authentication"))
    print(dim("  A GitHub personal access token is required to scan repositories."))
    print(dim("  Scopes needed: public_repo (public only) or repo (includes private)"))
    print()

    token_env = config.get("token_env_var", "GITHUB_TOKEN")
    env_token = os.environ.get(token_env, "")

    if env_token:
        print(f"  Found token in ${token_env} environment variable.")
        use_env = _prompt("Use this token? (y/n)", "y")
        if use_env.lower() == "y":
            token = env_token
        else:
            token = _prompt("Enter GitHub token")
    else:
        print(f"  No token found in ${token_env}.")
        token = _prompt("Enter GitHub personal access token")

    if not token:
        print(bold_red("\n  Error: GitHub token is required."))
        return None

    # Validate token
    print(f"  Validating token...", end=" ", flush=True)
    ok, username, rate_limit = validate_token(token)
    if ok:
        print(bold_green(f"authenticated as @{username} ({rate_limit} req/hr)"))
    else:
        print(bold_red(f"failed ({username})"))
        print(bold_red("  Cannot proceed without a valid token."))
        return None

    print()

    # Step 2: Organization
    print(bold("  [2/5] Target Organization"))
    org = _prompt("GitHub org to scan")
    if not org:
        print(bold_red("\n  Error: Organization name is required."))
        return None
    print()

    # Step 3: Plugin Selection
    print(bold("  [3/5] Plugin Selection"))
    print(dim("  Scanning for available plugins...\n"))

    discovered = discover_plugins()
    if not discovered:
        print(bold_red("  No plugins found! Cannot scan without plugins."))
        return None

    # Group by category
    categories = {}
    plugin_list = []
    idx = 1
    for category, plugin in discovered:
        if category not in categories:
            categories[category] = []
        meta = plugin.metadata()
        categories[category].append((idx, plugin))
        plugin_list.append(plugin)
        idx += 1

    for category, items in sorted(categories.items()):
        print(f"  {bold(category)}/")
        for num, plugin in items:
            meta = plugin.metadata()
            sev_label = meta.severity.upper() if meta.severity else ""
            print(f"    [{num}] {meta.name:25s} {dim(meta.description):50s} v{meta.version}  {dim(sev_label)}")
        print()

    selection = _prompt(
        "Enter plugin numbers (comma-separated), 'all', or press Enter for all",
        "all",
    )

    if selection.lower() == "all":
        selected_plugins = plugin_list
    else:
        selected_plugins = []
        try:
            indices = [int(x.strip()) for x in selection.split(",")]
            for i in indices:
                if 1 <= i <= len(plugin_list):
                    selected_plugins.append(plugin_list[i - 1])
                else:
                    print(yellow(f"    Skipping invalid index: {i}"))
        except ValueError:
            print(yellow("    Could not parse selection. Using all plugins."))
            selected_plugins = plugin_list

    if not selected_plugins:
        print(bold_red("  No plugins selected. Cannot scan."))
        return None

    plugin_names = [p.metadata().name for p in selected_plugins]
    print(f"  {bold_green(f'{len(selected_plugins)} plugin(s) selected')}: {', '.join(plugin_names)}")
    print()

    # Step 4: Configuration
    print(bold("  [4/5] Scan Configuration"))
    workers = _prompt_int("Worker threads (1-15)", config.get("workers", 5), 1, 15)
    output_format = _prompt_choice(
        "Output format", ["json", "csv", "terminal"],
        config.get("output_format", "json"),
    )

    default_output = config.get("output_file", "scan_results.json")
    if output_format == "csv":
        default_output = default_output.rsplit(".", 1)[0] + ".csv"
    elif output_format == "terminal":
        default_output = ""

    if output_format != "terminal":
        output_file = _prompt("Output file", default_output)
    else:
        output_file = ""

    verbose = _prompt_choice("Verbose mode?", ["y", "n"], "n") == "y"
    print()

    # Step 5: Confirmation
    print(bold("  [5/5] Review & Launch"))
    print(f"  Org      : {bold(org)}")
    print(f"  Plugins  : {', '.join(plugin_names)}")
    print(f"  Workers  : {workers}")
    if output_file:
        print(f"  Output   : {output_file} ({output_format.upper()})")
    else:
        print(f"  Output   : terminal only")
    print(f"  Verbose  : {'yes' if verbose else 'no'}")
    print()

    try:
        input(f"  {bold('Press Enter to start, or Ctrl+C to abort...')}")
    except (EOFError, KeyboardInterrupt):
        print(bold_yellow("\n\n  Scan aborted."))
        return None

    # Offer to save preferences
    save_prefs = _prompt("Save these preferences for next time? (y/n)", "n")
    if save_prefs.lower() == "y":
        prefs = {
            "token_env_var": token_env,
            "workers": workers,
            "output_format": output_format,
            "output_file": output_file or "scan_results.json",
            "default_plugins": "all" if len(selected_plugins) == len(plugin_list) else ",".join(plugin_names),
        }
        if save_config(prefs):
            print(dim("  Preferences saved to ~/.ghscan.json"))
        else:
            print(yellow("  Could not save preferences."))
    print()

    return {
        "token": token,
        "org": org,
        "plugins": selected_plugins,
        "workers": workers,
        "output_format": output_format,
        "output_file": output_file,
        "verbose": verbose,
    }
