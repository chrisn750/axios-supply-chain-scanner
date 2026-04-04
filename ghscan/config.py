"""
Config file management — load/save user preferences to ~/.ghscan.json.
"""

import json
import os

CONFIG_PATH = os.path.expanduser("~/.ghscan.json")

DEFAULTS = {
    "token_env_var": "GITHUB_TOKEN",
    "workers": 5,
    "output_format": "json",
    "output_file": "scan_results.json",
    "default_plugins": "all",
}


def load_config():
    """Load config from ~/.ghscan.json, falling back to defaults."""
    config = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                config.update(saved)
        except Exception:
            pass
    return config


def save_config(config):
    """Save config to ~/.ghscan.json."""
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False
