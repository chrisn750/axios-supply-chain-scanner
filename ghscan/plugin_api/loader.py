"""
Plugin discovery and loading — recursively walks the plugins directory,
imports modules, and instantiates ScanPlugin subclasses.
"""

import importlib
import inspect
import os
import sys
import traceback

from ghscan.plugin_api import ScanPlugin


def discover_plugins(plugins_dir=None, verbose=False):
    """
    Recursively discover and instantiate all ScanPlugin subclasses
    in the plugins directory.

    Returns a list of (category, plugin_instance) tuples sorted by category
    then plugin name.
    """
    if plugins_dir is None:
        plugins_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "plugins")

    if not os.path.isdir(plugins_dir):
        return []

    # Ensure the parent of plugins_dir is on sys.path for imports
    package_root = os.path.dirname(os.path.dirname(plugins_dir))
    if package_root not in sys.path:
        sys.path.insert(0, package_root)

    results = []

    for root, _dirs, files in os.walk(plugins_dir):
        for filename in files:
            if not filename.endswith(".py") or filename.startswith("_"):
                continue

            filepath = os.path.join(root, filename)

            # Build the module import path relative to the package
            rel_path = os.path.relpath(filepath, package_root)
            module_path = rel_path.replace(os.sep, ".").removesuffix(".py")

            # Derive category from subdirectory structure
            rel_to_plugins = os.path.relpath(root, plugins_dir)
            if rel_to_plugins == ".":
                category = "general"
            else:
                category = rel_to_plugins.replace(os.sep, "/").replace("_", "-")

            try:
                module = importlib.import_module(module_path)
            except Exception as e:
                from ghscan.utils import thread_print
                thread_print(f"  [WARN] Failed to load plugin {module_path}: {e}", flush=True)
                if verbose:
                    traceback.print_exc()
                continue

            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, ScanPlugin) and obj is not ScanPlugin:
                    try:
                        instance = obj()
                        meta = instance.metadata()
                        if not meta.category:
                            meta.category = category
                        results.append((meta.category, instance))
                    except Exception as e:
                        from ghscan.utils import thread_print
                        thread_print(
                            f"  [WARN] Failed to instantiate plugin {obj.__name__}: {e}",
                            flush=True)
                        if verbose:
                            traceback.print_exc()

    results.sort(key=lambda x: (x[0], x[1].metadata().name))
    return results
