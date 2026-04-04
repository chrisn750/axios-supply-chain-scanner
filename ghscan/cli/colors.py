"""
ANSI color helpers — auto-disabled when stdout is not a TTY.
"""

import os
import sys

_COLOR_ENABLED = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

# Allow override via environment
if os.environ.get("NO_COLOR"):
    _COLOR_ENABLED = False
if os.environ.get("FORCE_COLOR"):
    _COLOR_ENABLED = True

# ANSI escape codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN = "\033[36m"
_WHITE = "\033[37m"

_BG_RED = "\033[41m"
_BG_GREEN = "\033[42m"
_BG_YELLOW = "\033[43m"
_BG_BLUE = "\033[44m"


def _wrap(code, text):
    if not _COLOR_ENABLED:
        return text
    return f"{code}{text}{_RESET}"


def bold(text):
    return _wrap(_BOLD, text)


def dim(text):
    return _wrap(_DIM, text)


def red(text):
    return _wrap(_RED, text)


def green(text):
    return _wrap(_GREEN, text)


def yellow(text):
    return _wrap(_YELLOW, text)


def blue(text):
    return _wrap(_BLUE, text)


def magenta(text):
    return _wrap(_MAGENTA, text)


def cyan(text):
    return _wrap(_CYAN, text)


def white(text):
    return _wrap(_WHITE, text)


def bold_red(text):
    return _wrap(_BOLD + _RED, text)


def bold_green(text):
    return _wrap(_BOLD + _GREEN, text)


def bold_yellow(text):
    return _wrap(_BOLD + _YELLOW, text)


def bold_cyan(text):
    return _wrap(_BOLD + _CYAN, text)


def severity_color(severity, text):
    """Color text based on severity level."""
    colors = {
        "critical": bold_red,
        "high": lambda t: _wrap(_BOLD + _YELLOW, t),
        "medium": yellow,
        "low": dim,
        "info": blue,
    }
    fn = colors.get(severity, str)
    return fn(text)
