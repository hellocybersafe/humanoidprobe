import urllib.request
import json

# ─────────────────────────────────────────────
# updater.py
# Job: Check PyPI for newer version — notify only
# User is always in control of when to upgrade
# ─────────────────────────────────────────────

PYPI_URL = "https://pypi.org/pypi/humanoidprobe/json"


def check_for_update(current_version):
    """
    Silently checks PyPI for latest version.
    Returns (latest_version, update_available).
    Never raises — update check must never crash the tool.
    """
    try:
        with urllib.request.urlopen(PYPI_URL, timeout=3) as response:
            data   = json.loads(response.read().decode())
            latest = data["info"]["version"]
            return latest, _is_newer(latest, current_version)
    except Exception:
        return None, False


def _is_newer(latest, current):
    try:
        return [int(x) for x in latest.split(".")] > [int(x) for x in current.split(".")]
    except Exception:
        return False


def print_update_notice(current_version, no_update_check=False):
    """
    Prints update notice if newer version exists on PyPI.
    Skipped if no_update_check is True.
    User must manually run: pip install --upgrade humanoidprobe
    """
    if no_update_check:
        return

    YELLOW = "\033[93m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    latest, available = check_for_update(current_version)
    if available:
        print(f"  {YELLOW}{BOLD}[UPDATE]{RESET} HumanoidProbe {latest} is available")
        print(f"  {DIM}Run: pip install --upgrade humanoidprobe{RESET}\n")
