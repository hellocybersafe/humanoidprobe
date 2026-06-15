import json
import os
from datetime import datetime
from urllib.parse import urlparse

# ─────────────────────────────────────────────
# memory.py
# Job: Save and load WAF intelligence profiles
# Separated by domain + probe type
# Stored in ~/.humanoidprobe/ — survives pip upgrades
# contributor field reserved for future shared intelligence network
# ─────────────────────────────────────────────


def _data_dir():
    path = os.path.join(os.path.expanduser("~"), ".humanoidprobe", "waf_profiles")
    os.makedirs(path, exist_ok=True)
    return path


def _extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or url


def _profile_path(domain, probe_type):
    safe = domain.replace(":", "_")
    return os.path.join(_data_dir(), f"{safe}_{probe_type}.json")


def load_profile(url, probe_type):
    path = _profile_path(_extract_domain(url), probe_type)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def save_profile(url, probe_type, results):
    domain = _extract_domain(url)
    path   = _profile_path(domain, probe_type)
    now    = datetime.utcnow().isoformat()

    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                profile = json.load(f)
            profile["scan_count"]  += 1
            profile["last_scanned"] = now
        except Exception:
            profile = _new_profile(domain, probe_type, now)
    else:
        profile = _new_profile(domain, probe_type, now)

    blocked   = [r for r in results if r.get("verdict") == "BLOCKED"]
    passed    = [r for r in results if r.get("verdict") == "PASSED"]
    reflected = [r for r in results if r.get("verdict") == "REFLECTED"]

    profile["waf_detected"] = len(blocked) > 0

    for r in blocked:
        cat = r.get("category", "uncategorised")
        profile["blocked_categories"][cat] = profile["blocked_categories"].get(cat, 0) + 1
        if r.get("payload") and r["payload"] not in profile["blocked_payloads"]:
            profile["blocked_payloads"].append(r["payload"])

    for r in passed:
        cat = r.get("category", "uncategorised")
        profile["passed_categories"][cat] = profile["passed_categories"].get(cat, 0) + 1
        if r.get("payload") and r["payload"] not in profile["passed_payloads"]:
            profile["passed_payloads"].append(r["payload"])

    for r in reflected:
        if r.get("payload") and r["payload"] not in profile["reflected_payloads"]:
            profile["reflected_payloads"].append(r["payload"])

    try:
        with open(path, "w") as f:
            json.dump(profile, f, indent=2)
    except Exception as e:
        print(f"  [MEMORY] Could not save profile: {e}")

    return profile


def _new_profile(domain, probe_type, now):
    return {
        "domain"             : domain,
        "probe_type"         : probe_type,
        "scan_count"         : 1,
        "first_scanned"      : now,
        "last_scanned"       : now,
        "waf_detected"       : False,
        "blocked_categories" : {},
        "passed_categories"  : {},
        "reflected_payloads" : [],
        "passed_payloads"    : [],
        "blocked_payloads"   : [],
        "contributor"        : None
    }


def show_profile(url, probe_type):
    profile = load_profile(url, probe_type)

    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    if not profile:
        print(f"\n  No profile found for {_extract_domain(url)} ({probe_type.upper()})")
        print(f"  Run a scan first to build intelligence.\n")
        return

    print(f"\n{BOLD}{'─' * 60}{RESET}")
    print(f"{BOLD}  WAF INTELLIGENCE PROFILE{RESET}")
    print(f"{BOLD}{'─' * 60}{RESET}")
    print(f"  Domain       : {profile['domain']}")
    print(f"  Probe type   : {profile['probe_type'].upper()}")
    print(f"  Total scans  : {profile['scan_count']}")
    print(f"  First seen   : {profile['first_scanned'][:10]}")
    print(f"  Last scanned : {profile['last_scanned'][:10]}")
    print(f"  WAF detected : {'Yes' if profile['waf_detected'] else 'No'}")

    if profile.get("blocked_categories"):
        print(f"\n  {RED}{BOLD}Blocked categories:{RESET}")
        for cat, count in sorted(profile["blocked_categories"].items(), key=lambda x: -x[1]):
            print(f"      {RED}-> {cat} ({count} blocked){RESET}")

    if profile.get("passed_categories"):
        print(f"\n  {YELLOW}{BOLD}Passed categories:{RESET}")
        for cat, count in sorted(profile["passed_categories"].items(), key=lambda x: -x[1]):
            print(f"      {YELLOW}-> {cat} ({count} passed){RESET}")

    if profile.get("reflected_payloads"):
        print(f"\n  {GREEN}{BOLD}Reflected payloads:{RESET}")
        for p in profile["reflected_payloads"]:
            print(f"      {GREEN}-> {p}{RESET}")

    print(f"{BOLD}{'─' * 60}{RESET}\n")


def list_profiles():
    data_dir = _data_dir()
    files    = [f for f in os.listdir(data_dir) if f.endswith(".json")]

    CYAN  = "\033[96m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    RESET = "\033[0m"

    if not files:
        print("\n  No WAF profiles saved yet.")
        print("  Run a scan to start building your intelligence database.\n")
        return

    print(f"\n{BOLD}{'─' * 60}{RESET}")
    print(f"{BOLD}  SAVED WAF PROFILES{RESET}")
    print(f"{DIM}  Stored in ~/.humanoidprobe/waf_profiles/{RESET}")
    print(f"{BOLD}{'─' * 60}{RESET}")

    for fname in sorted(files):
        path = os.path.join(data_dir, fname)
        try:
            with open(path, "r") as fp:
                p = json.load(fp)
            waf = "WAF detected" if p.get("waf_detected") else "No WAF"
            print(f"  {CYAN}{p['domain']}{RESET} [{p['probe_type'].upper()}] — {p['scan_count']} scan(s) — {waf} — last: {p['last_scanned'][:10]}")
        except Exception:
            print(f"  {fname} — could not read profile")

    print(f"{BOLD}{'─' * 60}{RESET}\n")
