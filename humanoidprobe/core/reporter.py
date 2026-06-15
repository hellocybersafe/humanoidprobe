GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def print_banner(version="", no_update_check=False):
    from humanoidprobe.core.updater import print_update_notice
    print(f"\n{CYAN}{BOLD}")
    print(f"  ██╗  ██╗██╗   ██╗███╗   ███╗ █████╗ ███╗   ██╗ ██████╗ ██╗██████╗ ")
    print(f"  ██║  ██║██║   ██║████╗ ████║██╔══██╗████╗  ██║██╔═══██╗██║██╔══██╗")
    print(f"  ███████║██║   ██║██╔████╔██║███████║██╔██╗ ██║██║   ██║██║██║  ██║")
    print(f"  ██╔══██║██║   ██║██║╚██╔╝██║██╔══██║██║╚██╗██║██║   ██║██║██║  ██║")
    print(f"  ██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║╚██████╔╝██║██████╔╝")
    print(f"  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═════╝")
    print(f"{RESET}")
    print(f"{BOLD}  HumanoidProbe v{version} — WAF Intelligence Tool{RESET}")
    print(f"{CYAN}  by CyberSafeLabs  |  Research & development: @cybermansec{RESET}")
    print(f"{DIM}  Analyse WAF behaviour. Think like an attacker.{RESET}\n")
    print_update_notice(version, no_update_check=no_update_check)


def print_profile_notice(profile, probe_type):
    if not profile:
        return
    print(f"  {CYAN}{BOLD}[MEMORY]{RESET} WAF profile found for {profile.get('domain', '')} ({probe_type.upper()})")
    print(f"  {CYAN}[MEMORY]{RESET} Previous scans : {profile.get('scan_count', 0)}")
    if profile.get("blocked_categories"):
        cats = ", ".join(profile["blocked_categories"].keys())
        print(f"  {CYAN}[MEMORY]{RESET} Known blocked  : {cats}")
    if profile.get("passed_categories"):
        cats = ", ".join(profile["passed_categories"].keys())
        print(f"  {CYAN}[MEMORY]{RESET} Known passed   : {cats}")
    print()


def print_result(result, index, total):
    verdict = result.get("verdict", "UNKNOWN")
    payload = result.get("payload", "")
    display = payload if len(payload) <= 55 else payload[:52] + "..."
    if verdict == "REFLECTED":
        label = f"{GREEN}{BOLD}[REFLECTED]{RESET}"
    elif verdict == "PASSED":
        label = f"{YELLOW}[PASSED]   {RESET}"
    elif verdict == "BLOCKED":
        label = f"{RED}[BLOCKED]  {RESET}"
    else:
        label = f"{CYAN}[ERROR]    {RESET}"
    print(f"  [{index:02}/{total}] {label} {display}")


def print_summary(results, url, parameter, probe_type):
    total     = len(results)
    blocked   = [r for r in results if r.get("verdict") == "BLOCKED"]
    passed    = [r for r in results if r.get("verdict") == "PASSED"]
    reflected = [r for r in results if r.get("verdict") == "REFLECTED"]
    errors    = [r for r in results if r.get("verdict") == "ERROR"]
    print(f"\n{BOLD}{'─' * 60}{RESET}")
    print(f"{BOLD}  SCAN SUMMARY{RESET}")
    print(f"{BOLD}{'─' * 60}{RESET}")
    print(f"  Target     : {url}")
    print(f"  Parameter  : {parameter}")
    print(f"  Probe type : {probe_type.upper()}")
    print(f"  Total      : {total} payloads tested")
    print(f"  {RED}Blocked    : {len(blocked)}{RESET}")
    print(f"  {YELLOW}Passed     : {len(passed)}{RESET}")
    print(f"  {GREEN}Reflected  : {len(reflected)}{RESET}")
    print(f"  {CYAN}Errors     : {len(errors)}{RESET}")
    if reflected:
        print(f"\n{GREEN}{BOLD}  [!] REFLECTED — Verify execution in browser:{RESET}")
        for r in reflected:
            print(f"      {GREEN}-> {r.get('payload', '')}{RESET}")
    if passed:
        print(f"\n{YELLOW}{BOLD}  [+] PASSED — WAF did not block:{RESET}")
        for r in passed:
            print(f"      {YELLOW}-> {r.get('payload', '')}{RESET}")
    print(f"\n{BOLD}  WAF BEHAVIOUR:{RESET}")
    if total == 0:
        print(f"  -> No payloads tested.")
    elif len(blocked) == total:
        print(f"  {RED}-> Highly aggressive WAF. Review bypass suggestions.{RESET}")
    elif len(blocked) == 0 and len(reflected) == 0:
        print(f"  {YELLOW}-> No WAF blocks. Check passed payloads manually.{RESET}")
    elif len(reflected) > 0:
        print(f"  {GREEN}-> Reflected payloads found. Verify in browser.{RESET}")
    else:
        rate = (len(blocked) / total) * 100
        print(f"  -> WAF blocked {rate:.0f}% of payloads.")
    print(f"\n  {CYAN}[MEMORY] WAF profile saved to ~/.humanoidprobe/waf_profiles/{RESET}")
    print(f"\n  {CYAN}{BOLD}Humanoid sees what others miss.{RESET}")
    print(f"{BOLD}{'─' * 60}{RESET}\n")


def print_bypass_suggestions(suggestions):
    if not suggestions:
        return
    print(f"\n{BOLD}{'─' * 60}{RESET}")
    print(f"{BOLD}  HUMANOID BYPASS SUGGESTIONS{RESET}")
    print(f"{DIM}  Generated from WAF behaviour analysis{RESET}")
    print(f"{BOLD}{'─' * 60}{RESET}")
    high   = [s for s in suggestions if s.get("confidence") == "high"]
    medium = [s for s in suggestions if s.get("confidence") == "medium"]
    low    = [s for s in suggestions if s.get("confidence") == "low"]
    if high:
        print(f"\n  {GREEN}{BOLD}High confidence:{RESET}")
        for s in high[:3]:
            print(f"      {GREEN}-> {s['payload']}{RESET}")
            print(f"         {DIM}{s['reason']}{RESET}")
    if medium:
        print(f"\n  {YELLOW}{BOLD}Medium confidence:{RESET}")
        for s in medium[:5]:
            print(f"      {YELLOW}-> {s['payload']}{RESET}")
            print(f"         {DIM}{s['reason']}{RESET}")
    if low:
        print(f"\n  {CYAN}{BOLD}Low confidence:{RESET}")
        for s in low[:3]:
            print(f"      {CYAN}-> {s['payload']}{RESET}")
            print(f"         {DIM}{s['reason']}{RESET}")
    print(f"\n  {DIM}Total suggestions: {len(suggestions)}{RESET}\n")
