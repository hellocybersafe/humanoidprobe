#!/usr/bin/env python3

"""
humanoidprobe.py — HumanoidProbe
CyberSafeLabs | Research & development: @cybermansec
For ethical use only. Only test targets you have explicit permission to test.
"""

import argparse
import os
import sys
import time


def _load_payloads(payload_file):
    if not os.path.exists(payload_file):
        print(f"[ERROR] Payload file not found: {payload_file}")
        sys.exit(1)

    entries          = []
    current_category = "general"

    with open(payload_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("# Category:"):
                current_category = line.replace("# Category:", "").strip()
                continue
            if line.startswith("#"):
                continue
            entries.append({"payload": line, "category": current_category})

    return entries


def main():
    parser = argparse.ArgumentParser(
        description="HumanoidProbe — WAF Intelligence Tool by CyberSafeLabs",
        epilog="Example: humanoidprobe -u https://example.com/search -p q --type xss"
    )
    parser.add_argument("-u", "--url",           help="Target URL")
    parser.add_argument("-p", "--parameter",     help="GET parameter to inject into")
    parser.add_argument("--type",                default="xss",       help="Probe type (default: xss)")
    parser.add_argument("--delay",               type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--timeout",             type=int,   default=10,  help="Request timeout in seconds")
    parser.add_argument("--no-update-check",     action="store_true", help="Skip update notification")
    parser.add_argument("--list-profiles",       action="store_true", help="List all saved WAF profiles")
    parser.add_argument("--show-profile",        metavar="URL",       help="Show saved WAF profile for a URL")
    parser.add_argument("--version",             action="store_true", help="Show version and exit")
    args = parser.parse_args()

    from humanoidprobe.__version__    import __version__
    from humanoidprobe.core.requester import send_payload, get_baseline
    from humanoidprobe.core.detector  import (
        get_baseline_length,
        analyse_result,
        probe_waf_capabilities,
        generate_custom_payload,
        store_learned_payload,
    )
    from humanoidprobe.core.reporter  import (
        print_banner,
        print_profile_notice,
        print_result,
        print_summary,
        print_bypass_suggestions,
    )
    from humanoidprobe.core.memory    import (
        load_profile,
        save_profile,
        show_profile,
        list_profiles,
    )
    from humanoidprobe.core.bypass    import generate_bypass_suggestions

    if args.version:
        print(f"HumanoidProbe v{__version__} by CyberSafeLabs")
        return

    no_update = getattr(args, "no_update_check", False)
    print_banner(__version__, no_update_check=no_update)

    if args.list_profiles:
        list_profiles()
        return

    if args.show_profile:
        show_profile(args.show_profile, (args.type or "xss").lower())
        return

    if not args.url or not args.parameter:
        parser.print_help()
        print("\n[ERROR] --url and --parameter are required for scanning.\n")
        sys.exit(1)

    probe_type = args.type.lower()

    profile = load_profile(args.url, probe_type)
    if profile:
        print_profile_notice(profile, probe_type)
    else:
        print(f"  [*] No previous profile found for this target — starting fresh.\n")

    pkg_dir         = os.path.dirname(os.path.abspath(__file__))
    payload_file    = os.path.join(pkg_dir, "payloads", f"{probe_type}.txt")
    payload_entries = _load_payloads(payload_file)

    print(f"  [*] Loading {probe_type.upper()} payloads from: {payload_file}")
    print(f"  [*] Loaded {len(payload_entries)} payloads\n")

    print(f"  [*] Getting baseline for: {args.url}")
    baseline_length = get_baseline_length(args.url, args.parameter, timeout=args.timeout)
    if baseline_length:
        print(f"  [*] Baseline length: {baseline_length} bytes\n")
    else:
        print(f"  [!] No baseline — continuing without it\n")

    print(f"  [*] Probing WAF capabilities...")
    capabilities = probe_waf_capabilities(args.url, args.parameter)

    print(f"  [*] Probing '{args.parameter}' with {probe_type.upper()} payloads")
    print(f"  [*] Delay: {args.delay}s between requests\n")
    print(f"  {'─' * 60}")

    total         = len(payload_entries)
    all_results   = []
    any_reflected = False

    for i, entry in enumerate(payload_entries, start=1):
        original_payload = entry["payload"]
        category         = entry["category"]

        # Phase 1 — fire original payload as-is
        raw_result                     = send_payload(args.url, args.parameter, original_payload, timeout=args.timeout)
        raw_result["category"]         = category
        raw_result["original_payload"] = original_payload
        analysed                       = analyse_result(raw_result, baseline_length)

        # Phase 2 — if blocked, mutate and retry once
        if analysed.get("verdict") == "BLOCKED":
            mutated_payload = generate_custom_payload(original_payload, capabilities)

            if mutated_payload != original_payload:
                raw_retry                     = send_payload(args.url, args.parameter, mutated_payload, timeout=args.timeout)
                raw_retry["category"]         = category
                raw_retry["original_payload"] = original_payload
                analysed                      = analyse_result(raw_retry, baseline_length)
                analysed["payload"]           = mutated_payload

                YELLOW = "\033[93m"
                RESET  = "\033[0m"
                if analysed.get("verdict") != "BLOCKED":
                    print(f"  {YELLOW}[MUTATE]{RESET} Bypass found: {mutated_payload}")
                else:
                    print(f"  {YELLOW}[MUTATE]{RESET} Mutation also blocked: {mutated_payload}")

        all_results.append(analysed)
        print_result(analysed, i, total)

        # Phase 3 — stop on first reflection
        if analysed.get("verdict") == "REFLECTED":
            any_reflected = True
            store_learned_payload(analysed["payload"])
            GREEN = "\033[92m"
            BOLD  = "\033[1m"
            RESET = "\033[0m"
            print(f"\n  {GREEN}{BOLD}[HIT]{RESET} Reflected payload confirmed — stopping scan.")
            print(f"  {GREEN}[HIT]{RESET} Payload  : {analysed['payload']}")
            print(f"  {GREEN}[HIT]{RESET} Verify execution in browser before reporting.\n")
            break

        time.sleep(args.delay)

    save_profile(args.url, probe_type, all_results)
    print_summary(all_results, args.url, args.parameter, probe_type)

    if not any_reflected:
        suggestions = generate_bypass_suggestions(all_results, profile)
        if suggestions:
            print_bypass_suggestions(suggestions)
        else:
            blocked = [r for r in all_results if r.get("verdict") == "BLOCKED"]
            if not blocked:
                print(f"  [*] No WAF blocks detected. Test passed payloads manually.\n")
    else:
        GREEN = "\033[92m"
        BOLD  = "\033[1m"
        RESET = "\033[0m"
        print(f"  {GREEN}{BOLD}[*] Reflected payload saved to inventory.{RESET}")
        print(f"      Verify execution in browser before reporting.\n")


if __name__ == "__main__":
    main()
