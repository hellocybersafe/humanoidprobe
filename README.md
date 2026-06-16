# HumanoidProbe
**by CyberSafeLabs**
*Research & development: @cybermansec*

> *Analyse WAF behaviour. Think like an attacker.*

HumanoidProbe is a WAF intelligence CLI tool.
It probes WAF behaviour, generates context-aware bypass mutations,
and builds a local intelligence profile per target over time.

Built from real bug bounty research. Not theory.

<img width="970" height="773" alt="Screenshot_2026-06-15_18-21-26" src="https://github.com/user-attachments/assets/43cff536-e3e2-4512-b787-e808dae49f88" />
<img width="970" height="775" alt="Screenshot_2026-06-15_18-16-46" src="https://github.com/user-attachments/assets/0ec7a60d-2daf-4f84-9a97-79ffe1c47c5f" />

---

## Install

```bash
pip install humanoidprobe
```

## Update

```bash
pip install --upgrade humanoidprobe
```

---

## Usage

```bash
# XSS probe
humanoidprobe -u https://example.com/search -p q --type xss

# View saved WAF profile
humanoidprobe --show-profile https://example.com --type xss

# List all saved profiles
humanoidprobe --list-profiles

# Check version
humanoidprobe --version

# Skip update check
humanoidprobe -u https://example.com/search -p q --no-update-check
```

---

## How it works

1. Fires a canary string to probe what the WAF allows
2. Tests each payload individually as-is
3. If blocked — generates a context-aware mutation and retries
4. Stops immediately on first confirmed reflection
5. Saves confirmed payloads to inventory for future scans
6. Builds a WAF profile per domain that gets smarter over time

---

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `REFLECTED` | Payload appeared in response — verify execution in browser |
| `PASSED` | WAF did not block — test manually |
| `BLOCKED` | WAF caught this payload |
| `ERROR` | Request failed |

---

## Legal & ethical use

Only use HumanoidProbe against targets you have explicit permission to test.
Built for legitimate bug bounty and security research only.

---

*CyberSafeLabs — protecting digital assets through research*
