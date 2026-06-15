import requests
import time

# ─────────────────────────────────────────────
# requester.py
# Job: Send HTTP GET requests with injected payloads
# ─────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


def send_payload(url, parameter, payload, timeout=10):
    try:
        response = requests.get(
            url,
            params={parameter: payload},
            headers=HEADERS,
            timeout=timeout
        )
        return {
            "payload"         : payload,
            "status_code"     : response.status_code,
            "response_body"   : response.text,
            "response_length" : len(response.text),
            "error"           : None
        }
    except requests.exceptions.Timeout:
        return _error_result(payload, "Timeout")
    except requests.exceptions.ConnectionError:
        return _error_result(payload, "Connection error")
    except Exception as e:
        return _error_result(payload, str(e))


def get_baseline(url, parameter, timeout=10):
    try:
        response = requests.get(
            url,
            params={parameter: "hello"},
            headers=HEADERS,
            timeout=timeout
        )
        return len(response.text)
    except Exception:
        return None


def _error_result(payload, reason):
    return {
        "payload"         : payload,
        "status_code"     : None,
        "response_body"   : "",
        "response_length" : 0,
        "error"           : reason
    }
