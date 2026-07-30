"""Bounded checks for observable HTTP rate-limit enforcement."""

import time

import requests

from utils.colors import Color, info, ok, result, section
from utils.config_loader import load_rate_limit_config


MAX_REQUEST_COUNT = 20
MIN_REQUEST_DELAY_SECONDS = 0.1
MAX_REQUEST_DELAY_SECONDS = 1.0


def check_rate_limit(target_url, session=None, timeout=10):
    """Send a small sequence of benign requests and report observed enforcement.

    This intentionally avoids concurrency and caps the probe at twenty requests.
    A missing signal is not proof that a target has no rate limiting: controls may
    be scoped to authentication, an API route, or a larger request window. For
    that reason, this module never raises a vulnerability solely from a missing
    rate-limit response or header.
    """
    section("RATE-LIMIT ASSESSMENT")

    config = load_rate_limit_config()
    request_count = _bounded_request_count(config.get("request_count", 8))
    request_delay = _bounded_request_delay(config.get("inter_request_delay_seconds", 0.2))
    rate_limit_status_codes = set(config.get("rate_limit_status_codes", [429]))
    rate_limit_headers = {header.lower() for header in config.get("rate_limit_headers", [])}

    s = session or requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"})
    scan_results = {
        "requests_sent": 0,
        "rate_limit_applied": False,
        "rate_limit_headers": [],
        "vulnerabilities": [],
    }

    info(
        f"Sending up to {request_count} benign requests, "
        f"spaced {request_delay:.1f}s apart"
    )

    for attempt in range(1, request_count + 1):
        try:
            response = s.get(target_url, timeout=timeout, verify=False, allow_redirects=True)
        except requests.RequestException as exc:
            info(f"Stopping rate-limit probe after request failure: {exc}")
            scan_results["inconclusive"] = True
            break

        scan_results["requests_sent"] += 1
        if response.status_code >= 500:
            info(f"Stopping rate-limit probe after server error (HTTP {response.status_code})")
            scan_results["inconclusive"] = True
            break

        observed_headers = sorted(
            header for header in response.headers
            if header.lower() in rate_limit_headers
        )
        scan_results["rate_limit_headers"] = sorted(
            set(scan_results["rate_limit_headers"]) | set(observed_headers)
        )

        if response.status_code in rate_limit_status_codes:
            scan_results["rate_limit_applied"] = True
            scan_results["limited_at_request"] = attempt
            scan_results["status_code"] = response.status_code
            ok(f"Rate limiting enforced at request {attempt} (HTTP {response.status_code})")
            result("PASS", "Rate limiting is actively enforced for this route")
            break

        if attempt < request_count:
            time.sleep(request_delay)

    if scan_results["rate_limit_applied"]:
        return scan_results

    if scan_results.get("inconclusive"):
        result("INFO", "Rate-limit assessment was inconclusive because the target could not complete the probe")
        return scan_results

    if scan_results["rate_limit_headers"]:
        headers = ", ".join(scan_results["rate_limit_headers"])
        info(f"Rate-limit headers observed: {Color.CYAN}{headers}{Color.RESET}")
        result("INFO", "Rate-limit policy is advertised, but this bounded probe did not reach enforcement")
    else:
        info("No rate-limit headers or HTTP 429 response observed during the bounded probe")
        result(
            "INFO",
            "Rate-limit enforcement was not observed; this is inconclusive, not a vulnerability finding",
        )
        scan_results["inconclusive"] = True

    return scan_results


def _bounded_request_count(value):
    """Return a safe number of requests even if configuration is malformed."""
    try:
        return min(max(int(value), 1), MAX_REQUEST_COUNT)
    except (TypeError, ValueError):
        return 8


def _bounded_request_delay(value):
    """Return a safe inter-request delay even if configuration is malformed."""
    try:
        return min(max(float(value), MIN_REQUEST_DELAY_SECONDS), MAX_REQUEST_DELAY_SECONDS)
    except (TypeError, ValueError):
        return 0.2
