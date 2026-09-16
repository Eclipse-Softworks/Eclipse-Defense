import requests
import urllib.parse
import re
import time
from utils.colors import section, result, info, found, ok, Color
from utils.config_loader import load_filter_config


def check_filter_bypass(target_url, session=None, timeout=10):
    """Probe query, method, body, and header handling for filter bypass signals."""
    section("CLIENT-SIDE FILTER BYPASS DETECTION")

    config = load_filter_config()
    client_filter_params = config["client_filter_params"]

    s = session or requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"})

    parsed   = urllib.parse.urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params   = urllib.parse.parse_qs(parsed.query)

    scan_results = {
        "xss_found":  False,
        "sqli_found": False,
        "vulnerabilities": [],
    }

    param_names = list(params.keys()) if params else client_filter_params[:6]
    info(f"Testing {len(param_names)} parameter(s) for filter bypass")

    xss_found_any  = False
    sqli_found_any = False

    for param in param_names:
        info(f"Probing parameter: {Color.CYAN}{param}{Color.RESET}")

        if _test_xss(base_url, param, params, s, scan_results, timeout):
            xss_found_any = True

        if _test_sqli(base_url, param, params, s, scan_results, timeout):
            sqli_found_any = True

    _test_http_verb_tampering(target_url, s, scan_results, timeout)
    _test_content_type_bypass(target_url, s, scan_results, timeout)
    _test_header_injection(target_url, s, scan_results, timeout)

    if not xss_found_any:
        ok("No reflected XSS indicators detected")
        result("PASS", "XSS filter appears to be active or parameters are not reflected")

    if not sqli_found_any:
        ok("No SQL injection error signatures detected")
        result("PASS", "No SQL errors triggered from injection attempts")

    scan_results["xss_found"]  = xss_found_any
    scan_results["sqli_found"] = sqli_found_any

    return scan_results


def _test_xss(base_url, param, params, session, scan_results, timeout):
    """Send configured XSS probes and record unencoded reflected payloads."""
    config = load_filter_config()
    xss_payloads = config["xss_payloads"]

    xss_detected = False

    for payload in xss_payloads:
        test_params = {p: (v[0] if isinstance(v, list) else v)
                       for p, v in (params.items() if params else {param: ""}.items())}
        test_params[param] = payload

        try:
            resp = session.get(base_url, params=test_params, timeout=timeout,
                               verify=False, allow_redirects=True)
            body = resp.text

            payload_lower   = payload.lower()
            body_lower      = body.lower()
            unencoded_tags  = re.search(r"<script[^>]*>|<img[^>]+onerror|<svg[^>]+onload|onerror=alert|onload=alert", body_lower)

            if payload_lower in body_lower and unencoded_tags:
                found("Reflected XSS detected!")
                found(f"    Parameter: {param}")
                found(f"    Payload:   {payload}")
                result("HIGH", f"Reflected XSS via '{param}': payload reflected unencoded")

                scan_results["vulnerabilities"].append({
                    "type":     "Reflected XSS",
                    "param":    param,
                    "payload":  payload,
                    "severity": "HIGH",
                })
                xss_detected = True
                break

            if payload_lower in body_lower:
                found("Input reflected unfiltered (potential XSS):")
                found(f"    Parameter: {param}")
                found(f"    Payload:   {payload}")
                result("MEDIUM", f"Input reflected without encoding in '{param}'")
                scan_results["vulnerabilities"].append({
                    "type":     "Potential XSS (unencoded reflection)",
                    "param":    param,
                    "payload":  payload,
                    "severity": "MEDIUM",
                })

        except requests.RequestException:
            pass

    return xss_detected


def _test_sqli(base_url, param, params, session, scan_results, timeout):
    """Detect configured SQL error signatures and significant timing deviations."""
    config = load_filter_config()
    sql_injection_payloads = config["sql_injection_payloads"]
    sql_error_patterns = config["sql_error_patterns"]

    sqli_detected = False
    baseline_time = None
    baseline_body = ""

    try:
        test_params = {p: (v[0] if isinstance(v, list) else v)
                       for p, v in (params.items() if params else {param: "test"}.items())}
        t0 = time.time()
        baseline_response = session.get(base_url, params=test_params, timeout=timeout, verify=False)
        baseline_time = time.time() - t0
        baseline_body = baseline_response.text
    except requests.RequestException:
        info(f"Skipping SQLi checks for '{param}': baseline request failed")
        return False

    for payload in sql_injection_payloads:
        test_params = {p: (v[0] if isinstance(v, list) else v)
                       for p, v in (params.items() if params else {param: ""}.items())}
        test_params[param] = payload

        try:
            t0   = time.time()
            resp = session.get(base_url, params=test_params, timeout=timeout,
                               verify=False, allow_redirects=True)
            elapsed = time.time() - t0
            body    = resp.text.lower()

            for pattern in sql_error_patterns:
                if (re.search(pattern, body, re.IGNORECASE)
                        and not re.search(pattern, baseline_body, re.IGNORECASE)):
                    found("SQL error signature detected!")
                    found(f"    Parameter: {param}")
                    found(f"    Payload:   {payload}")
                    found(f"    Pattern:   {pattern}")
                    result("CRITICAL", f"SQL Injection error-based via '{param}'")

                    scan_results["vulnerabilities"].append({
                        "type":     "SQL Injection (Error-Based)",
                        "param":    param,
                        "payload":  payload,
                        "severity": "CRITICAL",
                    })
                    sqli_detected = True
                    break

            if "SLEEP" in payload or "WAITFOR" in payload or "pg_sleep" in payload:
                delay = elapsed - baseline_time
                if delay >= 2.5:
                    found(f"Time-based blind SQLi detected! Delay: {delay:.2f}s")
                    found(f"    Parameter: {param}")
                    found(f"    Payload:   {payload}")
                    result("CRITICAL", f"Time-based blind SQL Injection via '{param}' (delay {delay:.2f}s)")

                    scan_results["vulnerabilities"].append({
                        "type":     "SQL Injection (Time-Based Blind)",
                        "param":    param,
                        "payload":  payload,
                        "severity": "CRITICAL",
                    })
                    sqli_detected = True

            if sqli_detected:
                break

        except requests.RequestException:
            pass

    return sqli_detected


def _test_http_verb_tampering(target_url, session, scan_results, timeout):
    """Check advertised and observable HTTP methods for unsafe exposure."""
    info("Testing HTTP verb tampering / method override")

    try:
        resp = session.options(target_url, timeout=timeout, verify=False)
        allowed = resp.headers.get("Allow", resp.headers.get("Access-Control-Allow-Methods", ""))

        if allowed:
            info(f"Allowed methods: {Color.CYAN}{allowed}{Color.RESET}")
            allowed_methods = {method.strip().upper() for method in allowed.split(",")}
            risky = [method for method in ["PUT", "DELETE", "TRACE", "CONNECT"] if method in allowed_methods]
            if risky:
                found(f"Risky HTTP methods allowed: {', '.join(risky)}")
                result("MEDIUM", f"Server allows risky methods: {', '.join(risky)}")
                scan_results["vulnerabilities"].append({
                    "type":     "Risky HTTP Methods",
                    "param":    "OPTIONS",
                    "payload":  ", ".join(risky),
                    "severity": "MEDIUM",
                })
            else:
                ok("No risky HTTP methods found in Allow header")
        else:
            ok("No Allow header returned")

    except requests.RequestException:
        pass

    try:
        resp = session.request("TRACE", target_url, timeout=timeout, verify=False)
        if resp.status_code == 200 and "TRACE" in resp.text.upper():
            found("TRACE method enabled - Cross-Site Tracing (XST) possible")
            result("MEDIUM", "HTTP TRACE method is enabled (XST risk)")
            scan_results["vulnerabilities"].append({
                "type":     "Cross-Site Tracing (XST)",
                "param":    "TRACE",
                "payload":  "TRACE request",
                "severity": "MEDIUM",
            })
        else:
            ok("TRACE method disabled")
    except requests.RequestException:
        pass


def _test_content_type_bypass(target_url, session, scan_results, timeout):
    info("Testing Content-Type header bypass")

    payloads = [
        ("application/json",       '{"query": "<script>alert(\'eclipse_xss_probe_12345\')</script>"}'),
        ("text/xml",               '<?xml version="1.0"?><query><value><script>alert(\'eclipse_xss_probe_12345\')</script></value></query>'),
        ("application/x-www-form-urlencoded", "input=%3Cscript%3Ealert%28%27eclipse_xss_probe_12345%27%29%3C/script%3E"),
    ]

    for content_type, body in payloads:
        try:
            resp = session.post(
                target_url,
                data=body,
                headers={"Content-Type": content_type},
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            body_resp = resp.text.lower()

            if "eclipse_xss_probe_12345" in body_resp and "<script" in body_resp:
                found(f"Content-Type bypass reflected payload: {content_type}")
                result("HIGH", f"XSS via Content-Type '{content_type}' bypass")
                scan_results["vulnerabilities"].append({
                    "type":     "Content-Type Bypass XSS",
                    "param":    "POST body",
                    "payload":  content_type,
                    "severity": "HIGH",
                })

        except requests.RequestException:
            pass


def _test_header_injection(target_url, session, scan_results, timeout):
    info("Testing HTTP header injection")

    injection_headers = {
        "X-Forwarded-Host":  "evil.example.com",
        "X-Forwarded-For":   "127.0.0.1",
        "X-Original-URL":    "/admin",
        "X-Rewrite-URL":     "/admin",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "X-Forwarded-Proto": "https",
        "X-Override-URL":    "/admin",
    }

    try:
        baseline = session.get(target_url, timeout=timeout, verify=False, allow_redirects=True)
        baseline_url = baseline.url
        baseline_status = baseline.status_code
    except requests.RequestException:
        baseline_url = ""
        baseline_status = None

    for header, value in injection_headers.items():
        try:
            resp = session.get(target_url, headers={header: value},
                               timeout=timeout, verify=False, allow_redirects=True)
            if (resp.status_code == 200 and "/admin" in resp.url
                    and (resp.url != baseline_url or baseline_status != 200)):
                found(f"Header injection may have bypassed access control: {header}")
                result("HIGH", f"Access control bypass via {header}: {value}")
                scan_results["vulnerabilities"].append({
                    "type":     "Header-Based Access Control Bypass",
                    "param":    header,
                    "payload":  value,
                    "severity": "HIGH",
                })
        except requests.RequestException:
            pass
