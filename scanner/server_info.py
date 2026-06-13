import requests
from utils.colors import section, result, info, found, ok, Color
from utils.config_loader import load_server_config


def check_server_info(target_url, session=None):
    section("WEB SERVER FINGERPRINTING & HEADERS")

    s = session or requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"})

    scan_results = {}

    try:
        resp = s.get(target_url, timeout=10, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        found(f"Request failed: {e}")
        return scan_results

    headers = {k.lower(): v for k, v in resp.headers.items()}

    info(f"Final URL after redirects: {Color.CYAN}{resp.url}{Color.RESET}")
    info(f"HTTP Status: {Color.CYAN}{resp.status_code}{Color.RESET}")

    _detect_server(headers, scan_results)
    _check_security_headers(headers, scan_results)
    _check_information_disclosure(headers, scan_results)
    _check_cookie_flags(resp.cookies, scan_results)

    return scan_results


def _detect_server(headers, scan_results):
    config = load_server_config()
    known_servers = config["servers"]
    
    raw_server = headers.get("server", "")
    raw_powered = headers.get("x-powered-by", "")

    info(f"Server header:      {Color.YELLOW}{raw_server or '(not disclosed)'}{Color.RESET}")
    info(f"X-Powered-By:       {Color.YELLOW}{raw_powered or '(not disclosed)'}{Color.RESET}")

    detected = []
    combined = (raw_server + " " + raw_powered).lower()

    for key, label in known_servers.items():
        if key in combined:
            detected.append(label)

    if detected:
        scan_results["detected_server"] = detected
        for srv in detected:
            ok(f"Identified: {Color.CYAN}{srv}{Color.RESET}")
    else:
        info("Server technology not identified from headers")
        scan_results["detected_server"] = ["Unknown"]

    if raw_server and any(c.isdigit() for c in raw_server):
        found(f"Server version disclosed in header: {raw_server}")
        result("MEDIUM", "Server version number is exposed - remove or genericize Server header")
        scan_results["version_disclosed"] = True
    else:
        scan_results["version_disclosed"] = False


def _check_security_headers(headers, scan_results):
    config = load_server_config()
    security_headers = config["security_headers"]
    
    missing = []
    present = []

    for header_obj in security_headers:
        header_key = header_obj["header"]
        label = header_obj["label"]
        severity = header_obj["severity"]
        
        if header_key in headers:
            ok(f"{label}: {Color.GRAY}{headers[header_key][:80]}{Color.RESET}")
            present.append(label)
        else:
            found(f"Missing security header: {label}")
            result(severity, f"Header not set: {label}")
            missing.append((label, severity))

    scan_results["missing_security_headers"] = missing
    scan_results["present_security_headers"] = present


def _check_information_disclosure(headers, scan_results):
    config = load_server_config()
    risky_headers = config["risky_headers"]
    
    disclosed = []

    for h in risky_headers:
        if h in headers and h not in ("strict-transport-security", "content-security-policy"):
            val = headers[h]
            if h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                      "x-generator", "x-backend-server", "x-runtime"):
                found(f"Technology disclosure - {h}: {val}")
                result("LOW", f"Header leaks tech info: {h}: {val}")
                disclosed.append(h)

    scan_results["disclosed_headers"] = disclosed


def _check_cookie_flags(cookies, scan_results):
    issues = []

    for cookie in cookies:
        flags = []

        if not cookie.secure:
            flags.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            flags.append("missing HttpOnly flag")

        samesite = cookie._rest.get("SameSite", None) if hasattr(cookie, "_rest") else None
        if not samesite:
            flags.append("missing SameSite attribute")

        if flags:
            found(f"Cookie '{cookie.name}': {', '.join(flags)}")
            result("MEDIUM", f"Insecure cookie: {cookie.name} - {', '.join(flags)}")
            issues.append({"name": cookie.name, "issues": flags})
        else:
            ok(f"Cookie '{cookie.name}' has secure flags set")

    scan_results["cookie_issues"] = issues
