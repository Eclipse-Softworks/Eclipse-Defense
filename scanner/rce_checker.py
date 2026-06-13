import requests
import urllib.parse
import re
from utils.colors import section, result, info, found, ok, Color
from utils.config_loader import load_rce_config


def check_rce(target_url, session=None):
    section("REMOTE CODE EXECUTION (RCE) DETECTION")
    
    config = load_rce_config()
    common_query_params = config["common_query_params"]
    rce_payloads = config["rce_payloads"]

    s = session or requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"})

    scan_results = {
        "rce_found":      False,
        "ssti_found":     False,
        "vulnerabilities": [],
    }

    parsed   = urllib.parse.urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params   = urllib.parse.parse_qs(parsed.query)

    param_names = list(params.keys()) if params else common_query_params[:6]

    info(f"Testing {len(param_names)} parameter(s): {Color.CYAN}{', '.join(param_names)}{Color.RESET}")
    info(f"Running {len(rce_payloads)} RCE/SSTI payload(s)")

    rce_found_any  = False
    ssti_found_any = False

    for param in param_names:
        for probe in rce_payloads:
            test_params = {p: (v[0] if isinstance(v, list) else v)
                           for p, v in (params.items() if params else {p: "" for p in param_names}.items())}
            test_params[param] = probe["payload"]

            try:
                resp = s.get(base_url, params=test_params, timeout=8, verify=False, allow_redirects=True)
                body = resp.text

                if re.search(probe["pattern"], body, re.IGNORECASE):
                    tag = "[RCE]" if "SSTI" not in probe["name"] else "[SSTI]"
                    found(f"{tag} Vulnerability confirmed: {probe['name']}")
                    found(f"    Parameter: {param}")
                    found(f"    Payload:   {probe['payload']}")
                    result(probe["severity"], f"{probe['name']} via parameter '{param}'")

                    vuln_entry = {
                        "type":      probe["name"],
                        "param":     param,
                        "payload":   probe["payload"],
                        "severity":  probe["severity"],
                    }
                    scan_results["vulnerabilities"].append(vuln_entry)

                    if "SSTI" in probe["name"]:
                        ssti_found_any = True
                    else:
                        rce_found_any = True

            except requests.RequestException:
                pass

    _check_log4shell_headers(target_url, s, scan_results)

    if not rce_found_any and not ssti_found_any:
        ok("No obvious RCE or SSTI indicators found in GET parameters")
        result("PASS", "No RCE/SSTI detected in tested parameters")

    scan_results["rce_found"]  = rce_found_any
    scan_results["ssti_found"] = ssti_found_any

    return scan_results


def _check_log4shell_headers(target_url, session, scan_results):
    info("Testing Log4Shell via request headers")

    headers_to_test = {
        "X-Api-Version":      "${jndi:ldap://127.0.0.1:1389/a}",
        "User-Agent":         "${jndi:ldap://127.0.0.1:1389/a}",
        "X-Forwarded-For":    "${jndi:ldap://127.0.0.1:1389/a}",
        "Referer":            "${jndi:ldap://127.0.0.1:1389/a}",
        "Accept-Language":    "${jndi:ldap://127.0.0.1:1389/a}",
    }

    for header, payload in headers_to_test.items():
        try:
            resp = session.get(target_url, headers={header: payload},
                               timeout=8, verify=False, allow_redirects=True)
            body = resp.text

            if re.search(r"uid=\d+|root:|administrator|nt authority", body, re.IGNORECASE):
                found(f"Log4Shell triggered via header: {header}")
                result("CRITICAL", f"Log4Shell RCE via {header} header")
                scan_results["vulnerabilities"].append({
                    "type":     "Log4Shell (CVE-2021-44228)",
                    "param":    header,
                    "payload":  payload,
                    "severity": "CRITICAL",
                })
                scan_results["rce_found"] = True

        except requests.RequestException:
            pass

    ok("Log4Shell header injection test completed")
