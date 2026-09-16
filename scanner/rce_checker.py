import requests
import urllib.parse
import re
from utils.colors import section, result, info, found, ok, Color
from utils.config_loader import load_rce_config


def check_rce(target_url, session=None, timeout=10):
    """Probe parameters for RCE/SSTI evidence with per-parameter baselines."""
    section("REMOTE CODE EXECUTION (RCE) DETECTION")

    config = load_rce_config()
    common_query_params = config["common_query_params"]
    rce_payloads = config["rce_payloads"]

    s = session or requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"})

    scan_results = {
        "rce_found": False,
        "ssti_found": False,
        "vulnerabilities": [],
        "leads": [],  # low-confidence hits that need manual/OOB confirmation
    }

    parsed = urllib.parse.urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = urllib.parse.parse_qs(parsed.query)

    param_names = list(params.keys()) if params else common_query_params[:6]

    joined = ", ".join(param_names)
    info(f"Testing {len(param_names)} parameter(s): {Color.CYAN}{joined}{Color.RESET}")
    info(f"Running {len(rce_payloads)} RCE/SSTI payload(s)")

    rce_found_any = False
    ssti_found_any = False

    # Cache one baseline (benign-value) response body per parameter so every
    # probe can be diffed against "what this page normally looks like".
    # Without this, any page that happens to contain ordinary words like
    # "system", "root", or "administrator" in its nav/footer/CSS triggers
    # every keyword-based check regardless of whether the payload did anything.
    baseline_bodies = {}

    def get_baseline(param):
        if param not in baseline_bodies:
            baseline_params = {
                p: (v[0] if isinstance(v, list) else v)
                for p, v in (
                    params.items() if params else dict.fromkeys(param_names, "").items()
                )
            }
            baseline_params[param] = "eclipse_baseline_probe_12345"
            try:
                resp = s.get(
                    base_url,
                    params=baseline_params,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
                baseline_bodies[param] = resp.text
            except requests.RequestException:
                baseline_bodies[param] = ""
        return baseline_bodies[param]

    for param in param_names:
        baseline_body = get_baseline(param)
        for probe in rce_payloads:
            test_params = {
                p: (v[0] if isinstance(v, list) else v)
                for p, v in (
                    params.items() if params else dict.fromkeys(param_names, "").items()
                )
            }
            test_params[param] = probe["payload"]

            try:
                resp = s.get(
                    base_url,
                    params=test_params,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
                body = resp.text

                match = re.search(probe["pattern"], body, re.IGNORECASE)
                if not match:
                    continue

                # Differential check: if the same pattern already matches the
                # baseline (payload-free) response, it's just normal page
                # content, not evidence the injection executed.
                if re.search(probe["pattern"], baseline_body, re.IGNORECASE):
                    continue

                needs_oob = probe.get("requires_oob_confirmation", False)

                if needs_oob:
                    tag = "[LEAD]"
                    found(
                        f"{tag} Possible {probe['name']} "
                        "(needs out-of-band confirmation)"
                    )
                    found(f"    Parameter: {param}")
                    found(f"    Payload:   {probe['payload']}")
                    if probe.get("note"):
                        info(f"    Note: {probe['note']}")
                    info_msg = (
                        f"{probe['name']} via parameter '{param}' — unconfirmed, "
                        "requires OOB listener"
                    )
                    result("INFO", info_msg)

                    scan_results["leads"].append({
                        "type": probe["name"],
                        "param": param,
                        "payload": probe["payload"],
                        "note": probe.get("note", ""),
                    })
                    # Deliberately NOT setting rce_found_any here — an
                    # in-band body match can't confirm a blind/async vuln.
                    continue

                tag = "[RCE]" if "SSTI" not in probe["name"] else "[SSTI]"
                found(f"{tag} Vulnerability confirmed: {probe['name']}")
                found(f"    Parameter: {param}")
                found(f"    Payload:   {probe['payload']}")
                result(probe["severity"], f"{probe['name']} via parameter '{param}'")

                vuln_entry = {
                    "type": probe["name"],
                    "param": param,
                    "payload": probe["payload"],
                    "severity": probe["severity"],
                }
                scan_results["vulnerabilities"].append(vuln_entry)

                if "SSTI" in probe["name"]:
                    ssti_found_any = True
                else:
                    rce_found_any = True

            except requests.RequestException:
                pass

    _check_log4shell_headers(target_url, s, scan_results, timeout)

    if not rce_found_any and not ssti_found_any:
        ok("No obvious RCE or SSTI indicators found in GET parameters")
        result("PASS", "No RCE/SSTI detected in tested parameters")

    if scan_results["leads"]:
        msg = (
            f"{len(scan_results['leads'])} unconfirmed lead(s) logged — "
            "verify manually with an OOB listener before reporting as CRITICAL"
        )
        info(msg)

    scan_results["rce_found"] = rce_found_any
    scan_results["ssti_found"] = ssti_found_any

    return scan_results


def _check_log4shell_headers(target_url, session, scan_results, timeout):
    """Test Log4Shell-shaped headers while retaining only unconfirmed response leads.

    A response can never prove a JNDI callback occurred; confirmation requires an
    out-of-band DNS or LDAP listener.
    """
    info("Testing Log4Shell via request headers")

    headers_to_test = {
        "X-Api-Version": "${jndi:ldap://127.0.0.1:1389/a}",
        "User-Agent": "${jndi:ldap://127.0.0.1:1389/a}",
        "X-Forwarded-For": "${jndi:ldap://127.0.0.1:1389/a}",
        "Referer": "${jndi:ldap://127.0.0.1:1389/a}",
        "Accept-Language": "${jndi:ldap://127.0.0.1:1389/a}",
    }

    # Baseline with the header omitted/normal, so we only flag a header if the
    # payload-bearing request differs from a clean request to the same URL.
    try:
        baseline_resp = session.get(
            target_url, timeout=timeout, verify=False, allow_redirects=True
        )
        baseline_body = baseline_resp.text
    except requests.RequestException:
        baseline_body = ""

    # Tightened to the same structured-output shape used elsewhere (e.g. "id"
    # or "whoami" output), instead of bare "root"/"administrator" keywords
    # that show up in completely unrelated page content.
    pattern = (
        r"uid=\d+\([\w-]*\).*gid=\d+\([\w-]*\)"
        r"|\bnt authority\\(system|local service|network service)\b"
    )

    for header, payload in headers_to_test.items():
        try:
            resp = session.get(
                target_url,
                headers={header: payload},
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            body = resp.text

            matched = re.search(pattern, body, re.IGNORECASE)
            if matched and not re.search(pattern, baseline_body, re.IGNORECASE):
                found(
                    f"[LEAD] Possible Log4Shell via header: {header} "
                    "(needs out-of-band confirmation)"
                )
                note_text = (
                    "    Note: response-body matching cannot confirm Log4Shell — "
                    "the JNDI lookup is asynchronous/blind. Confirm with a DNS/LDAP "
                    "collaborator listener before treating this as CRITICAL."
                )
                info(note_text)
                result("INFO", f"Possible Log4Shell via {header} header — unconfirmed")
                scan_results["leads"].append({
                    "type": "Log4Shell (CVE-2021-44228) — unconfirmed",
                    "param": header,
                    "payload": payload,
                    "note": (
                        "Requires OOB (DNS/LDAP) listener to confirm; "
                        "body-match alone is not proof."
                    ),
                })

        except requests.RequestException:
            pass

    ok("Log4Shell header injection test completed")
