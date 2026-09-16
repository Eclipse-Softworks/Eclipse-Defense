import requests
import urllib.parse
import os
import json
from utils.colors import section, result, info, found, ok, Color
from utils.config_loader import load_file_config


def check_file_overwrite(target_url, session=None, timeout=10):
    """Probe for traversal, upload-validation, and publicly exposed sensitive files."""
    section("FILE OVERWRITE & PATH TRAVERSAL DETECTION")

    s = session or requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"})

    parsed = urllib.parse.urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    params = urllib.parse.parse_qs(parsed.query)

    scan_results = {
        "traversal_found": False,
        "upload_bypass": False,
        "sensitive_file_found": False,
        "vulnerabilities": [],
    }

    _check_path_traversal(target_url, parsed, params, s, scan_results, timeout)
    _check_upload_endpoints(base_url, s, scan_results, timeout)
    _check_backup_files(base_url, s, scan_results, timeout)

    if not any((
        scan_results["traversal_found"],
        scan_results["upload_bypass"],
        scan_results["sensitive_file_found"],
    )):
        ok("No file overwrite or path traversal vulnerabilities detected")
        result("PASS", "File access controls appear to be in place")

    return scan_results


def _check_path_traversal(target_url, parsed, params, session, scan_results, timeout):
    """Try traversal payloads on file-like parameters and detect file content."""
    config = load_file_config()
    file_param_names = config["file_param_names"]
    file_traversal_payloads = config["file_traversal_payloads"]

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    param_names = list(params.keys()) if params else file_param_names[:5]
    joined = ", ".join(param_names)
    info(f"Testing path traversal on parameters: {Color.CYAN}{joined}{Color.RESET}")

    for param in param_names:
        baseline_params = {
            p: (v[0] if isinstance(v, list) else v)
            for p, v in (
                params.items() if params else dict.fromkeys(param_names, "").items()
            )
        }
        baseline_params[param] = "eclipse_baseline_probe_12345"
        try:
            baseline_body = session.get(
                base_url,
                params=baseline_params,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            ).text
        except requests.RequestException:
            info(f"Skip checks for '{param}':request failed")
            continue

        for payload in file_traversal_payloads:
            test_params = {
                p: (v[0] if isinstance(v, list) else v)
                for p, v in (
                    params.items() if params else dict.fromkeys(param_names, "").items()
                )
            }
            test_params[param] = payload

            try:
                resp = session.get(
                    base_url,
                    params=test_params,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
                body = resp.text

                if _detect_file_content(body, payload) and not _detect_file_content(
                    baseline_body, payload
                ):
                    found("Path traversal confirmed!")
                    found(f"    Parameter: {param}")
                    found(f"    Payload:   {payload}")
                    result(
                        "CRITICAL",
                        f"Directory traversal via '{param}' with payload '{payload}'",
                    )

                    scan_results["vulnerabilities"].append({
                        "type": "Path Traversal / LFI",
                        "param": param,
                        "payload": payload,
                        "severity": "CRITICAL",
                    })
                    scan_results["traversal_found"] = True
                    break

            except requests.RequestException:
                pass


def _detect_file_content(body, payload):
    unix_indicators = ["root:x:", "daemon:x:", "nobody:", "bin/bash", "bin/sh"]
    win_indicators = ["[extensions]", "[fonts]", "[files]", "for 16-bit"]

    if (
        "passwd" in payload.lower()
        or "shadow" in payload.lower()
        or "hosts" in payload.lower()
    ):
        return any(ind in body for ind in unix_indicators)

    if "win.ini" in payload.lower():
        return any(ind in body.lower() for ind in win_indicators)

    return False


def _check_upload_endpoints(base_url, session, scan_results, timeout):
    config = load_file_config()
    upload_endpoints = config["upload_endpoints"]
    file_upload_bypass_payloads = config["file_upload_bypass_payloads"]

    info(f"Probing {len(upload_endpoints)} potential upload endpoints")

    found_endpoints = []
    control_sig = _get_control_signature(
        base_url + "/eclipse_baseline_nonexistent_upload_12345.xyz",
        session,
        timeout=timeout,
        allow_redirects=False,
    )

    for endpoint in upload_endpoints:
        url = base_url + endpoint
        try:
            resp = session.get(
                url, timeout=timeout, verify=False, allow_redirects=False
            )
            if resp.status_code not in (404, 410) and _differs_from_control(
                resp, control_sig
            ):
                found_endpoints.append((url, resp.status_code))
                url_display = f"{Color.YELLOW}{url}{Color.RESET}"
                info(f"Upload endpoint exists: {url_display} [{resp.status_code}]")
        except requests.RequestException:
            pass

    if not found_endpoints:
        ok("No upload endpoints discovered")
        return

    for url, status in found_endpoints:
        for payload_obj in file_upload_bypass_payloads:
            filename = payload_obj["filename"]
            content = (
                payload_obj["content"].encode()
                if isinstance(payload_obj["content"], str)
                else payload_obj["content"]
            )
            mime = payload_obj["mime_type"]
            files = {"file": (filename, content, mime)}
            try:
                resp = session.post(url, files=files, timeout=timeout, verify=False)

                if resp.status_code in (200, 201, 202):
                    if _upload_bypass_confirmed(
                        resp, session, url, filename, content, timeout
                    ):
                        found("File upload bypass succeeded!")
                        found(f"Endpoint: {url}")
                        found(f"Filename: {filename}")
                        found(f"MIME:     {mime}")
                        result(
                            "CRITICAL",
                            f"Upload bypass with filename '{filename}' at {url}",
                        )
                        scan_results["upload_bypass"] = True
                        scan_results["vulnerabilities"].append({
                            "type": "File Upload Bypass",
                            "param": url,
                            "payload": filename,
                            "severity": "CRITICAL",
                        })

            except requests.RequestException:
                pass


def _check_backup_files(base_url, session, scan_results, timeout):
    backup_patterns = [
        "/backup.zip",
        "/backup.tar.gz",
        "/backup.sql",
        "/.git/config",
        "/.git/HEAD",
        "/.env",
        "/.env.backup",
        "/.env.local",
        "/config.php.bak",
        "/wp-config.php.bak",
        "/web.config.bak",
        "/database.yml",
        "/Gemfile",
        "/package.json",
        "/composer.json",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/.DS_Store",
        "/thumbs.db",
        "/server-status",
        "/server-info",
    ]

    info(f"Checking {len(backup_patterns)} sensitive file paths")
    control_sig = _get_control_signature(
        base_url + "/eclipse_baseline_nonexistent_12345.xyz",
        session,
        timeout=timeout,
        allow_redirects=False,
    )

    for path in backup_patterns:
        url = base_url + path
        try:
            resp = session.get(
                url, timeout=timeout, verify=False, allow_redirects=False
            )
            if (
                resp.status_code == 200
                and len(resp.text) > 10
                and _differs_from_control(resp, control_sig)
            ):
                severity = (
                    "CRITICAL"
                    if any(
                        x in path for x in [".env", ".git", "phpinfo", "config", ".sql"]
                    )
                    else "MEDIUM"
                )
                found(f"Sensitive file exposed: {path}")
                result(severity, f"Publicly accessible: {url}")
                scan_results["vulnerabilities"].append({
                    "type": "Sensitive File Exposure",
                    "param": path,
                    "payload": "GET request",
                    "severity": severity,
                })
                scan_results["sensitive_file_found"] = True
        except requests.RequestException:
            pass


def _get_control_signature(url, session, timeout=5, allow_redirects=False):
    """Return a baseline status/body-size signature for soft-404 comparison."""
    try:
        resp = session.get(
            url, timeout=timeout, verify=False, allow_redirects=allow_redirects
        )
        return (resp.status_code, len(resp.text))
    except requests.RequestException:
        return None


def _differs_from_control(resp, control_sig):
    if control_sig is None:
        # Without a control response, a custom 200/soft-404 page cannot be
        # distinguished from a genuinely exposed endpoint.
        return False

    control_status, control_len = control_sig
    body_len = len(resp.text)

    if resp.status_code != control_status:
        return True

    return abs(body_len - control_len) > max(50, int(control_len * 0.10))


def _upload_bypass_confirmed(resp, session, upload_url, filename, content, timeout):
    """Confirm an upload only when the response or retrievable file identifies it."""
    if _json_upload_response_matches(resp, filename):
        return True

    for candidate_url in _upload_file_candidates(resp, upload_url, filename):
        try:
            check = session.get(
                candidate_url, timeout=timeout, verify=False, allow_redirects=True
            )
            if check.status_code == 200 and content in check.content:
                return True
        except requests.RequestException:
            pass

    return False


def _json_upload_response_matches(resp, filename):
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return False

    for key, value in _walk_json(data):
        if key.lower() in {"path", "url", "filename", "file", "filepath"}:
            if isinstance(value, str) and os.path.basename(value) == filename:
                return True

    return False


def _upload_file_candidates(resp, upload_url, filename):
    candidates = []

    location = resp.headers.get("Location")
    if location and filename in location:
        candidates.append(urllib.parse.urljoin(upload_url, location))

    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        data = None

    if data is not None:
        for key, value in _walk_json(data):
            if key.lower() in {"path", "url", "filename", "file", "filepath"}:
                if isinstance(value, str) and os.path.basename(value) == filename:
                    candidates.append(urllib.parse.urljoin(upload_url, value))

    candidates.extend([
        urllib.parse.urljoin(upload_url.rstrip("/") + "/", filename),
        urllib.parse.urljoin(upload_url.rsplit("/", 1)[0] + "/", filename),
        urllib.parse.urljoin(upload_url, "/uploads/" + filename),
    ])

    return list(dict.fromkeys(candidates))


def _walk_json(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk_json(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_json(item)
