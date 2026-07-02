import requests
import urllib.parse
import os
from utils.colors import section, result, info, found, ok, Color
from utils.config_loader import load_file_config


def check_file_overwrite(target_url, session=None):
    section("FILE OVERWRITE & PATH TRAVERSAL DETECTION")

    s = session or requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"})

    parsed   = urllib.parse.urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    params   = urllib.parse.parse_qs(parsed.query)

    scan_results = {
        "traversal_found":   False,
        "upload_bypass":     False,
        "vulnerabilities":   [],
    }

    _check_path_traversal(target_url, parsed, params, s, scan_results)
    _check_upload_endpoints(base_url, s, scan_results)
    _check_backup_files(base_url, s, scan_results)

    if not scan_results["traversal_found"] and not scan_results["upload_bypass"]:
        ok("No file overwrite or path traversal vulnerabilities detected")
        result("PASS", "File access controls appear to be in place")

    return scan_results


def _check_path_traversal(target_url, parsed, params, session, scan_results):
    config = load_file_config()
    file_param_names = config["file_param_names"]
    file_traversal_payloads = config["file_traversal_payloads"]
    
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    param_names = list(params.keys()) if params else file_param_names[:5]
    info(f"Testing path traversal on parameters: {Color.CYAN}{', '.join(param_names)}{Color.RESET}")

    for param in param_names:
        for payload in file_traversal_payloads:
            test_params = {p: (v[0] if isinstance(v, list) else v)
                           for p, v in (params.items() if params else {p: "" for p in param_names}.items())}
            test_params[param] = payload

            try:
                resp = session.get(base_url, params=test_params, timeout=8,
                                   verify=False, allow_redirects=True)
                body = resp.text

                if _detect_file_content(body, payload):
                    found(f"Path traversal confirmed!")
                    found(f"    Parameter: {param}")
                    found(f"    Payload:   {payload}")
                    result("CRITICAL", f"Directory traversal via '{param}' with payload '{payload}'")

                    scan_results["vulnerabilities"].append({
                        "type":     "Path Traversal / LFI",
                        "param":    param,
                        "payload":  payload,
                        "severity": "CRITICAL",
                    })
                    scan_results["traversal_found"] = True
                    break

            except requests.RequestException:
                pass


def _detect_file_content(body, payload):
    unix_indicators = ["root:x:", "daemon:x:", "nobody:", "bin/bash", "bin/sh"]
    win_indicators  = ["[extensions]", "[fonts]", "[files]", "for 16-bit"]

    if "passwd" in payload.lower() or "shadow" in payload.lower() or "hosts" in payload.lower():
        return any(ind in body for ind in unix_indicators)

    if "win.ini" in payload.lower():
        return any(ind in body.lower() for ind in win_indicators)

    return False


def _check_upload_endpoints(base_url, session, scan_results):
    config = load_file_config()
    upload_endpoints = config["upload_endpoints"]
    file_upload_bypass_payloads = config["file_upload_bypass_payloads"]
    
    info(f"Probing {len(upload_endpoints)} potential upload endpoints")

    found_endpoints = []

    for endpoint in upload_endpoints:
        url = base_url + endpoint
        try:
            resp = session.get(url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code not in (404, 410):
                found_endpoints.append((url, resp.status_code))
                info(f"Upload endpoint exists: {Color.YELLOW}{url}{Color.RESET} [{resp.status_code}]")
        except requests.RequestException:
            pass

    if not found_endpoints:
        ok("No upload endpoints discovered")
        return

    for url, status in found_endpoints:
        for payload_obj in file_upload_bypass_payloads:
            filename = payload_obj["filename"]
            content = payload_obj["content"].encode() if isinstance(payload_obj["content"], str) else payload_obj["content"]
            mime = payload_obj["mime_type"]
            files = {"file": (filename, content, mime)}
            try:
                resp = session.post(url, files=files, timeout=8, verify=False)

                if resp.status_code in (200, 201, 202):
                    body = resp.text.lower()
                    if any(kw in body for kw in ["success", "upload", "saved", "created", filename.lower()]):
                        found(f"File upload bypass succeeded!")
                        found(f"Endpoint: {url}")
                        found(f"Filename: {filename}")
                        found(f"MIME:     {mime}")
                        result("CRITICAL", f"Upload bypass with filename '{filename}' at {url}")
                        scan_results["upload_bypass"] = True
                        scan_results["vulnerabilities"].append({
                            "type":     "File Upload Bypass",
                            "param":    url,
                            "payload":  filename,
                            "severity": "CRITICAL",
                        })

            except requests.RequestException:
                pass


def _check_backup_files(base_url, session, scan_results):
    backup_patterns = [
        "/backup.zip", "/backup.tar.gz", "/backup.sql",
        "/.git/config", "/.git/HEAD",
        "/.env", "/.env.backup", "/.env.local",
        "/config.php.bak", "/wp-config.php.bak",
        "/web.config.bak", "/database.yml",
        "/Gemfile", "/package.json", "/composer.json",
        "/phpinfo.php", "/info.php", "/test.php",
        "/.DS_Store", "/thumbs.db",
        "/server-status", "/server-info",
        "/robots.txt", "/sitemap.xml",
    ]

    info(f"Checking {len(backup_patterns)} sensitive file paths")

    for path in backup_patterns:
        url = base_url + path
        try:
            resp = session.get(url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code == 200 and len(resp.text) > 10:
                severity = "CRITICAL" if any(x in path for x in [".env", ".git", "phpinfo", "config", ".sql"]) else "MEDIUM"
                found(f"Sensitive file exposed: {path}")
                result(severity, f"Publicly accessible: {url}")
                scan_results["vulnerabilities"].append({
                    "type":     "Sensitive File Exposure",
                    "param":    path,
                    "payload":  "GET request",
                    "severity": severity,
                })
        except requests.RequestException:
            pass
