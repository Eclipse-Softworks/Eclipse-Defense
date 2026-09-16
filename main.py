import argparse
import sys
import time
import logging
import urllib3
import requests
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from utils.colors import banner, section, result, info, found, ok, Color
from scanner import (
    check_tls,
    check_server_info,
    check_rce,
    check_file_overwrite,
    check_filter_bypass,
    check_rate_limit,
)

logger = logging.getLogger("eclipse")

MODULES = {
    "tls":    ("TLS/SSL",                    check_tls),
    "server": ("Server Fingerprint",         check_server_info),
    "rce":    ("Remote Code Execution",      check_rce),
    "file":   ("File Overwrite/Traversal",   check_file_overwrite),
    "filter": ("Client Filter Bypass",       check_filter_bypass),
    "rate":   ("Rate Limiting",               check_rate_limit),
}
ACTIVE_MODULES = {"rce", "file", "filter", "rate"}


def parse_args():
    """Parse and normalize CLI options, accepting either supported URL form."""
    parser = argparse.ArgumentParser(
        prog="security_scanner",
        description="Eclipse Softworks Cyber Defense Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="Target URL to scan (positional or with -u flag)")
    parser.add_argument("-u", "--url-flag", dest="url_flag", help="Target URL to scan (flag format)")
    parser.add_argument("-m", "--modules", nargs="+",
                        choices=list(MODULES.keys()),
                        help="Modules to run (default: all)")
    parser.add_argument("--all",           action="store_true",
                        help="Run all modules (default behavior)")
    parser.add_argument("--timeout",       type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-color",      action="store_true",
                        help="Disable colored output")
    parser.add_argument("--authorized",    action="store_true",
                        help="Confirm you are authorized to run active probes")

    # Logging options
    parser.add_argument("--log-file", type=str, default=None,
                        help="Optional path to write structured logs to")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose (debug) logging to console")
    
    args = parser.parse_args()
    
    # Support both positional and flag-based URL specification
    if args.url and args.url_flag:
        parser.error("specify the target URL once, either positionally or with -u/--url-flag")

    if args.url_flag:
        args.url = args.url_flag
    
    if not args.url:
        parser.error("the following arguments are required: URL")

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    parsed_url = urlparse(args.url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
        parser.error("URL must include an http:// or https:// scheme and hostname")

    try:
        parsed_url.port
    except ValueError:
        parser.error("URL contains an invalid port")
    
    return args


def print_summary(all_results):
    """Aggregate normalized vulnerability records and render the terminal summary."""
    section("SCAN SUMMARY")

    total_vulns = []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for module_name, res in all_results.items():
        if isinstance(res, dict):
            vulns = res.get("vulnerabilities", [])
            total_vulns.extend(vulns)
            for v in vulns:
                sev = v.get("severity", "LOW").upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1

    print(f"\n  {Color.BOLD}Total vulnerabilities found: {Color.YELLOW}{len(total_vulns)}{Color.RESET}")
    print()
    print(f"  {Color.RED}{Color.BOLD}CRITICAL : {severity_counts['CRITICAL']}{Color.RESET}")
    print(f"  {Color.RED}HIGH     : {severity_counts['HIGH']}{Color.RESET}")
    print(f"  {Color.YELLOW}MEDIUM   : {severity_counts['MEDIUM']}{Color.RESET}")
    print(f"  {Color.CYAN}LOW      : {severity_counts['LOW']}{Color.RESET}")

    if total_vulns:
        print(f"\n  {Color.BOLD}{Color.WHITE}Vulnerability Breakdown:{Color.RESET}")
        for v in total_vulns:
            sev  = v.get("severity", "LOW")
            vtype = v.get("type", "Unknown")
            param = v.get("param", "-")
            colors = {
                "CRITICAL": Color.RED + Color.BOLD,
                "HIGH":     Color.RED,
                "MEDIUM":   Color.YELLOW,
                "LOW":      Color.CYAN,
            }
            c = colors.get(sev.upper(), Color.WHITE)
            print(f"  {c}[{sev}]{Color.RESET} {vtype} ({Color.GRAY}param: {param}{Color.RESET})")
    else:
        print(f"\n  {Color.GREEN}{Color.BOLD}No vulnerabilities detected in this scan.{Color.RESET}")
    print(f"\n  {Color.GRAY}Scan completed at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}{Color.RESET}")


def run_module(name, label, func, url, session, timeout):
    """Run one scanner module and convert an unexpected failure into a result."""
    try:
        start = time.time()
        res = func(url, timeout=timeout) if name == "tls" else func(url, session, timeout=timeout)
        elapsed = time.time() - start
        info(f"Module '{label}' completed in {elapsed:.2f}s")
        return res
    except Exception as e:
        found(f"Module '{label}' encountered an error: {e}")
        return {"error": str(e), "vulnerabilities": []}


def main():
    """Validate the target, create the shared HTTP session, and run selected modules."""
    args = parse_args()

    # Configure logging based on flags
    log_level = logging.DEBUG if args.verbose else logging.INFO
    handlers = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s", handlers=handlers)
    logger.setLevel(log_level)

    if args.no_color:
        Color.disable()

    banner()

    url = args.url.rstrip("/")
    selected = args.modules if args.modules else list(MODULES.keys())

    if ACTIVE_MODULES.intersection(selected) and not args.authorized:
        print(f"{Color.RED}[!] Active modules send requests beyond passive inspection. "
              f"Re-run with --authorized after confirming scope.{Color.RESET}")
        sys.exit(2)

    print(f"  {Color.BOLD}Target  : {Color.CYAN}{url}{Color.RESET}")
    print(f"  {Color.BOLD}Modules : {Color.CYAN}{', '.join(selected)}{Color.RESET}")
    print(f"  {Color.BOLD}Timeout : {Color.CYAN}{args.timeout}s{Color.RESET}")
    print()

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36"
    })

    all_results = {}

    for mod_key in selected:
        label, func = MODULES[mod_key]
        res = run_module(mod_key, label, func, url, session, args.timeout)
        all_results[mod_key] = res

    print_summary(all_results)
    print()


if __name__ == "__main__":
    main()
