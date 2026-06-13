import argparse
import sys
import time
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from utils.colors import banner, section, result, info, found, ok, Color
from scanner import (
    check_tls,
    check_server_info,
    check_rce,
    check_file_overwrite,
    check_filter_bypass,
)

MODULES = {
    "tls":    ("TLS/SSL",                    check_tls),
    "server": ("Server Fingerprint",         check_server_info),
    "rce":    ("Remote Code Execution",      check_rce),
    "file":   ("File Overwrite/Traversal",   check_file_overwrite),
    "filter": ("Client Filter Bypass",       check_filter_bypass),
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="security_scanner",
        description="Eclipse Softworks Cyber Defense Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://example.com
  python main.py https://example.com -m tls server
  python main.py https://example.com -u https://example.com (alternative)
  python main.py https://example.com/search?q=test -m rce filter
  python main.py https://example.com --all
        """
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
    
    args = parser.parse_args()
    
    # Support both positional and flag-based URL specification
    if args.url_flag:
        args.url = args.url_flag
    
    if not args.url:
        parser.error("the following arguments are required: URL")
    
    return args


def print_summary(all_results):
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


def run_module(name, label, func, url, session):
    try:
        start = time.time()
        res   = func(url, session) if name != "tls" else func(url)
        elapsed = time.time() - start
        info(f"Module '{label}' completed in {elapsed:.2f}s")
        return res
    except Exception as e:
        found(f"Module '{label}' encountered an error: {e}")
        return {"error": str(e), "vulnerabilities": []}


def main():
    args = parse_args()

    banner()

    url = args.url.rstrip("/")
    if not url.startswith(("http://", "https://")):
        print(f"{Color.RED}[!] URL must start with http:// or https://{Color.RESET}")
        sys.exit(1)

    selected = args.modules if args.modules else list(MODULES.keys())

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
        if mod_key == "tls":
            res = run_module(mod_key, label, func, url, session)
        else:
            res = run_module(mod_key, label, func, url, session)
        all_results[mod_key] = res

    print_summary(all_results)
    print()


if __name__ == "__main__":
    main()
