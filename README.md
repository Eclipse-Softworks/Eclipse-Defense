# Eclipse Defense - Security Scanner

Advanced Web Security Assessment Tool

## File Structure

```
Eclipse-Defense/
├── main.py                          # CLI entry point
├── config.json                      # Main scanner settings
├── requirements.txt                 # Python dependencies
├── .gitignore                       # Git ignore rules
├── config/                          # Configuration files (JSON)
│   ├── server_config.json           # Server detection rules
│   ├── filter_config.json           # XSS/SQLi detection payloads
│   ├── rce_config.json              # RCE/SSTI detection payloads
│   ├── file_config.json             # File traversal payloads
│   ├── rate_limit_config.json       # Bounded rate-limit probe settings
│   └── tls_config.json              # TLS/cipher rules
├── scanner/                         # Security assessment modules
│   ├── __init__.py
│   ├── server_info.py               # Server fingerprinting & headers
│   ├── filter_bypass_checker.py     # XSS, SQLi, HTTP verb tampering
│   ├── rce_checker.py               # Remote code execution detection
│   ├── file_overwrite_checker.py    # Path traversal & file upload bypass
│   ├── rate_limit/                  # Rate-limit assessment package
│   │   └── checker.py               # Bounded benign-request probe
│   └── tls_checker.py               # TLS/SSL assessment
└── utils/                           # Utility modules
    ├── __init__.py
    ├── colors.py                    # CLI color output helpers
    └── config_loader.py             # Configuration loading utility
```

## Architecture

All security detection rules and payloads are stored in JSON configuration files (`config/`). Scanner modules dynamically load configurations via the ConfigLoader utility, ensuring clean, maintainable code with zero hardcoded constants.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Full active scan (only after confirming that you are authorized to test the target)
python main.py https://target.com --authorized

# Full scan (flag-based URL)
python main.py -u https://target.com --authorized

# Specific modules (positional URL)
python main.py https://target.com -m tls server
python main.py https://target.com/search?q=test -m rce filter file --authorized
python main.py https://target.com/api -m rate --authorized

# With custom timeout
python main.py https://target.com --timeout 15 --authorized

# Logs to a file and enables verbose debug output
python main.py https://target.com --authorized --log-file eclipse.log --verbose

# All modules explicitly
python main.py https://target.com --all --authorized

# All modules explicitly
python main.py -u https://target.com --all --authorized
```

## Validation

```bash
python -m unittest discover -v tests
python -m ruff check .
```

The project also includes a GitHub Actions CI workflow that runs the existing unit tests
and the lint checks on pull requests and pushes.

## Modules

| Flag     | Description                                  |
|----------|----------------------------------------------|
| `tls`    | TLS version, cipher strength, cert validity  |
| `server` | Server banner, security headers, cookies     |
| `rce`    | RCE, SSTI, Log4Shell detection               |
| `file`   | Path traversal, file upload bypass, backups  |
| `filter` | XSS, SQLi, HTTP verb tampering, header inject|
| `rate`   | Bounded rate-limit header and enforcement check|

`rce`, `file`, `filter`, and `rate` send active requests. The rate-limit module
sends at most 20 benign, sequential requests and requires `--authorized`; a
missing signal is inconclusive and is never reported as a vulnerability.
