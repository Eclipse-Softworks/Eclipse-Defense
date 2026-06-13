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
│   └── tls_config.json              # TLS/cipher rules
├── scanner/                         # Security assessment modules
│   ├── __init__.py
│   ├── server_info.py               # Server fingerprinting & headers
│   ├── filter_bypass_checker.py     # XSS, SQLi, HTTP verb tampering
│   ├── rce_checker.py               # Remote code execution detection
│   ├── file_overwrite_checker.py    # Path traversal & file upload bypass
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
# Full scan (positional URL argument)
python main.py https://target.com

# Full scan (flag-based URL)
python main.py -u https://target.com

# Specific modules (positional URL)
python main.py https://target.com -m tls server
python main.py https://target.com/search?q=test -m rce filter file

# With custom timeout
python main.py https://target.com --timeout 15

# All modules explicitly
python main.py https://target.com --all

# All modules explicitly
python main.py -u https://target.com --all
```

## Modules

| Flag     | Description                                  |
|----------|----------------------------------------------|
| `tls`    | TLS version, cipher strength, cert validity  |
| `server` | Server banner, security headers, cookies     |
| `rce`    | RCE, SSTI, Log4Shell detection               |
| `file`   | Path traversal, file upload bypass, backups  |
| `filter` | XSS, SQLi, HTTP verb tampering, header inject|
