import ssl
import socket
import datetime
from urllib.parse import urlparse
from utils.colors import section, result, info, found, ok, Color
from utils.config_loader import load_tls_config


def check_tls(target_url, timeout=10):
    """Inspect TLS connection, certificate, and legacy protocol support."""
    section("TLS / SSL SECURITY ASSESSMENT")

    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scan_results = {"vulnerabilities": []}

    if parsed.scheme != "https":
        result("HIGH", f"Target is not using HTTPS: {parsed.scheme}://")
        _add_vulnerability(
            scan_results,
            "TLS Not Enabled",
            "scheme",
            parsed.scheme or "unknown",
            "HIGH",
        )
        return scan_results

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()
                cipher_name, cipher_proto, cipher_bits = tls_sock.cipher()

                info(f"Connected to {Color.CYAN}{hostname}:{port}{Color.RESET}")

                scan_results["protocol"] = protocol
                scan_results["cipher"] = cipher_name
                scan_results["bits"] = cipher_bits

                _check_protocol_version(protocol, scan_results)
                _check_cipher_strength(cipher_name, cipher_bits, scan_results)
                _check_certificate(cert, hostname, scan_results)

    except ssl.SSLCertVerificationError as e:
        found(f"Certificate verification FAILED: {e}")
        result("CRITICAL", "Certificate is invalid or self-signed")
        scan_results["cert_valid"] = False
        _add_vulnerability(
            scan_results,
            "Invalid TLS Certificate",
            hostname,
            str(e),
            "CRITICAL",
        )

    except ssl.SSLError as e:
        found(f"SSL Error: {e}")
        scan_results["ssl_error"] = str(e)

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        found(f"Connection failed: {e}")
        scan_results["connection_error"] = str(e)

    _check_weak_protocol_support(hostname, port, scan_results, timeout)

    return scan_results


def _add_vulnerability(scan_results, vuln_type, param, payload, severity):
    scan_results.setdefault("vulnerabilities", []).append({
        "type": vuln_type,
        "param": param,
        "payload": payload,
        "severity": severity,
    })


def _check_protocol_version(protocol, scan_results):
    config = load_tls_config()
    safe_protocols = set(config["safe_protocols"])
    warn_protocols = set(config["warn_protocols"])

    if protocol in safe_protocols:
        ok(f"Protocol: {protocol}")
        result("PASS", f"Secure TLS version in use: {protocol}")
        scan_results["protocol_safe"] = True
    elif protocol in warn_protocols:
        found(f"Deprecated protocol detected: {protocol}")
        result("HIGH", f"Deprecated TLS version: {protocol} - upgrade to TLS 1.3")
        scan_results["protocol_safe"] = False
        _add_vulnerability(
            scan_results,
            "Deprecated TLS Protocol",
            "protocol",
            protocol,
            "HIGH",
        )
    else:
        found(f"Unknown or very old protocol: {protocol}")
        result("CRITICAL", f"Obsolete protocol: {protocol}")
        scan_results["protocol_safe"] = False
        _add_vulnerability(
            scan_results,
            "Obsolete TLS Protocol",
            "protocol",
            protocol,
            "CRITICAL",
        )


def _check_cipher_strength(cipher_name, cipher_bits, scan_results):
    config = load_tls_config()
    weak_ciphers = config["weak_ciphers"]

    info(f"Cipher suite: {Color.CYAN}{cipher_name}{Color.RESET} ({cipher_bits} bits)")

    weak_found = [w for w in weak_ciphers if w.upper() in cipher_name.upper()]

    if weak_found:
        found(f"Weak cipher detected: {cipher_name}")
        result("HIGH", f"Weak cipher in use: {', '.join(weak_found)}")
        scan_results["cipher_safe"] = False
        _add_vulnerability(
            scan_results,
            "Weak TLS Cipher",
            "cipher",
            cipher_name,
            "HIGH",
        )
    elif cipher_bits and cipher_bits < 128:
        found(f"Insufficient key length: {cipher_bits} bits")
        result("HIGH", f"Key length below 128 bits: {cipher_bits}")
        scan_results["cipher_safe"] = False
        _add_vulnerability(
            scan_results,
            "Weak TLS Key Length",
            "cipher_bits",
            str(cipher_bits),
            "HIGH",
        )
    else:
        ok(f"Cipher strength acceptable: {cipher_bits} bits")
        result("PASS", "Cipher suite is strong")
        scan_results["cipher_safe"] = True


def _check_certificate(cert, hostname, scan_results):
    """Validate certificate lifetime and SAN coverage, recording actionable findings."""
    if not cert:
        found("No certificate data retrieved")
        result("CRITICAL", "Certificate missing")
        _add_vulnerability(
            scan_results,
            "Missing TLS Certificate",
            hostname,
            "No certificate data retrieved",
            "CRITICAL",
        )
        return

    not_after_str = cert.get("notAfter", "")
    not_before_str = cert.get("notBefore", "")

    fmt = "%b %d %H:%M:%S %Y %Z"

    try:
        not_after = datetime.datetime.strptime(not_after_str, fmt)
        not_before = datetime.datetime.strptime(not_before_str, fmt)
        now = datetime.datetime.now(datetime.UTC)

        days_left = (not_after - now).days

        info(f"Certificate valid from: {Color.CYAN}{not_before.date()}{Color.RESET}")
        info(f"Certificate expires:    {Color.CYAN}{not_after.date()}{Color.RESET}")

        if days_left < 0:
            found(f"Certificate EXPIRED {abs(days_left)} days ago")
            result("CRITICAL", "Certificate has expired")
            scan_results["cert_expired"] = True
            _add_vulnerability(
                scan_results,
                "Expired TLS Certificate",
                hostname,
                not_after_str,
                "CRITICAL",
            )
        elif days_left < 14:
            found(f"Certificate expiring very soon: {days_left} days remaining")
            result("HIGH", f"Certificate expiring in {days_left} days")
            scan_results["cert_expiring_soon"] = True
            _add_vulnerability(
                scan_results,
                "TLS Certificate Expiring Soon",
                hostname,
                f"{days_left} days remaining",
                "HIGH",
            )
        elif days_left < 30:
            result("MEDIUM", f"Certificate expiring in {days_left} days")
            scan_results["cert_expiring_soon"] = True
            _add_vulnerability(
                scan_results,
                "TLS Certificate Expiring Soon",
                hostname,
                f"{days_left} days remaining",
                "MEDIUM",
            )
        else:
            ok(f"Certificate valid for {days_left} more days")
            result("PASS", "Certificate expiry is acceptable")
            scan_results["cert_expired"] = False

    except ValueError:
        found(f"Could not parse certificate dates: {not_after_str}")

    sans = cert.get("subjectAltName", ())
    san_hosts = [v for t, v in sans if t == "DNS"]
    san_join = ", ".join(san_hosts) if san_hosts else "None"
    san_info = f"Subject Alt Names (SAN): {Color.CYAN}{san_join}{Color.RESET}"
    info(san_info)

    if not san_hosts:
        result("MEDIUM", "No SAN entries found in certificate")
        scan_results["has_san"] = False
        _add_vulnerability(
            scan_results,
            "Missing Certificate SAN",
            hostname,
            "No subjectAltName entries",
            "MEDIUM",
        )
    else:
        match = any(_hostname_matches_san(hostname, san) for san in san_hosts)
        if match:
            ok("Hostname matches certificate SAN")
            result("PASS", "Hostname validated against SAN")
            scan_results["has_san"] = True
        else:
            san_list = ", ".join(san_hosts)
            found(
                f"Hostname {hostname} NOT found in SANs: "
                f"{san_list}"
            )
            result("HIGH", "Hostname mismatch with certificate SAN")
            scan_results["has_san"] = False
            _add_vulnerability(
                scan_results,
                "Certificate Hostname Mismatch",
                hostname,
                san_list,
                "HIGH",
            )


def _hostname_matches_san(hostname, san):
    """Apply TLS wildcard rules: ``*.example.com`` spans exactly one label."""
    hostname = hostname.lower().rstrip(".")
    san = san.lower().rstrip(".")
    if not san.startswith("*."):
        return hostname == san

    suffix = san[1:]
    return hostname.endswith(suffix) and hostname.count(".") == suffix.count(".")


def _check_weak_protocol_support(hostname, port, scan_results, timeout=10):
    """Attempt legacy TLS versions to detect support."""
    weak_versions = {
        "TLS 1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
        "TLS 1.1": ssl.TLSVersion.TLSv1_1
        if hasattr(ssl.TLSVersion, "TLSv1_1")
        else None,
    }

    for label, version in weak_versions.items():
        if version is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    found(f"Server accepts {label} (deprecated)")
                    result("HIGH", f"Weak protocol {label} is accepted by server")
                    scan_results[f"accepts_{label.replace(' ', '_').lower()}"] = True
                    _add_vulnerability(
                        scan_results,
                        "Weak TLS Protocol Supported",
                        "protocol",
                        label,
                        "HIGH",
                    )
        except ssl.SSLError:
            ok(f"Server rejects {label}")
            result("PASS", f"Server correctly rejects {label}")
            scan_results[f"accepts_{label.replace(' ', '_').lower()}"] = False
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            info(f"Could not determine {label} support: {exc}")
