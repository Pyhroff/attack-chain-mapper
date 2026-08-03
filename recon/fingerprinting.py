"""Service fingerprinting logic."""

import logging
import re
import socket
import ssl
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup

import config

logger = logging.getLogger(__name__)


def _collect_http_metadata(url: str) -> dict:
    metadata = {
        "url": url,
        "status_code": None,
        "server": None,
        "title": None,
        "headers": {},
        "error": None,
    }
    try:
        head_response = requests.head(url, timeout=config.REQUEST_TIMEOUT_SECONDS, allow_redirects=True)
        metadata["status_code"] = head_response.status_code
        metadata["server"] = head_response.headers.get("Server")
        metadata["headers"] = dict(head_response.headers)
    except Exception as exc:
        metadata["error"] = f"HEAD failed: {exc}"
        logger.warning("HTTP HEAD failed for %s: %s", url, exc)
        return metadata

    try:
        get_response = requests.get(url, timeout=config.REQUEST_TIMEOUT_SECONDS, allow_redirects=True)
        soup = BeautifulSoup(get_response.text, "html.parser")
        if soup.title and soup.title.string:
            metadata["title"] = soup.title.string.strip()
    except Exception as exc:
        logger.debug("HTTP GET title extraction failed for %s: %s", url, exc)
    return metadata


def _parse_ssl_certificate(hostname: str, ip: str) -> dict:
    cert_data = {
        "issuer": None,
        "valid_from": None,
        "valid_to": None,
        "is_valid_now": None,
        "sans": [],
        "error": None,
    }
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=config.REQUEST_TIMEOUT_SECONDS) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
    except Exception as exc:
        cert_data["error"] = str(exc)
        logger.warning("SSL certificate parsing failed for %s (%s): %s", hostname, ip, exc)
        return cert_data

    issuer_entries = cert.get("issuer", [])
    issuer_parts: list[str] = []
    for entry_group in issuer_entries:
        for key, value in entry_group:
            issuer_parts.append(f"{key}={value}")
    cert_data["issuer"] = ", ".join(issuer_parts) if issuer_parts else None

    cert_data["valid_from"] = cert.get("notBefore")
    cert_data["valid_to"] = cert.get("notAfter")
    if cert_data["valid_from"] and cert_data["valid_to"]:
        try:
            start = datetime.strptime(cert_data["valid_from"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            end = datetime.strptime(cert_data["valid_to"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            now = datetime.now(timezone.utc)
            cert_data["is_valid_now"] = start <= now <= end
        except Exception:
            cert_data["is_valid_now"] = None

    sans: list[str] = []
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type == "DNS":
            sans.append(san_value)
    cert_data["sans"] = sans
    return cert_data


def _detect_tech_stack(domain: str, http_data: dict, https_data: dict) -> list[dict]:
    findings: list[dict] = []
    all_headers = {}
    all_headers.update(http_data.get("headers") or {})
    all_headers.update(https_data.get("headers") or {})

    server_header = (all_headers.get("Server") or all_headers.get("server") or "").lower()

    if "jenkins" in server_header:
        version = all_headers.get("X-Jenkins") or "unknown"
        findings.append({"technology": "Jenkins", "version": str(version), "source": "headers"})

    if "nginx" in server_header:
        version_match = re.search(r"nginx/?([0-9.]+)?", server_header)
        version = version_match.group(1) if version_match and version_match.group(1) else "unknown"
        findings.append({"technology": "nginx", "version": version, "source": "server_header"})

    if "s3" in domain.lower() or ".s3." in domain.lower():
        findings.append({"technology": "AWS S3", "version": None, "source": "domain_pattern"})
    elif "x-amz-bucket-region" in {key.lower() for key in all_headers.keys()}:
        findings.append({"technology": "AWS S3", "version": None, "source": "amz_header"})

    try:
        docker_probe = requests.get(
            f"http://{domain}/v2/",
            timeout=config.REQUEST_TIMEOUT_SECONDS,
            allow_redirects=True,
        )
        if docker_probe.status_code in (200, 401):
            findings.append(
                {
                    "technology": "Docker Registry",
                    "version": None,
                    "source": "/v2/ endpoint",
                    "status_code": docker_probe.status_code,
                }
            )
    except Exception as exc:
        logger.debug("Docker registry probe failed for %s: %s", domain, exc)

    return findings


def fingerprint_service(domain: str, ip: str) -> dict:
    """Fingerprint a domain+IP service over HTTP, HTTPS, and TLS metadata."""
    logger.info("Fingerprinting %s (%s)", domain, ip)
    http_url = f"http://{domain}:80"
    https_url = f"https://{domain}:443"
    http_data = _collect_http_metadata(http_url)
    https_data = _collect_http_metadata(https_url)
    ssl_certificate = _parse_ssl_certificate(domain, ip)
    tech_stack = _detect_tech_stack(domain, http_data, https_data)

    return {
        "domain": domain,
        "ip": ip,
        "http": http_data,
        "https": https_data,
        "ssl_certificate": ssl_certificate,
        "tech_stack": tech_stack,
    }


def fingerprint_target(target: str, verbose: bool = False) -> dict:
    """Backward-compatible placeholder wrapper."""
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target
    return fingerprint_service(target, ip)
