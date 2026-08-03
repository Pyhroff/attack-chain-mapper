"""Subdomain enumeration and DNS resolution helpers."""

import logging
import re
from ipaddress import ip_address

import dns.resolver
import requests
from bs4 import BeautifulSoup

import config
from utils import deduplicate

logger = logging.getLogger(__name__)
_SUBDOMAIN_REGEX_TEMPLATE = r"(?:[a-zA-Z0-9-]+\.)+{domain}"


def _is_valid_subdomain(value: str, domain: str) -> bool:
    if "@" in value or " " in value:
        return False
    return bool(
        re.fullmatch(r"[a-z0-9][a-z0-9.-]*", value)
        and value.endswith(domain.lower())
    )


def _extract_subdomains_from_text(text: str, domain: str) -> list[str]:
    pattern = re.compile(_SUBDOMAIN_REGEX_TEMPLATE.format(domain=re.escape(domain)))
    matches = pattern.findall(text)
    return deduplicate(
        [match.lower() for match in matches if _is_valid_subdomain(match.lower(), domain)]
    )


def _from_crt_sh(domain: str) -> list[str]:
    logger.info("Subdomain source: crt.sh")
    try:
        response = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=config.REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        results = response.json()
    except Exception as exc:
        logger.warning("crt.sh lookup failed for %s: %s", domain, exc)
        return []

    found: list[str] = []
    for entry in results:
        names = entry.get("name_value", "")
        for raw_name in names.splitlines():
            name = raw_name.strip().lower().lstrip("*.").rstrip(".")
            if _is_valid_subdomain(name, domain):
                found.append(name)
    return deduplicate(found)


def _from_shodan_ip_history(domain: str) -> list[str]:
    logger.info("Subdomain source: Shodan")
    if not config.SHODAN_API_KEY:
        logger.info("Skipping Shodan source: SHODAN_API_KEY not configured")
        return []

    try:
        import shodan
    except Exception as exc:
        logger.warning("Shodan package unavailable: %s", exc)
        return []

    api = shodan.Shodan(config.SHODAN_API_KEY)
    try:
        dns_records = dns.resolver.resolve(domain, "A")
        ips = [record.to_text() for record in dns_records]
    except Exception as exc:
        logger.warning("Unable to resolve %s for Shodan history: %s", domain, exc)
        return []

    found: list[str] = []
    for ip in ips:
        try:
            # Uses host history to identify historical hostnames tied to target IP.
            history = api.host(ip, history=True)
            for hostname in history.get("hostnames", []):
                normalized = hostname.lower().strip(".")
                if normalized.endswith(domain.lower()):
                    found.append(normalized)
        except Exception as exc:
            logger.warning("Shodan history failed for %s (%s): %s", domain, ip, exc)
    return deduplicate(found)


def _from_google_dorking(domain: str) -> list[str]:
    logger.info("Subdomain source: Google dorking")
    try:
        response = requests.get(
            "https://www.google.com/search",
            params={"q": f"site:*.{domain}"},
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/126.0.0.0 Safari/537.36"
                )
            },
            timeout=config.REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except Exception as exc:
        logger.warning("Google dorking failed for %s: %s", domain, exc)
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    text_blob = " ".join(soup.stripped_strings)
    return _extract_subdomains_from_text(text_blob, domain)


def find_subdomains(domain: str) -> list[str]:
    """Discover subdomains using CT logs, optional Shodan history, and search dorks."""
    sources = [
        _from_crt_sh(domain),
        _from_shodan_ip_history(domain),
        _from_google_dorking(domain),
        [f"www.{domain}"],
    ]
    flattened = [subdomain.rstrip(".").lower() for source in sources for subdomain in source]
    deduped = deduplicate(flattened)
    logger.info("Subdomain discovery complete: %d candidates", len(deduped))
    return deduped


def resolve_subdomains(subdomains: list[str]) -> dict[str, list[str]]:
    """Resolve subdomains to A/AAAA records; dead domains are skipped."""
    resolved: dict[str, list[str]] = {}
    for subdomain in subdomains:
        ips: list[str] = []
        for record_type in ("A", "AAAA"):
            try:
                answers = dns.resolver.resolve(subdomain, record_type)
                for answer in answers:
                    ip_text = answer.to_text()
                    # Validate and normalize IPs.
                    ips.append(str(ip_address(ip_text)))
            except Exception as exc:
                logger.debug("DNS %s lookup failed for %s: %s", record_type, subdomain, exc)
        unique_ips = deduplicate(ips)
        if unique_ips:
            resolved[subdomain] = unique_ips
        else:
            logger.warning("Unresolvable subdomain skipped: %s", subdomain)
    logger.info("DNS resolution complete: %d/%d resolved", len(resolved), len(subdomains))
    return resolved


def enumerate_subdomains(target: str, verbose: bool = False) -> list[str]:
    """Backward-compatible wrapper."""
    return find_subdomains(target)
