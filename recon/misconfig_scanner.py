"""Misconfiguration scanning helpers."""

import logging
import re

import dns.resolver
import requests

from config import REQUEST_TIMEOUT_SECONDS, SHODAN_API_KEY

logger = logging.getLogger(__name__)


def check_s3_buckets(domain: str) -> list[dict]:
    """Find likely S3 buckets and check public accessibility."""
    label = domain.replace(".", "-")
    candidates = [
        label,
        f"{label}-backup",
        f"{label}-backups",
        f"{label}-logs",
        f"{label}-data",
        f"{label}-assets",
        f"{label}-static",
    ]
    if SHODAN_API_KEY:
        logger.info("S3 bucket check: Shodan key detected (direct checks enabled regardless)")
    else:
        logger.info("S3 bucket check: no Shodan key; using direct bucket checks")

    findings: list[dict] = []
    for bucket in candidates:
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
        except Exception as exc:
            logger.debug("S3 probe failed for %s: %s", bucket, exc)
            continue

        if response.status_code == 200 and "<ListBucketResult" in response.text:
            findings.append(
                {
                    "bucket": bucket,
                    "url": url,
                    "permission": "public_list",
                    "status_code": response.status_code,
                }
            )
        elif response.status_code in (200, 403):
            findings.append(
                {
                    "bucket": bucket,
                    "url": url,
                    "permission": "public_read_or_exists",
                    "status_code": response.status_code,
                }
            )

    logger.info("S3 bucket check complete: %d potentially accessible buckets", len(findings))
    return findings


def check_github_leaks(domain: str) -> dict:
    """Count potential secret leaks related to the domain in public GitHub code search."""
    logger.info("Checking GitHub leak indicators for %s", domain)
    queries = [f'"{domain}" password', f'"{domain}" api_key']
    total = 0
    endpoint = "https://api.github.com/search/code"
    headers = {"Accept": "application/vnd.github+json"}
    for query in queries:
        try:
            response = requests.get(
                endpoint,
                params={"q": query, "per_page": 1},
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                logger.warning(
                    "GitHub API returned %s for query %r", response.status_code, query
                )
                continue
            payload = response.json()
            total += int(payload.get("total_count", 0))
        except Exception as exc:
            logger.warning("GitHub API query failed for %r: %s", query, exc)

    return {"query_domain": domain, "result_count": total}


def _query_dns_txt(name: str) -> list[str]:
    values: list[str] = []
    try:
        answers = dns.resolver.resolve(name, "TXT")
        for answer in answers:
            values.append("".join(part.decode() if isinstance(part, bytes) else str(part) for part in answer.strings))
    except Exception:
        return []
    return values


def check_dns_records(domain: str) -> dict:
    """Collect DNS records and flag SPF/DKIM/DMARC weaknesses."""
    logger.info("Checking DNS records for %s", domain)
    record_data = {"MX": [], "TXT": [], "NS": []}
    weaknesses: list[str] = []

    for record_type in ("MX", "TXT", "NS"):
        try:
            answers = dns.resolver.resolve(domain, record_type)
            record_data[record_type] = [answer.to_text() for answer in answers]
        except Exception as exc:
            logger.warning("DNS %s lookup failed for %s: %s", record_type, domain, exc)

    spf_records = [txt for txt in record_data["TXT"] if "v=spf1" in txt.lower()]
    if not spf_records:
        weaknesses.append("No SPF record found")
    else:
        for spf in spf_records:
            if "+all" in spf.lower():
                weaknesses.append("Overly permissive SPF (+all)")

    dmarc_records = _query_dns_txt(f"_dmarc.{domain}")
    if not dmarc_records:
        weaknesses.append("No DMARC record found")
    else:
        dmarc_joined = " ".join(dmarc_records).lower()
        if "p=none" in dmarc_joined:
            weaknesses.append("Permissive DMARC policy (p=none)")

    dkim_records = _query_dns_txt(f"default._domainkey.{domain}")
    if not dkim_records:
        weaknesses.append("No DKIM record found on default selector")
    else:
        dkim_joined = " ".join(dkim_records).lower()
        if re.search(r"\bt=y\b", dkim_joined):
            weaknesses.append("Permissive DKIM in testing mode (t=y)")

    return {
        "domain": domain,
        "records": record_data,
        "spf_records": spf_records,
        "dmarc_records": dmarc_records,
        "dkim_records": dkim_records,
        "weaknesses": weaknesses,
    }


def scan_misconfigurations(target: str, verbose: bool = False) -> list:
    """Backward-compatible wrapper for combined misconfiguration checks."""
    results = [
        {"check": "s3_buckets", "result": check_s3_buckets(target)},
        {"check": "github_leaks", "result": check_github_leaks(target)},
        {"check": "dns_records", "result": check_dns_records(target)},
    ]
    return results
