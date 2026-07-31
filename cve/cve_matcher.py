"""CVE matching placeholders."""


def match_cves(recon_data: dict, verbose: bool = False) -> list:
    if verbose:
        print("[cve] Matching CVEs from recon data")
    return [
        {
            "id": "CVE-2023-0000",
            "component": "nginx",
            "cvss": 7.5,
        }
    ]
