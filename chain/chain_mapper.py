"""Attack chain mapping placeholders."""


def map_attack_chain(recon_data: dict, cve_data: list, verbose: bool = False) -> list:
    if verbose:
        print("[chain] Building possible attack chains")
    return [
        {
            "step": 1,
            "description": "Exploit CVE-2023-0000 on exposed nginx service",
            "source": {"recon": recon_data, "cves": cve_data},
        }
    ]
