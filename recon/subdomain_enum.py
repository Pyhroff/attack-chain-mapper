"""Subdomain enumeration placeholders."""


def enumerate_subdomains(target: str, verbose: bool = False) -> list:
    if verbose:
        print(f"[recon] Enumerating subdomains for {target}")
    return [f"www.{target}", f"api.{target}"]
