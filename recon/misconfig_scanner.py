"""Misconfiguration scanner placeholders."""


def scan_misconfigurations(target: str, verbose: bool = False) -> list:
    if verbose:
        print(f"[recon] Scanning misconfigurations for {target}")
    return [{"finding": "Directory listing enabled", "severity": "medium"}]
