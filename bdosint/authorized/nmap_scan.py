"""AUTHORIZED-ONLY port scanning via nmap binary. Conservative options."""

from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Any

log = logging.getLogger("bdosint")

DEFAULT_PORTS = "80,443,22,21,25,53,110,143,3306,3389,8080,8443"
AUTHORIZATION_BANNER = (
    "AUTHORIZED PROFILE ACTIVE — you have asserted written permission "
    "to scan this target. BD-OSINT performs no brute force, no exploit "
    "execution, and no service authentication attempts."
)


def scan(target: str, ports: str = DEFAULT_PORTS, timeout: float = 15.0) -> dict[str, Any]:
    """Run conservative nmap service detection. Requires authorized profile."""
    nmap = shutil.which("nmap")
    if not nmap:
        return {"error": "nmap binary not found; install via 'sudo apt install nmap'"}
    cmd = [nmap, "-sV", "--version-light", "-Pn",
           "--max-rate", "150", "--host-timeout", "10m",
           "-p", ports, target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return {"error": "nmap run exceeded 15 minutes and was terminated"}
    if proc.returncode != 0:
        return {"error": f"nmap exited {proc.returncode}: {proc.stderr.strip()[:300]}"}

    services: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                services.append({
                    "port": parts[0], "state": "open",
                    "service": parts[2], "version": " ".join(parts[3:])[:120],
                })
    return {"target": target, "ports_scanned": ports, "services": services,
            "raw_output_tail": proc.stdout[-2000:]}
