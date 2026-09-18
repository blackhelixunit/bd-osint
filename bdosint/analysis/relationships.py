"""Relationship graph between domain entities."""

from __future__ import annotations

from typing import Any


def build(domain: str, dns: dict, subdomains: dict, certificates: dict) -> list[dict[str, str]]:
    """Build typed edges: domain/subdomain -> ip/cname/ns/mx/certificate."""
    edges: list[dict[str, str]] = []

    def edge(src: str, kind: str, dst: str) -> None:
        edges.append({"source": src, "relationship": kind, "target": dst})

    for ip in dns.get("A", []) + dns.get("AAAA", []):
        edge(domain, "A", ip)
    for mx in dns.get("MX", []):
        edge(domain, "MX", mx.split()[-1])
    for ns in dns.get("NS", []):
        edge(domain, "NS", ns)
    for cname in dns.get("CNAME", []):
        edge(domain, "CNAME", cname)
    for entry in subdomains.get("subdomains", []):
        edge(domain, "HAS_SUBDOMAIN", entry["subdomain"])
    for cert in certificates.get("certificates", [])[:50]:
        edge(domain, "CERTIFICATE", f"cert:{cert.get('id', '')} ({cert.get('issuer', 'unknown')})")

    return edges
