"""Flat CSV tables: subdomains, DNS records, certificates, findings, technologies."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def write(scan_data: dict[str, Any], path: str) -> str:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)

        writer.writerow(["# SUBDOMAINS"])
        writer.writerow(["subdomain", "classification"])
        for s in (scan_data.get("subdomains") or {}).get("subdomains", []):
            writer.writerow([s.get("subdomain"), s.get("classification")])

        writer.writerow([])
        writer.writerow(["# DNS RECORDS"])
        writer.writerow(["type", "value"])
        dns = scan_data.get("dns") or {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            for value in dns.get(rtype, []):
                writer.writerow([rtype, value])

        writer.writerow([])
        writer.writerow(["# CERTIFICATES"])
        writer.writerow(["id", "issuer", "names", "first_seen"])
        for c in (scan_data.get("certificates") or {}).get("certificates", []):
            writer.writerow([c.get("id"), c.get("issuer"),
                             " ".join(c.get("names", [])), c.get("first_seen")])

        writer.writerow([])
        writer.writerow(["# FINDINGS"])
        writer.writerow(["title", "category", "severity", "confidence", "status", "evidence"])
        for f in scan_data.get("findings", []):
            d = f.to_dict() if hasattr(f, "to_dict") else f
            writer.writerow([d.get("title"), d.get("category"), d.get("severity"),
                             d.get("confidence"), d.get("status"), d.get("evidence")])

        writer.writerow([])
        writer.writerow(["# TECHNOLOGIES"])
        writer.writerow(["technology", "confidence", "version", "evidence"])
        for t in scan_data.get("technologies") or []:
            writer.writerow([t.get("technology"), t.get("confidence"),
                             t.get("version"), ";".join(t.get("evidence", []))])
    return str(out)
