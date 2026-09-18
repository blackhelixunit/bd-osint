"""Certificate Transparency via crt.sh (public logs only)."""

from __future__ import annotations

import logging
from typing import Any

from bdosint.core.normalization import dedupe_ordered, normalize_domain_set

log = logging.getLogger("bdosint")

CRTSH_URL = "https://crt.sh/"


def collect(domain: str, http) -> dict[str, Any]:
    """Query crt.sh JSON endpoint for certificate log entries."""
    data, err = http.get_json(
        CRTSH_URL, provider="crtsh", params={"q": f"%.{domain}", "output": "json"}
    )
    if err:
        return {"error": err, "certificates": [], "names": []}
    if not isinstance(data, list):
        return {"error": "unexpected crt.sh response", "certificates": [], "names": []}

    certs: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    for entry in data:
        issuer = _extract_issuer(entry)
        name_values = (entry.get("name_value") or "").split("\n")
        for name in name_values:
            n = name.strip().lstrip("*").lstrip(".").lower()
            if not n or not n.endswith(domain):
                continue
            names.add(n)
        cert_id = str(entry.get("id") or entry.get("min_cert_id") or len(certs))
        info = certs.setdefault(cert_id, {
            "id": cert_id,
            "issuer": issuer,
            "names": [],
            "first_seen": entry.get("entry_timestamp") or entry.get("not_before"),
            "last_seen": entry.get("entry_timestamp"),
        })
        for name in name_values:
            nn = name.strip().lower().rstrip(".")
            if nn and nn not in info["names"]:
                info["names"].append(nn)

    return {
        "certificates": list(certs.values())[:500],
        "names": dedupe_ordered(sorted(names)),
        "total_entries_seen": len(data),
    }


def _extract_issuer(entry: dict[str, Any]) -> str:
    raw = entry.get("issuer_name") or ""
    for part in raw.split(","):
        part = part.strip()
        if part.upper().startswith("O=") and len(part) > 2:
            return part[2:]
    return raw or "unknown"
