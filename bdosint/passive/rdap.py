"""RDAP registration data (public registry data only)."""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("bdosint")

_IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"


def _rdap_server(domain: str, http) -> str | None:
    """Resolve the authoritative RDAP server via IANA bootstrap."""
    data, err = http.get_json(_IANA_RDAP_BOOTSTRAP, provider="rdap")
    if err or not data:
        return None
    tld = domain.rsplit(".", 1)[-1]
    for entry in data.get("services", []):
        if tld in entry[0]:
            return entry[1][0]
    return None


def collect(domain: str, http) -> dict[str, Any]:
    """Collect public RDAP data. Privacy-redacted fields stay redacted."""
    server = _rdap_server(domain, http)
    if not server:
        return {"error": "no RDAP server found for TLD (registry may not support RDAP)"}
    url = f"{server.rstrip('/')}/domain/{domain}"
    data, err = http.get_json(url, provider="rdap")
    if err:
        return {"error": err}
    return _parse_rdap(data, url)


def _parse_rdap(data: dict[str, Any], source: str) -> dict[str, Any]:
    out: dict[str, Any] = {"source": source}

    def first_event(action: str) -> str | None:
        for ev in data.get("events", []):
            if ev.get("eventAction") == action:
                return ev.get("eventDate")
        return None

    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vcard = ent.get("vcardArray", [None, []])
            for item in (vcard[1] if len(vcard) > 1 else []):
                if item and item[0] == "fn":
                    registrar = item[3]
                    break
            if registrar is None:
                registrar = "[REDACTED OR NOT PUBLIC]"

    out.update({
        "domain": data.get("ldhName"),
        "status": data.get("status", []),
        "registrar": registrar or "not publicly listed",
        "created": first_event("registration"),
        "updated": first_event("last changed") or first_event("last update of RDAP database"),
        "expiry": first_event("expiration"),
        "nameservers": sorted({
            str(ns.get("ldhName", "")).lower().rstrip(".")
            for ns in data.get("nameservers", []) if ns.get("ldhName")
        }),
    })
    return out
