"""Passive DNS collection via dnspython. No zone transfer unless authorized."""

from __future__ import annotations

import logging
from typing import Any

import dns.exception
import dns.resolver

log = logging.getLogger("bdosint")

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


def collect(domain: str, timeout: float = 10.0) -> dict[str, Any]:
    """Collect standard DNS records. Returns structured dict; never raises."""
    result: dict[str, Any] = {rt: [] for rt in RECORD_TYPES}
    result["dnssec"] = "unknown"
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            values = [_render(r, rtype) for r in answers]
            result[rtype] = sorted(set(values))
        except dns.resolver.NXDOMAIN:
            result["error"] = "NXDOMAIN — domain does not exist"
            return result
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NoNameservers as exc:
            result[f"{rtype}_error"] = f"no nameservers: {exc}"
        except dns.exception.Timeout:
            result[f"{rtype}_error"] = "timeout"
        except Exception as exc:
            result[f"{rtype}_error"] = str(exc)

    result["dnssec"] = _dnssec_status(domain, resolver)
    return result


def _render(rdata: Any, rtype: str) -> str:
    try:
        if rtype == "MX":
            return f"{int(rdata.preference)} {str(rdata.exchange).rstrip('.')}"
        if rtype == "TXT":
            if hasattr(rdata, "strings"):
                return "".join(p.decode() if isinstance(p, bytes) else str(p) for p in rdata.strings)
        return str(rdata).rstrip(".")
    except Exception:
        return str(rdata)


def _dnssec_status(domain: str, resolver: dns.resolver.Resolver) -> str:
    """Best-effort DNSSEC indication via DS record presence at parent."""
    try:
        parent = ".".join(domain.split(".")[-2:])
        resolver.resolve(parent, "DS")
        return "ads (DS present at parent)"
    except dns.resolver.NoAnswer:
        return "no DS record observed at parent"
    except Exception:
        return "unknown"


def collect_zone_transfer(domain: str, timeout: float = 10.0) -> dict[str, Any]:
    """AUTHORIZED-ONLY: attempt AXFR against each NS."""
    import dns.query
    import dns.zone
    results: dict[str, Any] = {}
    try:
        ns_answer = dns.resolver.resolve(domain, "NS")
        nameservers = [str(ns).rstrip(".") for ns in ns_answer]
    except Exception as exc:
        return {"error": f"could not resolve NS: {exc}"}
    for ns in nameservers:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=timeout))
            records = [n.to_text() for n in zone.nodes.values()]  # type: ignore[union-attr]
            results[ns] = {"axfr_succeeded": True, "record_count": len(records)}
        except Exception as exc:
            results[ns] = {"axfr_succeeded": False, "note": str(exc)}
    return results
