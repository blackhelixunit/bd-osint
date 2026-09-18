"""Findings engine: conservative, evidence-based, never 'exploitable' by default."""

from __future__ import annotations

import logging
from typing import Any

from bdosint.models import Finding

log = logging.getLogger("bdosint")


def generate(scan_data: dict[str, Any]) -> list[Finding]:
    """Derive findings from collected data. All wording is conservative."""
    findings: list[Finding] = []

    dnssec = (scan_data.get("dns") or {}).get("dnssec", "unknown")
    if dnssec == "no DS record observed at parent":
        findings.append(Finding(
            title="DNSSEC not observed at parent zone",
            category="dns", severity="INFO", confidence="MEDIUM", status="observed",
            evidence="No DS record was observed at the parent zone via public DNS queries.",
            source="dns module",
            recommendation="Consider enabling DNSSEC if registry supports it.",
        ))

    xfr = (scan_data.get("authorized") or {}).get("zone_transfer") or {}
    for ns, res in xfr.items():
        if isinstance(res, dict) and res.get("axfr_succeeded"):
            findings.append(Finding(
                title=f"DNS zone transfer succeeded against {ns}",
                category="dns-misconfiguration", severity="MEDIUM",
                confidence="HIGH", status="verified",
                evidence=f"AXFR to {ns} returned zone data during authorized testing.",
                source="authorized/active_checks",
                recommendation="Restrict AXFR to approved secondary nameservers only.",
            ))

    for cname in (scan_data.get("dns") or {}).get("CNAME", []):
        findings.append(Finding(
            title="CNAME observed — verify target still exists",
            category="dns", severity="INFO", confidence="MEDIUM", status="potential",
            evidence=f"CNAME target observed: {cname}",
            source="dns module",
            recommendation=(
                "Verify the CNAME target resource still exists. "
                "A potential dangling DNS configuration observed; not confirmed exploitable."
            ),
        ))

    tls = scan_data.get("tls") or {}
    if tls.get("validity_status") == "expiring soon":
        findings.append(Finding(
            title="TLS certificate expiring soon",
            category="tls", severity="LOW", confidence="HIGH", status="observed",
            evidence=f"Certificate for {tls.get('host')} expires in {tls.get('days_remaining')} days.",
            source="tls module",
            recommendation="Renew the certificate before expiry.",
        ))
    elif tls.get("validity_status") == "expired":
        findings.append(Finding(
            title="TLS certificate expired",
            category="tls", severity="MEDIUM", confidence="HIGH", status="observed",
            evidence=f"Certificate for {tls.get('host')} is expired (not_after={tls.get('not_after')}).",
            source="tls module",
            recommendation="Replace the expired certificate immediately.",
        ))

    stxt = scan_data.get("securitytxt") or {}
    if stxt.get("found"):
        findings.append(Finding(
            title="security.txt published",
            category="process", severity="INFO", confidence="HIGH", status="observed",
            evidence=f"Found at {stxt.get('url')}",
            source="securitytxt module",
            recommendation="Good practice — keep contact information current.",
        ))

    wb = scan_data.get("wayback") or {}
    backups = [e for e in wb.get("interesting", []) if e.get("category") == "BACKUP-LIKE"]
    if backups:
        findings.append(Finding(
            title="Backup-like historical URLs observed in public archives",
            category="attack-surface", severity="LOW", confidence="MEDIUM", status="potential",
            evidence=f"{len(backups)} archive entries match backup-like patterns.",
            source="wayback module",
            recommendation="Verify these paths are no longer reachable and remove stale backup artifacts.",
        ))

    return findings
