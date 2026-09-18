"""JSON report writer matching the documented schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def build_report(scan_data: dict[str, Any], target: str, scope: dict) -> dict[str, Any]:
    from bdosint import __tool_name__, __version__
    return {
        "tool": __tool_name__,
        "version": __version__,
        "target": target,
        "timestamp": scan_data.get("timestamp"),
        "scope": scope,
        "bangladesh": scan_data.get("bangladesh"),
        "dns": scan_data.get("dns"),
        "rdap": scan_data.get("rdap"),
        "certificates": scan_data.get("certificates"),
        "subdomains": (scan_data.get("subdomains") or {}).get("subdomains", []),
        "http": scan_data.get("http"),
        "tls": scan_data.get("tls"),
        "securitytxt": scan_data.get("securitytxt"),
        "technologies": scan_data.get("technologies"),
        "security_headers": scan_data.get("security_headers"),
        "wayback": scan_data.get("wayback"),
        "relationships": scan_data.get("relationships"),
        "authorized": scan_data.get("authorized"),
        "findings": [f.to_dict() if hasattr(f, "to_dict") else f
                     for f in scan_data.get("findings", [])],
        "module_results": scan_data.get("module_results", []),
    }


def write(scan_data: dict[str, Any], target: str, scope: dict, path: str) -> str:
    report = build_report(scan_data, target, scope)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
    return str(out)
