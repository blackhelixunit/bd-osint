"""Conservative behavior rules for Bangladesh-sensitive targets."""

from __future__ import annotations

from bdosint.bangladesh.tld import BDTLDInfo, SENSITIVE_CATEGORIES

AUTHORIZED_MODULES_REQUIRING_CONFIRMATION = {"ports", "active"}


def policy_for(info: BDTLDInfo) -> dict:
    """Return the effective policy for a target domain."""
    sensitive = info.sensitive or info.category in SENSITIVE_CATEGORIES
    return {
        "is_bd": info.is_bd,
        "category": info.category,
        "sensitive": sensitive,
        "min_delay": 3.0 if sensitive else 1.0,
        "allow_authorized_profile": True,
        "note": (
            "Government/education domains: extra-conservative rates applied. "
            "Active scanning against these targets requires documented authorization."
            if sensitive else ""
        ),
    }
