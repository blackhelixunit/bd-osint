"""Target and scope validation. Never silently expands scope."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\.?$",
    re.IGNORECASE,
)


def is_valid_domain(domain: str) -> bool:
    """Return True for syntactically valid domain names."""
    if not domain or len(domain) > 253:
        return False
    domain = domain.strip().rstrip(".").lower()
    if domain.startswith("*."):
        return is_valid_domain(domain[2:])
    if not _DOMAIN_RE.match(domain):
        return False
    return True


def normalize_domain(domain: str) -> str:
    """Lowercase, strip scheme/port/path/trailing dot."""
    d = domain.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split(":")[0].rstrip(".")
    return d


@dataclass
class Scope:
    """Scope container: exact domains plus optional wildcard suffixes."""

    exact: set[str] = field(default_factory=set)
    wildcards: set[str] = field(default_factory=set)

    @classmethod
    def from_target(cls, target: str) -> "Scope":
        t = normalize_domain(target)
        if not is_valid_domain(t):
            raise ValueError(f"Invalid target domain: {target!r}")
        return cls(exact={t}, wildcards={t})

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        scope = cls()
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            line = normalize_domain(line)
            if not is_valid_domain(line):
                raise ValueError(f"Invalid scope entry: {raw!r}")
            if line.startswith("*."):
                scope.wildcards.add(line[2:])
            else:
                scope.exact.add(line)
                scope.wildcards.add(line)
        if not scope.exact and not scope.wildcards:
            raise ValueError("Scope file is empty")
        return scope

    def contains(self, domain: str) -> bool:
        d = normalize_domain(domain)
        if d in self.exact:
            return True
        return any(d == w or d.endswith("." + w) for w in self.wildcards)

    def to_dict(self) -> dict:
        return {"exact": sorted(self.exact), "wildcards": sorted(self.wildcards)}


def validate_target_in_scope(target: str, scope: Optional[Scope]) -> Scope:
    t = normalize_domain(target)
    if not is_valid_domain(t):
        raise ValueError(f"Invalid target domain: {target!r}")
    if scope is None:
        return Scope.from_target(t)
    if not scope.contains(t):
        raise ValueError(
            f"Target {t!r} is outside the supplied scope. "
            "The tool never expands scope silently."
        )
    return scope
