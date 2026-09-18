"""Data models used across BD-OSINT."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH")
CONFIDENCES = ("LOW", "MEDIUM", "HIGH")
CONFIRMATIONS = ("observed", "potential", "verified")


@dataclass
class Finding:
    """A structured, non-exploitative finding."""

    title: str
    category: str
    severity: str = "INFO"
    confidence: str = "HIGH"
    status: str = "observed"
    evidence: str = ""
    source: str = ""
    recommendation: str = ""

    def __post_init__(self) -> None:
        self.severity = self.severity.upper()
        self.confidence = self.confidence.upper()
        self.status = self.status.lower()
        if self.severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"Invalid confidence: {self.confidence}")
        if self.status not in CONFIRMATIONS:
            raise ValueError(f"Invalid status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleResult:
    """Result of a single module execution."""

    module: str
    ok: bool
    data: Any = None
    error: Optional[str] = None
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanContext:
    """Shared scan state passed to all modules."""

    target: str
    profile: str = "passive"
    timeout: float = 15.0
    concurrency: int = 5
    delay: float = 1.5
    use_cache: bool = True
    cache_ttl: int = 86400
    shodan_key: Optional[str] = None
    ports: str = "80,443,22,21,25,53,110,143,3306,3389,8080,8443"
    scope_file: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def started_at(self) -> str:
        return datetime.now(timezone.utc).isoformat()
