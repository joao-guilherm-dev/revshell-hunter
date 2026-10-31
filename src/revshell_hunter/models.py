"""Modelos de dados compartilhados."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
SEVERITY_LABEL = {"low": "BAIXO", "medium": "MÉDIO", "high": "ALTO"}


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    parent: str = ""
    user: str = ""


@dataclass(frozen=True)
class Connection:
    remote_ip: str
    remote_port: int
    local_ip: str = ""
    local_port: int = 0
    pid: Optional[int] = None
    status: str = "ESTABLISHED"
    process: Optional[ProcessInfo] = None


@dataclass(frozen=True)
class Reason:
    rule_id: str
    points: int
    description: str
    mitre: str = ""


@dataclass
class Finding:
    source: str  # "live" | "pcap"
    timestamp: str
    score: int
    severity: str
    title: str
    key: str
    details: Dict[str, Any] = field(default_factory=dict)
    reasons: List[Reason] = field(default_factory=list)

    @property
    def rule_ids(self) -> List[str]:
        return [r.rule_id for r in self.reasons]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "timestamp": self.timestamp,
            "score": self.score,
            "severity": self.severity,
            "title": self.title,
            "details": self.details,
            "reasons": [asdict(r) for r in self.reasons],
        }
