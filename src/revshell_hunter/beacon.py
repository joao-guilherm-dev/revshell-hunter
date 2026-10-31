"""Detecção de beaconing: reconexões em intervalos regulares."""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Dict, Hashable, List, Optional, Sequence, Set

from .config import BeaconConfig


@dataclass(frozen=True)
class BeaconResult:
    events: int
    mean_interval: float
    cv: float

    def describe(self) -> str:
        return (
            f"{self.events} conexões a cada ~{self.mean_interval:.0f}s "
            f"(variação {self.cv * 100:.0f}%)"
        )


def detect_beacon(timestamps: Sequence[float], cfg: BeaconConfig) -> Optional[BeaconResult]:
    """Retorna BeaconResult se os intervalos entre eventos forem regulares.

    Regular = coeficiente de variação (desvio-padrão / média) <= cfg.max_cv,
    com ao menos cfg.min_events eventos e intervalo médio >= cfg.min_interval_seconds.
    """
    ts = sorted(timestamps)
    if len(ts) < cfg.min_events:
        return None
    intervals = [b - a for a, b in zip(ts, ts[1:])]
    mean = statistics.fmean(intervals)
    if mean < cfg.min_interval_seconds:
        return None
    cv = statistics.pstdev(intervals) / mean
    if cv <= cfg.max_cv:
        return BeaconResult(events=len(ts), mean_interval=mean, cv=cv)
    return None


class BeaconTracker:
    """Acumula, por destino, o instante em que cada NOVA conexão foi vista pela 1ª vez."""

    _MAX_FLOWS_PER_KEY = 5000

    def __init__(self, cfg: BeaconConfig) -> None:
        self.cfg = cfg
        self._events: Dict[Hashable, List[float]] = {}
        self._seen: Dict[Hashable, Set[Hashable]] = {}

    def observe(self, key: Hashable, flow_id: Hashable, now: float) -> Optional[BeaconResult]:
        seen = self._seen.setdefault(key, set())
        events = self._events.setdefault(key, [])
        if flow_id not in seen:
            if len(seen) >= self._MAX_FLOWS_PER_KEY:
                seen.clear()
            seen.add(flow_id)
            events.append(now)
        while events and now - events[0] > self.cfg.history_seconds:
            events.pop(0)
        return detect_beacon(events, self.cfg)
