"""Motor de pontuação para conexões ao vivo."""

from __future__ import annotations

import ipaddress
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Iterable, List, Optional

from .beacon import BeaconTracker
from .catalog import mitre_for
from .config import Config
from .models import Connection, Finding, ProcessInfo, Reason


@lru_cache(maxsize=8192)
def is_external(ip: str) -> bool:
    """True para endereços públicos roteáveis (ignora privados, loopback, link-local, CGNAT...)."""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


class Analyzer:
    """Avalia conexões; mantém estado entre chamadas para detectar beaconing."""

    def __init__(self, config: Config, include_private: bool = False) -> None:
        self.cfg = config
        self.include_private = include_private
        self.beacons = BeaconTracker(config.beacon)

    def analyze(
        self, connections: Iterable[Connection], now: Optional[float] = None
    ) -> List[Finding]:
        now = time.time() if now is None else now
        findings: List[Finding] = []
        for conn in connections:
            if not (self.include_private or is_external(conn.remote_ip)):
                continue
            finding = self._evaluate(conn, now)
            if finding is not None and finding.score >= self.cfg.min_score:
                findings.append(finding)
        findings.sort(key=lambda f: -f.score)
        return findings

    # ------------------------------------------------------------------ internals
    def _evaluate(self, conn: Connection, now: float) -> Optional[Finding]:
        cfg = self.cfg
        proc: Optional[ProcessInfo] = conn.process
        name = proc.name.lower() if proc else ""
        parent = proc.parent.lower() if proc else ""
        exe = proc.exe.lower() if proc else ""
        port = conn.remote_port

        if name and cfg.is_allowlisted(name, parent, conn.remote_ip, port):
            return None

        reasons: List[Reason] = []

        def add(rule_id: str, text: str) -> None:
            reasons.append(Reason(rule_id, cfg.weight(rule_id), text, mitre_for(rule_id)))

        trusted = name in cfg.trusted_processes

        if cfg.is_blocklisted(conn.remote_ip):
            add("RSH-011", f"destino {conn.remote_ip} está na blocklist")

        if proc is not None:
            if name in cfg.shells:
                add("RSH-001", f"shell ({name}) com conexão externa")
            if name in cfg.net_tools:
                add("RSH-002", f"ferramenta de rede/tunelamento ({name})")
            if name in cfg.lolbins:
                add("RSH-003", f"LOLBin ({name}) com conexão externa")
            if parent in cfg.suspicious_parents and (
                name in cfg.shells or name in cfg.lolbins or name in cfg.net_tools
            ):
                add("RSH-007", f"processo pai suspeito ({parent}) gerou {name}")
            if exe and any(p in exe for p in cfg.suspicious_paths):
                add("RSH-006", f"binário em diretório suspeito ({proc.exe})")
            if exe and name in cfg.windows_system_binaries:
                if not any(d in exe for d in cfg.trusted_system_dirs):
                    add("RSH-009", f"{name} executando fora do diretório do sistema ({proc.exe})")
            matched = [p.name for p in cfg.cmdline_patterns if p.regex.search(proc.cmdline)]
            if matched:
                add("RSH-008", "linha de comando casa com: " + ", ".join(matched))

        if not trusted:
            if port in cfg.suspicious_ports:
                add("RSH-004", f"porta de destino típica de shell ({port})")
            elif port not in cfg.common_ports:
                add("RSH-005", f"porta de destino incomum ({port})")

            key = (name or f"pid:{conn.pid}", conn.remote_ip, port)
            flow_id = (conn.pid, conn.local_ip, conn.local_port)
            beacon = self.beacons.observe(key, flow_id, now)
            if beacon is not None:
                add("RSH-010", "beaconing: " + beacon.describe())

        if not reasons:
            return None

        score = sum(r.points for r in reasons)
        label = name or "processo desconhecido"
        pid_txt = f" (PID {conn.pid})" if conn.pid else ""
        remote = f"{conn.remote_ip}:{port}"
        return Finding(
            source="live",
            timestamp=iso(now),
            score=score,
            severity=cfg.severity_for(score),
            title=f"{label}{pid_txt} -> {remote}",
            key=f"{label}:{conn.pid}->{remote}",
            details={
                "process": name,
                "pid": conn.pid,
                "parent": parent,
                "user": proc.user if proc else "",
                "exe": proc.exe if proc else "",
                "cmdline": proc.cmdline if proc else "",
                "local": f"{conn.local_ip}:{conn.local_port}",
                "remote": remote,
                "status": conn.status,
            },
            reasons=reasons,
        )
