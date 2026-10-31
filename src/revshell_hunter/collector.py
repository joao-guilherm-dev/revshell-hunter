"""Coleta de conexões de rede do host via psutil, enriquecidas com dados do processo."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import psutil

from .models import Connection, ProcessInfo

log = logging.getLogger(__name__)

DEFAULT_STATUSES: Tuple[str, ...] = ("ESTABLISHED", "SYN_SENT")


@dataclass
class _RawConn:
    pid: Optional[int]
    laddr: Any
    raddr: Any
    status: str


def _safe(fn: Callable[[], Any], default: Any = "") -> Any:
    try:
        value = fn()
        return default if value is None else value
    except (psutil.Error, OSError):
        return default


def process_info(pid: int) -> Optional[ProcessInfo]:
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            name = _safe(proc.name).lower()
            exe = _safe(proc.exe).lower()
            cmdline = " ".join(_safe(proc.cmdline, []))
            user = _safe(proc.username)
        parent = _safe(proc.parent, None)
        parent_name = _safe(parent.name).lower() if parent is not None else ""
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    return ProcessInfo(pid=pid, name=name, exe=exe, cmdline=cmdline, parent=parent_name, user=user)


def _per_process_connections() -> Iterable[_RawConn]:
    """Fallback quando net_connections() global exige privilégio (ex.: macOS)."""
    for proc in psutil.process_iter():
        getter = getattr(proc, "net_connections", None) or proc.connections
        try:
            conns = getter(kind="inet")
        except (psutil.Error, OSError):
            continue
        for c in conns:
            yield _RawConn(proc.pid, c.laddr, c.raddr, c.status)


def _raw_connections() -> Iterable[_RawConn]:
    try:
        return [_RawConn(c.pid, c.laddr, c.raddr, c.status) for c in psutil.net_connections("inet")]
    except psutil.AccessDenied:
        log.warning("net_connections() negado; usando coleta por processo (cobertura parcial).")
        return list(_per_process_connections())


def collect_connections(statuses: Tuple[str, ...] = DEFAULT_STATUSES) -> List[Connection]:
    """Lista conexões TCP de saída (ESTABLISHED / SYN_SENT) com informações do processo."""
    cache: Dict[int, Optional[ProcessInfo]] = {}
    out: List[Connection] = []
    for raw in _raw_connections():
        if raw.status not in statuses or not raw.raddr:
            continue
        info = None
        if raw.pid:
            if raw.pid not in cache:
                cache[raw.pid] = process_info(raw.pid)
            info = cache[raw.pid]
        out.append(
            Connection(
                remote_ip=raw.raddr.ip,
                remote_port=raw.raddr.port,
                local_ip=raw.laddr.ip if raw.laddr else "",
                local_port=raw.laddr.port if raw.laddr else 0,
                pid=raw.pid,
                status=raw.status,
                process=info,
            )
        )
    return out
