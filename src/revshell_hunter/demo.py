"""Dados sintéticos para demonstração (nenhuma conexão real é feita).

Os IPs usam as faixas de documentação (TEST-NET, RFC 5737); por isso o demo roda com
include_private=True.
"""

from __future__ import annotations

from typing import Dict, List

from .analyzer import Analyzer
from .config import Config
from .models import Connection, Finding, ProcessInfo

T0 = 1_800_000_000.0


def _conn(ip: str, port: int, pid: int, lport: int, **proc) -> Connection:
    return Connection(
        remote_ip=ip, remote_port=port, local_ip="10.0.0.5", local_port=lport, pid=pid,
        process=ProcessInfo(pid=pid, **proc),
    )


def static_connections() -> List[Connection]:
    return [
        # shell filho de servidor web, porta típica de payload
        _conn("198.51.100.23", 4444, 4120, 49701, name="cmd.exe",
              exe=r"c:\windows\system32\cmd.exe", parent="w3wp.exe", user=r"IIS APPPOOL\site"),
        # PowerShell com comando codificado, filho de Word, sobre 443
        _conn("203.0.113.40", 443, 5532, 49811, name="powershell.exe",
              exe=r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
              parent="winword.exe", user=r"CORP\maria",
              cmdline=("powershell.exe -nop -w hidden -enc "
                       "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...")),
        # netcat solto em pasta pública
        _conn("198.51.100.7", 31337, 6001, 50122, name="nc.exe",
              exe=r"c:\users\public\nc.exe", parent="cmd.exe", user=r"CORP\joao"),
        # "cmd.exe" em pasta temporária (masquerading)
        _conn("192.0.2.77", 8080, 7310, 50222, name="cmd.exe",
              exe=r"c:\users\bob\appdata\local\temp\cmd.exe", parent="explorer.exe",
              user=r"CORP\bob"),
        # bash em host Linux com redirecionamento para /dev/tcp (trecho abreviado)
        _conn("192.0.2.99", 9001, 8800, 41000, name="bash", exe="/usr/bin/bash",
              parent="python3", user="www-data",
              cmdline="bash -i ... /dev/tcp/192.0.2.99/9001 ..."),
        # tráfego legítimo (não deve gerar alerta)
        _conn("203.0.113.5", 443, 900, 51000, name="chrome.exe",
              exe=r"c:\program files\google\chrome\application\chrome.exe", parent="explorer.exe"),
        _conn("203.0.113.9", 6000, 904, 51001, name="svchost.exe",
              exe=r"c:\windows\system32\svchost.exe", parent="services.exe"),
    ]


def beacon_connection(cycle: int) -> Connection:
    return _conn("203.0.113.77", 8443, 3300, 52000 + cycle, name="updater.exe",
                 exe=r"c:\programdata\updater\updater.exe", parent="services.exe",
                 user="SYSTEM")


def run_demo(cfg: Config, cycles: int = 8) -> List[Finding]:
    """Simula `cycles` varreduras (60s entre elas) e retorna o último achado por conexão."""
    analyzer = Analyzer(cfg, include_private=True)
    latest: Dict[str, Finding] = {}
    jitter = [0, 2, -1, 1, 0, -2, 1, 0]
    for i in range(cycles):
        now = T0 + i * 60 + jitter[i % len(jitter)]
        conns = static_connections() + [beacon_connection(i)]
        for f in analyzer.analyze(conns, now=now):
            latest[f.key] = f
    return sorted(latest.values(), key=lambda f: -f.score)
