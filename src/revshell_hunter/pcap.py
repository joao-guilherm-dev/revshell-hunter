"""Análise offline de capturas de rede (PCAP/PCAPNG) - requer scapy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from .analyzer import is_external, iso
from .beacon import detect_beacon
from .catalog import mitre_for
from .config import Config
from .models import Finding, Reason


@dataclass
class _Flow:
    init_ip: str
    init_port: int
    resp_ip: str
    resp_port: int
    start: float
    last: float
    packets: int = 0
    c2s_bytes: int = 0
    s2c_bytes: int = 0
    c2s_data_pkts: int = 0
    s2c_data_pkts: int = 0
    s2c_pkts: int = 0


def _load_scapy():
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import PcapReader
    except ImportError as exc:  # pragma: no cover - depende do ambiente
        raise RuntimeError(
            "scapy não está instalado. Use: pip install 'revshell-hunter[pcap]'"
        ) from exc
    return IP, IPv6, TCP, PcapReader


def _payload_len(ip_layer, tcp_layer, is_v6: bool) -> int:
    """Tamanho do payload TCP sem contar padding de Ethernet."""
    if is_v6:
        total = int(ip_layer.plen) - int(tcp_layer.dataofs) * 4
    else:
        total = int(ip_layer.len) - int(ip_layer.ihl) * 4 - int(tcp_layer.dataofs) * 4
    return max(0, total)


def read_flows(path: str, include_private: bool = False) -> Dict[Tuple, _Flow]:
    IP, IPv6, TCP, PcapReader = _load_scapy()
    flows: Dict[Tuple, _Flow] = {}
    with PcapReader(path) as reader:
        for pkt in reader:
            tcp = pkt.getlayer(TCP)
            if tcp is None:
                continue
            ip_layer = pkt.getlayer(IP)
            is_v6 = False
            if ip_layer is None:
                ip_layer = pkt.getlayer(IPv6)
                is_v6 = True
            if ip_layer is None:
                continue
            src, dst = ip_layer.src, ip_layer.dst
            if not include_private and not (is_external(src) or is_external(dst)):
                continue
            sport, dport, ts = int(tcp.sport), int(tcp.dport), float(pkt.time)
            fwd, rev = (src, sport, dst, dport), (dst, dport, src, sport)
            flow = flows.get(fwd) or flows.get(rev)
            if flow is None:
                flags = int(tcp.flags)
                if flags & 0x12 == 0x12:  # SYN+ACK visto primeiro: o iniciador é o destino
                    flow = _Flow(dst, dport, src, sport, ts, ts)
                    flows[rev] = flow
                else:
                    flow = _Flow(src, sport, dst, dport, ts, ts)
                    flows[fwd] = flow
            from_client = src == flow.init_ip and sport == flow.init_port
            plen = _payload_len(ip_layer, tcp, is_v6)
            flow.packets += 1
            flow.last = max(flow.last, ts)
            if from_client:
                flow.c2s_bytes += plen
                flow.c2s_data_pkts += 1 if plen else 0
            else:
                flow.s2c_pkts += 1
                flow.s2c_bytes += plen
                flow.s2c_data_pkts += 1 if plen else 0
    return flows


def analyze_pcap(
    path: str,
    cfg: Config,
    include_private: bool = False,
) -> List[Finding]:
    flows = read_flows(path, include_private=include_private)

    groups: Dict[Tuple[str, str, int], List[_Flow]] = {}
    for flow in flows.values():
        groups.setdefault((flow.init_ip, flow.resp_ip, flow.resp_port), []).append(flow)

    findings: List[Finding] = []
    for (src, dst, dport), items in groups.items():
        if not include_private and not is_external(dst):
            continue
        reasons: List[Reason] = []

        def add(rule_id: str, text: str, reasons: List[Reason] = reasons) -> None:
            reasons.append(Reason(rule_id, cfg.weight(rule_id), text, mitre_for(rule_id)))

        packets = sum(f.packets for f in items)
        established = any(f.s2c_pkts > 0 for f in items)
        busiest = max(items, key=lambda f: f.packets)

        if cfg.is_blocklisted(dst):
            add("PCAP-005", f"destino {dst} está na blocklist")
        if dport in cfg.suspicious_ports and established:
            add("PCAP-001", f"sessão estabelecida na porta {dport}, típica de shells/payloads")
        elif dport not in cfg.common_ports and dport not in cfg.suspicious_ports and packets >= 10:
            add("PCAP-002", f"fluxo sustentado ({packets} pacotes) na porta incomum {dport}")

        for f in items:
            data_pkts = f.c2s_data_pkts + f.s2c_data_pkts
            if (
                dport not in cfg.common_ports
                and f.packets >= 40
                and f.c2s_data_pkts >= 10
                and f.s2c_data_pkts >= 10
                and (f.last - f.start) >= 30
                and (f.c2s_bytes + f.s2c_bytes) / max(1, data_pkts) < 150
            ):
                add(
                    "PCAP-003",
                    f"fluxo interativo: {f.packets} pacotes, payload médio "
                    f"{(f.c2s_bytes + f.s2c_bytes) // max(1, data_pkts)} bytes, "
                    f"{f.last - f.start:.0f}s de duração",
                )
                break

        beacon = detect_beacon([f.start for f in items], cfg.beacon)
        if beacon is not None:
            add("PCAP-004", "beaconing: " + beacon.describe())

        if not reasons:
            continue
        score = sum(r.points for r in reasons)
        if score < cfg.min_score:
            continue
        first = min(f.start for f in items)
        last = max(f.last for f in items)
        remote = f"{dst}:{dport}"
        findings.append(
            Finding(
                source="pcap",
                timestamp=iso(first),
                score=score,
                severity=cfg.severity_for(score),
                title=f"{src} -> {remote}",
                key=f"{src}->{remote}",
                details={
                    "src": src,
                    "dst": dst,
                    "dport": dport,
                    "remote": remote,
                    "flows": len(items),
                    "packets": packets,
                    "bytes_c2s": sum(f.c2s_bytes for f in items),
                    "bytes_s2c": sum(f.s2c_bytes for f in items),
                    "first_seen": iso(first),
                    "last_seen": iso(last),
                    "busiest_flow_packets": busiest.packets,
                },
                reasons=reasons,
            )
        )
    findings.sort(key=lambda f: -f.score)
    return findings
