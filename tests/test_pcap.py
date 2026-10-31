import pytest

from revshell_hunter.config import load_config
from revshell_hunter.pcap import analyze_pcap

scapy = pytest.importorskip("scapy")
from scapy.all import IP, TCP, Raw, wrpcap  # noqa: E402

SRC, DST = "10.0.0.5", "8.8.4.4"
T0 = 1_700_000_000.0


def _pkt(src, dst, sport, dport, flags, t, payload=b""):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        p = p / Raw(payload)
    p.time = t
    return p


def _session(sport, dport, t, data_pairs=1):
    pkts = [
        _pkt(SRC, DST, sport, dport, "S", t),
        _pkt(DST, SRC, dport, sport, "SA", t + 0.05),
        _pkt(SRC, DST, sport, dport, "A", t + 0.1),
    ]
    for i in range(data_pairs):
        pkts.append(_pkt(SRC, DST, sport, dport, "PA", t + 0.2 + i, b"ls\n"))
        pkts.append(_pkt(DST, SRC, dport, sport, "PA", t + 0.3 + i, b"file1 file2\n"))
    return pkts


def _ids(findings):
    return {i for f in findings for i in f.rule_ids}


def test_beacon_and_suspicious_port(tmp_path):
    pkts = []
    for i in range(8):
        pkts += _session(40000 + i, 4444, T0 + i * 60 + (i % 3))
    path = tmp_path / "beacon.pcap"
    wrpcap(str(path), pkts)
    findings = analyze_pcap(str(path), load_config())
    assert len(findings) == 1 and findings[0].severity == "medium"
    assert _ids(findings) == {"PCAP-001", "PCAP-004"}
    d = findings[0].details
    assert d["flows"] == 8 and d["dport"] == 4444 and d["bytes_c2s"] == 8 * 3


def test_interactive_like_flow(tmp_path):
    pkts = _session(41000, 5000, T0, data_pairs=40)
    path = tmp_path / "interactive.pcap"
    wrpcap(str(path), pkts)
    findings = analyze_pcap(str(path), load_config())
    assert "PCAP-003" in _ids(findings)


def test_private_only_traffic_ignored_and_blocklist(tmp_path):
    pkts = [_pkt("10.0.0.5", "10.0.0.9", 40000, 4444, "S", T0),
            _pkt("10.0.0.9", "10.0.0.5", 4444, 40000, "SA", T0 + 0.1)]
    path = tmp_path / "private.pcap"
    wrpcap(str(path), pkts)
    assert analyze_pcap(str(path), load_config()) == []
    assert analyze_pcap(str(path), load_config(), include_private=True)

    path2 = tmp_path / "bl.pcap"
    wrpcap(str(path2), _session(40000, 443, T0))
    cfg = load_config(overrides={"blocklist_ips": [DST]})
    assert _ids(analyze_pcap(str(path2), cfg)) == {"PCAP-005"}


def test_normal_https_is_quiet(tmp_path):
    path = tmp_path / "https.pcap"
    wrpcap(str(path), _session(40000, 443, T0, data_pairs=3))
    assert analyze_pcap(str(path), load_config()) == []
