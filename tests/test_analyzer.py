from revshell_hunter.analyzer import Analyzer, is_external
from revshell_hunter.config import load_config

from .conftest import make_conn


def ids(findings):
    return {i for f in findings for i in f.rule_ids}


def test_is_external():
    assert is_external("8.8.8.8") and is_external("::ffff:8.8.8.8")
    for ip in ("10.1.1.1", "192.168.0.9", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "bogus"):
        assert not is_external(ip)


def test_shell_to_suspicious_port_is_high(analyzer):
    findings = analyzer.analyze([make_conn(port=4444)])
    assert findings[0].severity == "high"
    assert ids(findings) == {"RSH-001", "RSH-004"}


def test_shell_over_443_is_at_least_medium(analyzer):
    findings = analyzer.analyze([make_conn(port=443)])
    assert findings[0].severity == "medium" and ids(findings) == {"RSH-001"}


def test_private_destination_ignored_unless_included(cfg):
    conn = make_conn(ip="10.0.0.9", port=4444)
    assert Analyzer(cfg).analyze([conn]) == []
    assert Analyzer(cfg, include_private=True).analyze([conn])


def test_office_parent_spawning_shell(analyzer):
    findings = analyzer.analyze([make_conn(parent="winword.exe")])
    assert "RSH-007" in ids(findings) and findings[0].severity == "high"


def test_masquerading_and_suspicious_path(analyzer):
    conn = make_conn(exe=r"c:\users\bob\appdata\local\temp\cmd.exe")
    assert {"RSH-006", "RSH-009", "RSH-001"} <= ids(analyzer.analyze([conn]))


def test_legit_system32_cmd_is_not_flagged_as_masquerading(analyzer):
    assert "RSH-009" not in ids(analyzer.analyze([make_conn()]))


def test_cmdline_patterns(analyzer):
    conn = make_conn(name="powershell.exe", cmdline="powershell -nop -enc " + "QUJD" * 10)
    assert "RSH-008" in ids(analyzer.analyze([conn]))
    conn = make_conn(name="bash", exe="/usr/bin/bash", cmdline="bash -i ... /dev/tcp/1.2.3.4/80")
    assert "RSH-008" in ids(analyzer.analyze([conn]))


def test_netcat_in_public_folder_is_high(analyzer):
    conn = make_conn(name="nc.exe", exe=r"c:\users\public\nc.exe", port=31337)
    assert analyzer.analyze([conn])[0].severity == "high"


def test_trusted_process_exempt_from_port_rules():
    cfg = load_config(overrides={"min_score": 1})
    assert Analyzer(cfg).analyze([make_conn(name="chrome.exe", port=6000)]) == []
    other = Analyzer(cfg).analyze([make_conn(name="foo.exe", port=6000)])
    assert ids(other) == {"RSH-005"}


def test_uncommon_port_alone_stays_below_threshold(analyzer):
    assert analyzer.analyze([make_conn(name="svchost.exe", port=6000)]) == []


def test_allowlist_suppresses_only_matching_rule():
    rule = {"process": "plink.exe", "remote_cidr": "8.8.8.0/24"}
    cfg = load_config(overrides={"allowlist": [rule]})
    a = Analyzer(cfg)
    assert a.analyze([make_conn(name="plink.exe", port=22, ip="8.8.8.8")]) == []
    assert ids(a.analyze([make_conn(name="plink.exe", port=22, ip="1.1.1.1")])) == {"RSH-002"}


def test_blocklist_flags_even_trusted_process():
    cfg = load_config(overrides={"blocklist_ips": ["8.8.8.8"]})
    findings = Analyzer(cfg).analyze([make_conn(name="chrome.exe", port=443, ip="8.8.8.8")])
    assert ids(findings) == {"RSH-011"} and findings[0].severity == "medium"


def test_beaconing_detected_after_enough_regular_connections(cfg):
    a = Analyzer(cfg)
    last = []
    for i in range(8):
        conn = make_conn(name="updater.exe", exe=r"c:\program files\x\updater.exe", port=8443,
                         lport=50000 + i, pid=77)
        last = a.analyze([conn], now=1_000_000 + i * 60 + (i % 3))
    assert "RSH-010" in ids(last)


def test_irregular_connections_are_not_beacons(cfg):
    a = Analyzer(cfg)
    last = []
    for i, t in enumerate([0, 7, 90, 95, 400, 1000, 1010, 2500]):
        conn = make_conn(name="updater.exe", exe=r"c:\program files\x\updater.exe", port=8443,
                         lport=50000 + i, pid=77)
        last = a.analyze([conn], now=1_000_000 + t)
    assert "RSH-010" not in ids(last)
