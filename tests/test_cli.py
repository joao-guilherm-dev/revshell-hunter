import json

import pytest

from revshell_hunter import cli

from .conftest import make_conn


def test_demo_runs(capsys):
    assert cli.main(["demo", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "RSH-001" in out and "achado(s)" in out


def test_rules_command(capsys):
    assert cli.main(["rules"]) == 0
    assert "PCAP-004" in capsys.readouterr().out


def test_scan_exit_codes_and_reports(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "collect_connections", lambda statuses=(): [make_conn(port=4444)])
    out = tmp_path / "r.json"
    code = cli.main(["scan", "--no-color", "--fail-on", "high", "--json", str(out),
                     "--html", str(tmp_path / "r.html"), "--csv", str(tmp_path / "r.csv"),
                     "--jsonl", str(tmp_path / "r.jsonl")])
    assert code == 1
    assert json.loads(out.read_text(encoding="utf-8"))["findings"][0]["severity"] == "high"
    assert (tmp_path / "r.jsonl").read_text(encoding="utf-8").count("\n") == 1

    monkeypatch.setattr(cli, "collect_connections", lambda statuses=(): [])
    assert cli.main(["scan", "--no-color", "--fail-on", "low"]) == 0
    assert "Nada suspeito" in capsys.readouterr().out


def test_scan_watch_dedupes_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "collect_connections", lambda statuses=(): [make_conn(port=4444)])
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    calls = {"n": 0}
    real_time = cli.time.time

    def fake_time():
        calls["n"] += 1
        return real_time() + (100 if calls["n"] > 4 else 0)

    monkeypatch.setattr(cli.time, "time", fake_time)
    cli.main(["scan", "--no-color", "--watch", "1", "--duration", "50"])
    assert capsys.readouterr().out.count("RSH-004") == 1


def test_bad_config_returns_2(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("nope: 1\n", encoding="utf-8")
    assert cli.main(["demo", "-c", str(bad)]) == 2


def test_pcap_missing_file(tmp_path):
    pytest.importorskip("scapy")
    assert cli.main(["pcap", str(tmp_path / "nao-existe.pcap")]) == 2
