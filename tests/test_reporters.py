import csv
import json

from revshell_hunter.demo import run_demo
from revshell_hunter.reporters import (
    CSV_COLUMNS,
    format_finding,
    render_html,
    summary_line,
    write_csv,
    write_json,
)


def test_json_and_csv_roundtrip(cfg, tmp_path):
    findings = run_demo(cfg)
    write_json(str(tmp_path / "o.json"), findings, "demo")
    data = json.loads((tmp_path / "o.json").read_text(encoding="utf-8"))
    assert data["tool"] == "revshell-hunter" and len(data["findings"]) == len(findings)
    assert data["findings"][0]["reasons"][0]["rule_id"].startswith("RSH-")

    write_csv(str(tmp_path / "o.csv"), findings)
    rows = list(csv.DictReader((tmp_path / "o.csv").open(encoding="utf-8-sig")))
    assert list(rows[0].keys()) == CSV_COLUMNS and len(rows) == len(findings)


def test_html_escapes_untrusted_values(cfg):
    findings = run_demo(cfg)
    findings[0].details["cmdline"] = "<script>alert(1)</script>"
    findings[0].title = "<img src=x onerror=alert(1)>"
    out = render_html(findings, "demo")
    assert "<script>alert(1)" not in out and "<img src=x" not in out
    assert "&lt;script&gt;" in out


def test_console_and_summary(cfg):
    findings = run_demo(cfg)
    text = format_finding(findings[0], color=False)
    assert "ALTO" in text and "RSH-" in text
    assert "\033[" in format_finding(findings[0], color=True)
    assert summary_line([]) == "Nada suspeito encontrado."
    assert "achado(s)" in summary_line(findings)
