"""Saídas: console, JSON, JSONL, CSV e HTML."""

from __future__ import annotations

import csv
import html
import json
import platform
from datetime import datetime, timezone
from typing import IO, Any, Dict, Iterable, List

from . import __version__
from .models import SEVERITY_LABEL, SEVERITY_RANK, Finding

_COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m"}
_RESET = "\033[0m"
_BOLD = "\033[1m"

CSV_COLUMNS = [
    "timestamp", "source", "severity", "score", "title", "process", "pid", "parent",
    "user", "local", "remote", "rules", "mitre", "reasons", "cmdline",
]


def meta(mode: str) -> Dict[str, Any]:
    return {
        "tool": "revshell-hunter",
        "version": __version__,
        "mode": mode,
        "host": platform.node(),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


# --------------------------------------------------------------------------- console
def format_finding(f: Finding, color: bool = False) -> str:
    label = SEVERITY_LABEL[f.severity]
    head = f"[{label} | score {f.score}] {f.title}"
    if color:
        head = f"{_COLORS[f.severity]}{_BOLD}{head}{_RESET}"
    d = f.details
    lines = [head]
    if f.source == "live":
        lines.append(
            f"  pai: {d.get('parent') or '?'} | usuário: {d.get('user') or '?'} "
            f"| local: {d.get('local')}"
        )
        if d.get("exe"):
            lines.append(f"  exe: {d['exe']}")
        if d.get("cmdline"):
            cmd = d["cmdline"]
            lines.append(f"  cmd: {cmd[:200]}{'...' if len(cmd) > 200 else ''}")
    else:
        lines.append(
            f"  fluxos: {d.get('flows')} | pacotes: {d.get('packets')} | bytes ->"
            f" {d.get('bytes_c2s')} / <- {d.get('bytes_s2c')} "
            f"| {d.get('first_seen')} até {d.get('last_seen')}"
        )
    for r in f.reasons:
        lines.append(f"  - [{r.rule_id}] {r.description} ({r.mitre})")
    return "\n".join(lines)


def summary_line(findings: List[Finding]) -> str:
    if not findings:
        return "Nada suspeito encontrado."
    counts = {k: 0 for k in SEVERITY_RANK}
    for f in findings:
        counts[f.severity] += 1
    return (
        f"{len(findings)} achado(s): {counts['high']} alto(s), "
        f"{counts['medium']} médio(s), {counts['low']} baixo(s)."
    )


# ---------------------------------------------------------------------- JSON / JSONL
def write_json(path: str, findings: Iterable[Finding], mode: str) -> None:
    payload = {**meta(mode), "findings": [f.to_dict() for f in findings]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def append_jsonl(fh: IO[str], finding: Finding) -> None:
    fh.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")
    fh.flush()


# ------------------------------------------------------------------------------ CSV
def _csv_row(f: Finding) -> Dict[str, Any]:
    d = f.details
    return {
        "timestamp": f.timestamp,
        "source": f.source,
        "severity": f.severity,
        "score": f.score,
        "title": f.title,
        "process": d.get("process", ""),
        "pid": d.get("pid", ""),
        "parent": d.get("parent", ""),
        "user": d.get("user", ""),
        "local": d.get("local", d.get("src", "")),
        "remote": d.get("remote", ""),
        "rules": ";".join(f.rule_ids),
        "mitre": ";".join(sorted({r.mitre for r in f.reasons if r.mitre})),
        "reasons": " | ".join(r.description for r in f.reasons),
        "cmdline": d.get("cmdline", ""),
    }


def write_csv(path: str, findings: Iterable[Finding]) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for f in findings:
            writer.writerow(_csv_row(f))


# ----------------------------------------------------------------------------- HTML
_HTML_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--card:#f6f8fa;--line:#d0d7de;
--high:#cf222e;--medium:#9a6700;--low:#0969da}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;
--card:#161b22;--line:#30363d;--high:#ff7b72;--medium:#e3b341;--low:#79c0ff}}
body{font:14px/1.5 system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--fg);
margin:0;padding:24px;max-width:1200px;margin-inline:auto}
h1{margin:0 0 4px}p.sub{color:var(--muted);margin:0 0 20px}
.cards{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 18px}
.card b{font-size:22px;display:block}
.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:760px}
th,td{border-bottom:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:var(--card)}code{font-family:ui-monospace,Consolas,monospace;font-size:12px;
word-break:break-all}
ul{margin:0;padding-left:18px}
"""


def render_html(findings: List[Finding], mode: str) -> str:
    m = meta(mode)
    counts = {k: 0 for k in SEVERITY_RANK}
    for f in findings:
        counts[f.severity] += 1
    cards = "".join(
        f'<div class="card"><b class="{lvl}">{counts[lvl]}</b>{SEVERITY_LABEL[lvl].title()}</div>'
        for lvl in ("high", "medium", "low")
    )
    rows = []
    for f in findings:
        d = f.details
        reasons = "".join(
            f"<li><code>{html.escape(r.rule_id)}</code> {html.escape(r.description)} "
            f"<small>({html.escape(r.mitre)})</small></li>"
            for r in f.reasons
        )
        extra = ""
        if d.get("cmdline"):
            extra = f"<br><code>{html.escape(d['cmdline'][:300])}</code>"
        rows.append(
            "<tr>"
            f'<td class="{f.severity}"><b>{SEVERITY_LABEL[f.severity]}</b><br>{f.score}</td>'
            f"<td>{html.escape(f.title)}{extra}</td>"
            f"<td>{html.escape(str(d.get('parent') or d.get('src') or ''))}</td>"
            f"<td>{html.escape(f.timestamp)}</td>"
            f"<td><ul>{reasons}</ul></td>"
            "</tr>"
        )
    body = "".join(rows) or '<tr><td colspan="5">Nada suspeito encontrado.</td></tr>'
    return (
        "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>revshell-hunter - relatório</title><style>{_HTML_CSS}</style></head><body>"
        "<h1>revshell-hunter</h1>"
        f"<p class=\"sub\">modo {html.escape(mode)} · host {html.escape(m['host'])} · "
        f"{html.escape(m['generated_at'])} · v{html.escape(m['version'])}</p>"
        f"<div class=\"cards\">{cards}</div>"
        "<div class=\"wrap\"><table><thead><tr><th>Severidade</th><th>Conexão / fluxo</th>"
        "<th>Pai / origem</th><th>Quando</th><th>Motivos</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div></body></html>"
    )


def write_html(path: str, findings: List[Finding], mode: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(findings, mode))
