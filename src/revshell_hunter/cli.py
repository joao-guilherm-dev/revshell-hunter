"""Interface de linha de comando."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from typing import Dict, List, Optional

from . import __version__
from .analyzer import Analyzer
from .catalog import RULES
from .collector import DEFAULT_STATUSES, collect_connections
from .config import Config, ConfigError, load_config
from .demo import run_demo
from .models import SEVERITY_RANK, Finding
from .reporters import (
    append_jsonl,
    format_finding,
    summary_line,
    write_csv,
    write_html,
    write_json,
)

log = logging.getLogger("revshell_hunter")


def _is_privileged() -> bool:
    try:
        if os.name == "nt":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:  # pragma: no cover
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revshell-hunter",
        description=(
            "Detecção defensiva de reverse shell: conexões suspeitas, "
            "portas incomuns e beaconing."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", help="YAML com regras customizadas (mescla com o padrão)")
    common.add_argument("--min-score", type=int, help="score mínimo para reportar")
    common.add_argument("--include-private", action="store_true",
                        help="inclui destinos privados/loopback (útil em laboratório)")
    common.add_argument("--json", metavar="ARQ", help="grava relatório JSON")
    common.add_argument("--csv", metavar="ARQ", help="grava relatório CSV")
    common.add_argument("--html", metavar="ARQ", help="grava relatório HTML")
    common.add_argument("--fail-on", choices=list(SEVERITY_RANK),
                        help="sai com código 1 se houver achado desta severidade ou maior")
    common.add_argument("--no-color", action="store_true", help="desativa cores ANSI")
    common.add_argument("-v", "--verbose", action="store_true", help="logs detalhados")

    scan = sub.add_parser("scan", parents=[common], help="analisa as conexões do host agora")
    scan.add_argument("--watch", type=float, default=0, metavar="SEG",
                      help="repete a varredura a cada SEG segundos (habilita beaconing)")
    scan.add_argument("--duration", type=float, default=0, metavar="SEG",
                      help="com --watch, encerra após SEG segundos")
    scan.add_argument("--jsonl", metavar="ARQ",
                      help="acrescenta cada novo achado (um JSON por linha)")
    scan.add_argument("--established-only", action="store_true",
                      help="ignora SYN_SENT (tentativas de conexão)")

    pcap = sub.add_parser("pcap", parents=[common], help="analisa uma captura PCAP/PCAPNG")
    pcap.add_argument("file", help="arquivo .pcap / .pcapng")

    sub.add_parser("demo", parents=[common], help="roda a análise com dados sintéticos")
    sub.add_parser("rules", parents=[common], help="lista as regras e pesos efetivos")
    return parser


# ---------------------------------------------------------------------------- scan
def _run_scan(args: argparse.Namespace, cfg: Config, color: bool) -> List[Finding]:
    analyzer = Analyzer(cfg, include_private=args.include_private)
    statuses = ("ESTABLISHED",) if args.established_only else DEFAULT_STATUSES
    latest: Dict[str, Finding] = {}
    reported: Dict[str, int] = {}
    deadline = time.time() + args.duration if args.duration else None
    jsonl = open(args.jsonl, "a", encoding="utf-8") if args.jsonl else None  # noqa: SIM115
    try:
        while True:
            for f in analyzer.analyze(collect_connections(statuses)):
                latest[f.key] = f
                if f.score > reported.get(f.key, -1):
                    reported[f.key] = f.score
                    print(format_finding(f, color) + "\n")
                    if jsonl:
                        append_jsonl(jsonl, f)
            if not args.watch or (deadline and time.time() >= deadline):
                break
            time.sleep(args.watch)
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuário.", file=sys.stderr)
    finally:
        if jsonl:
            jsonl.close()
    return sorted(latest.values(), key=lambda f: -f.score)


# ---------------------------------------------------------------------------- main
def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if color and os.name == "nt":
        os.system("")  # habilita sequências ANSI no console do Windows

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"Erro de configuração: {exc}", file=sys.stderr)
        return 2
    if args.min_score is not None:
        cfg.min_score = args.min_score

    if args.command == "rules":
        print(f"{'ID':<10}{'PESO':<6}{'MITRE':<11}DESCRIÇÃO")
        for rid, (title, mitre) in RULES.items():
            print(f"{rid:<10}{cfg.weight(rid):<6}{mitre:<11}{title}")
        return 0

    mode = args.command
    if args.command == "scan":
        if not _is_privileged():
            print("Aviso: sem privilégios elevados parte dos processos pode não ser visível "
                  "(rode como Administrador/root).", file=sys.stderr)
        findings = _run_scan(args, cfg, color)
    elif args.command == "pcap":
        from .pcap import analyze_pcap

        try:
            findings = analyze_pcap(args.file, cfg, include_private=args.include_private)
        except (RuntimeError, OSError) as exc:
            print(f"Erro: {exc}", file=sys.stderr)
            return 2
        for f in findings:
            print(format_finding(f, color) + "\n")
    else:  # demo
        print("DEMO: dados sintéticos (faixas TEST-NET), nenhuma conexão real foi feita.\n")
        findings = run_demo(cfg)
        for f in findings:
            print(format_finding(f, color) + "\n")

    print(summary_line(findings))
    if args.json:
        write_json(args.json, findings, mode)
    if args.csv:
        write_csv(args.csv, findings)
    if args.html:
        write_html(args.html, findings, mode)

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
