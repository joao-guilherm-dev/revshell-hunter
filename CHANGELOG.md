# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [1.0.0] - 2026-10-30

### Adicionado
- Comando `scan`: análise ao vivo das conexões do host (processo, pai, linha de comando, caminho do binário).
- Comando `pcap`: análise offline de capturas (portas, fluxos interativos, beaconing).
- Detecção de beaconing por regularidade de intervalos (coeficiente de variação).
- Regras configuráveis em YAML, allowlist, blocklist de IP/CIDR.
- Relatórios em console, JSON, JSONL, CSV e HTML.
- Comando `demo` (dados sintéticos) e `rules` (catálogo com MITRE ATT&CK).
- Regras Sigma, configuração Sysmon e queries Splunk / Elastic / Sentinel.
- Dockerfile, docker-compose, CI com GitHub Actions.
