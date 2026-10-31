# revshell-hunter

[![CI](https://github.com/joao-guilherm-dev/revshell-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/joao-guilherm-dev/revshell-hunter/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Detecção **defensiva** de *reverse shell*: investiga conexões de rede (no host ao vivo ou em uma captura PCAP)
para achar conexões suspeitas, portas incomuns e *beaconing*, e entrega o resultado com score,
severidade e mapeamento MITRE ATT&CK. Acompanha regras Sigma, configuração Sysmon e queries para
Splunk, Elastic e Sentinel.

> **Uso responsável:** a ferramenta só *observa*. Use apenas em sistemas e redes que você administra
> ou tem autorização para auditar. Veja [SECURITY.md](SECURITY.md).

## O que ele faz

- **`scan`**: fotografa as conexões TCP de saída do host e cruza com o processo (nome, pai, usuário,
  caminho do binário, linha de comando). Com `--watch` repete a varredura e detecta beaconing.
- **`pcap`**: reconstrói fluxos de uma captura (`.pcap`/`.pcapng`) e procura portas típicas de payload,
  fluxos interativos (muitos pacotes pequenos nos dois sentidos) e inícios de conexão periódicos.
- **Pontuação por regras** (`RSH-*` e `PCAP-*`), configuráveis em YAML, com allowlist e blocklist.
- **Relatórios** em console, JSON, JSONL (para SIEM/forwarders), CSV e HTML (arquivo único, claro/escuro).
- **Pacote de detecção para SIEM** em [`rules/`](rules/) e [`sysmon/`](sysmon/).

## Instalação

```bash
git clone https://github.com/joao-guilherm-dev/revshell-hunter.git
cd revshell-hunter
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[pcap]"           # [pcap] instala o scapy (só necessário para o comando pcap)
```

## Uso rápido

```bash
revshell-hunter demo                                  # dados sintéticos, nenhuma conexão real
revshell-hunter scan                                  # análise única do host
revshell-hunter scan --watch 30 --jsonl achados.jsonl # monitora a cada 30s (habilita beaconing)
revshell-hunter pcap captura.pcap --html relatorio.html
revshell-hunter rules                                 # regras, pesos e técnicas MITRE
```

No Windows, rode o terminal como **Administrador** (e no Linux/macOS como root) para enxergar o
processo de todas as conexões.

Opções úteis (valem para `scan` e `pcap`):

| Opção | Efeito |
|---|---|
| `-c, --config ARQ` | YAML com regras próprias (mescla com o padrão) |
| `--min-score N` | score mínimo para reportar (padrão 3) |
| `--include-private` | inclui destinos privados/loopback (laboratório) |
| `--json / --csv / --html ARQ` | grava relatórios |
| `--fail-on {low,medium,high}` | código de saída 1 se houver achado dessa severidade ou maior (cron/CI) |
| `--watch SEG` / `--duration SEG` | repete a varredura / limita o tempo (só `scan`) |
| `--established-only` | ignora tentativas `SYN_SENT` (só `scan`) |

Códigos de saída: `0` ok, `1` achado acima do `--fail-on`, `2` erro (configuração, arquivo, dependência).

## Exemplo de saída (`revshell-hunter demo`)

```text
[ALTO | score 11] cmd.exe (PID 4120) -> 198.51.100.23:4444
  pai: w3wp.exe | usuário: IIS APPPOOL\site | local: 10.0.0.5:49701
  exe: c:\windows\system32\cmd.exe
  - [RSH-001] shell (cmd.exe) com conexão externa (T1059)
  - [RSH-007] processo pai suspeito (w3wp.exe) gerou cmd.exe (T1059)
  - [RSH-004] porta de destino típica de shell (4444) (T1571)

[ALTO | score 11] powershell.exe (PID 5532) -> 203.0.113.40:443
  pai: winword.exe | usuário: CORP\maria | local: 10.0.0.5:49811
  exe: c:\windows\system32\windowspowershell\v1.0\powershell.exe
  cmd: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
  - [RSH-001] shell (powershell.exe) com conexão externa (T1059)
  - [RSH-007] processo pai suspeito (winword.exe) gerou powershell.exe (T1059)
  - [RSH-008] linha de comando casa com: powershell-encoded-command, hidden-window (T1059)

[ALTO | score 10] bash (PID 8800) -> 192.0.2.99:9001
  pai: python3 | usuário: www-data | local: 10.0.0.5:41000
  exe: /usr/bin/bash
  cmd: bash -i ... /dev/tcp/192.0.2.99/9001 ...
  - [RSH-001] shell (bash) com conexão externa (T1059)
  - [RSH-008] linha de comando casa com: bash-dev-tcp (T1059)
  - [RSH-004] porta de destino típica de shell (9001) (T1571)

[...]

6 achado(s): 5 alto(s), 1 médio(s), 0 baixo(s).
```

## Como a pontuação funciona

Cada regra que dispara soma seu peso. Severidade: **alto** >= 7, **médio** >= 4, **baixo** >= 1.
Sinais fracos sozinhos (porta incomum = 1 ponto) não geram alerta; combinações (shell + pai suspeito +
porta de payload) sobem rápido. Catálogo completo, pesos e falsos positivos esperados em
[docs/detection-rules.md](docs/detection-rules.md).

| Regra | Sinal | MITRE |
|---|---|---|
| RSH-001 / 002 / 003 | shell, ferramenta de rede ou LOLBin com conexão externa | T1059, T1095, T1218 |
| RSH-004 / 005 | porta típica de payload / porta incomum | T1571 |
| RSH-006 / 009 | binário em pasta suspeita / binário de sistema fora do `System32` | T1036 |
| RSH-007 | Office, IIS, SQL Server ou PHP gerando shell | T1059 |
| RSH-008 | linha de comando suspeita (`-enc`, `/dev/tcp/`, `TcpClient`...) | T1059 |
| RSH-010 / PCAP-004 | beaconing (intervalos regulares) | T1071 |
| RSH-011 / PCAP-005 | destino na blocklist | T1071 |
| PCAP-001 / 002 / 003 | sessão em porta de payload, fluxo sustentado, fluxo interativo | T1571, T1059 |

## Configuração

Crie um YAML só com o que quer mudar e passe com `--config`:

```yaml
# minha-config.yaml
min_score: 4
extra_trusted_processes: [meu-agente.exe]      # extra_<lista> acrescenta à lista padrão
extra_suspicious_ports: [6000]
weights:
  RSH-010: 2                                   # dicionários são mesclados
allowlist:                                     # todos os campos do item precisam casar
  - { process: plink.exe, remote_cidr: 203.0.113.0/24 }
  - { process: backup-agent.exe, remote_port: 9001 }
blocklist_file: blocklist.txt                  # um IP/CIDR por linha, # para comentários
```

Todas as chaves e valores padrão estão em
[`src/revshell_hunter/data/default_rules.yaml`](src/revshell_hunter/data/default_rules.yaml).
Chaves desconhecidas são rejeitadas (evita erro de digitação silencioso).

## Docker

```bash
docker build -t revshell-hunter .

# Análise de PCAP (qualquer SO)
mkdir -p pcaps reports && cp captura.pcap pcaps/
HUNTER_UID=$(id -u) HUNTER_GID=$(id -g) docker compose run --rm pcap

# Monitoramento ao vivo - SOMENTE host Linux (usa o namespace de rede e de processos do host)
docker compose --profile live up
```

> No Docker Desktop (Windows/macOS) o contêiner enxerga a VM do Docker, **não** o seu host.
> Para analisar conexões do Windows, rode o `scan` direto no Python.

## Detecção em escala (SIEM)

O `scan` é uma fotografia: conexões que abrem e fecham entre duas varreduras passam despercebidas.
Para cobertura contínua use as regras da pasta [`rules/`](rules/) com **Sysmon** (Event ID 1 e 3):

- [`rules/sigma/`](rules/sigma/): 6 regras Sigma (shell com conexão externa, portas de payload, Office/IIS gerando shell, PowerShell codificado, `/dev/tcp`, netcat/plink).
- [`rules/splunk.md`](rules/splunk.md), [`rules/elastic.md`](rules/elastic.md), [`rules/sentinel.md`](rules/sentinel.md): queries prontas, incluindo beaconing.
- [`sysmon/sysmon-revshell.xml`](sysmon/sysmon-revshell.xml): configuração complementar para gerar os eventos.

## Estrutura

```text
revshell-hunter/
├── src/revshell_hunter/     # collector, analyzer, beacon, pcap, config, reporters, cli, demo
│   └── data/default_rules.yaml
├── tests/                   # pytest (inclui validação das regras Sigma e do XML do Sysmon)
├── rules/                   # Sigma + queries Splunk / Elastic / Sentinel
├── sysmon/                  # configuração Sysmon
├── docs/                    # arquitetura, regras, playbook de resposta, laboratório
├── examples/                # relatórios de exemplo (JSON)
├── Dockerfile, docker-compose.yml, Makefile
└── .github/workflows/ci.yml # lint + testes (Linux/Windows, Python 3.9-3.12) + build Docker
```

## Desenvolvimento

```bash
pip install -e ".[dev]"
ruff check .
pytest --cov=revshell_hunter
```

Veja [CONTRIBUTING.md](CONTRIBUTING.md). Documentação: [arquitetura](docs/architecture.md),
[regras](docs/detection-rules.md), [playbook de resposta a incidente](docs/incident-response.md),
[testes em laboratório](docs/lab-testing.md).

## Limitações

- O `scan` depende de amostragem; beaconing exige `--watch` com intervalo menor que o do beacon.
- Em PCAP só há metadados (portas, tempos, tamanhos); tráfego cifrado não é inspecionado.
- Reverse shell em porta comum (443) é detectado por comportamento (processo, pai, linha de comando,
  beaconing), não pela porta.
- Um atacante que use processo legítimo, porta comum e jitter alto reduz os sinais: trate a ferramenta
  como **uma camada** de detecção.
- Falsos positivos existem (administradores usando `plink`/PowerShell, agentes de monitoramento);
  use allowlist e ajuste os pesos.

## Status de validação

- Testes automatizados (pytest) e `ruff` passam em Linux; o CI cobre Windows e Python 3.9-3.12.
- O `scan` foi executado em um host real (Linux) e validado com tráfego benigno em loopback.
- Dockerfile/compose e as queries Splunk/Elastic/Sentinel não foram executados nas plataformas reais
  (as regras Sigma e o XML do Sysmon só tiveram a sintaxe validada nos testes): valide no seu ambiente.

## Roadmap

- Leitura direta de logs Sysmon (`.evtx`) para análise offline.
- Enriquecimento opcional com feeds de reputação (AbuseIPDB, OTX).
- Exportação para Syslog/CEF e webhook (Slack/Teams).
- Detecção de *bind shell* (portas em escuta incomuns).

## Licença

[MIT](LICENSE)
