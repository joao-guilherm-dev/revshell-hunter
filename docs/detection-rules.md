# Regras de detecção

Pesos são os padrões de `data/default_rules.yaml` e podem ser alterados. Use
`revshell-hunter rules` para listar os valores efetivos.

## Host ao vivo (`scan`)

| ID | Peso | MITRE | O que detecta | Falsos positivos comuns |
|---|---|---|---|---|
| RSH-001 | 4 | T1059 | `cmd`, `powershell`, `bash`... com conexão externa. | PowerShell de administração baixando módulos; scripts de inventário. |
| RSH-002 | 4 | T1095 | `nc`, `ncat`, `socat`, `plink`, `chisel` com conexão externa. | `plink`/`ncat` usados por admins (crie allowlist). |
| RSH-003 | 2 | T1218 | LOLBins (`mshta`, `rundll32`, `certutil`...) com conexão externa. | `rundll32` e `certutil` em updates legítimos. |
| RSH-004 | 3 | T1571 | Porta de destino típica de payload (4444, 1337, 31337...). | Jogos, Tor, IRC, ferramentas de monitoramento. |
| RSH-005 | 1 | T1571 | Porta de destino fora da lista de portas comuns. | Muito ruído por si só; por isso pesa pouco. |
| RSH-006 | 2 | T1036 | Binário em `AppData`, `Temp`, `Users\Public`, `/tmp`... | Apps instalados por usuário (Teams, Discord, updaters). |
| RSH-007 | 4 | T1059 | Pai suspeito (Office, IIS, SQL Server, PHP) gerou shell/LOLBin. | Macros de automação internas; manutenção via app web. |
| RSH-008 | 3 | T1059 | Linha de comando com padrão suspeito (`-enc`, `/dev/tcp/`, `TcpClient`...). | Ferramentas de gestão (SCCM, Intune, RMM). |
| RSH-009 | 3 | T1036.005 | Binário de sistema (`cmd.exe`...) fora de `System32`/`SysWOW64`. | Cópias legítimas em instaladores. |
| RSH-010 | 3 | T1071 | Mesmo processo reconectando ao mesmo destino em intervalos regulares. | Agentes de telemetria/monitoramento (use `trusted_processes`/allowlist). |
| RSH-011 | 5 | T1071 | Destino na blocklist (IP/CIDR). | Depende da qualidade do feed. |

Processos em `trusted_processes` (navegadores, Teams, Slack...) ficam isentos de RSH-004/005/010,
mas **não** da blocklist.

## Captura de rede (`pcap`)

| ID | Peso | MITRE | O que detecta |
|---|---|---|---|
| PCAP-001 | 3 | T1571 | Sessão estabelecida (houve resposta) em porta típica de payload. |
| PCAP-002 | 1 | T1571 | Fluxo sustentado (>= 10 pacotes) em porta incomum. |
| PCAP-003 | 2 | T1059 | Fluxo interativo: >= 40 pacotes, >= 10 com dados em cada sentido, payload médio < 150 bytes, duração >= 30 s, porta fora das comuns. |
| PCAP-004 | 3 | T1071 | Inícios de conexão regulares para o mesmo destino/porta (beaconing). |
| PCAP-005 | 5 | T1071 | Destino na blocklist. |

## Limitações importantes

- **Amostragem:** o `scan` fotografa o estado do sistema. Conexões que abrem e fecham entre duas
  varreduras passam despercebidas, e o beaconing depende do intervalo do `--watch`. Para cobertura
  contínua use Sysmon (EID 3) + SIEM com as regras da pasta `rules/`.
- **Tráfego cifrado:** o PCAP mostra metadados (portas, tempos, tamanhos), não o conteúdo.
- **Reverse shell em 443:** é detectado pelo comportamento (processo, pai, beaconing), não pela porta.
- **Evasão:** um atacante que use processo legítimo, porta comum e jitter alto reduz os sinais.
  Esta é uma camada de detecção, não uma defesa completa.
