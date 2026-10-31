# Regras de detecção

| Arquivo | Plataforma | Dependência de log |
|---|---|---|
| `sigma/*.yml` | Sigma (converta com `sigma-cli` para Splunk, Elastic, Sentinel...) | Sysmon EID 1/3 ou equivalente |
| `splunk.md` | Splunk SPL | Sysmon |
| `elastic.md` | Elastic KQL / EQL | Sysmon via Winlogbeat/Agent |
| `sentinel.md` | Microsoft Sentinel / Defender XDR KQL | Defender for Endpoint |
| `../sysmon/sysmon-revshell.xml` | Sysmon | - |

Converter uma regra Sigma (exemplo):

```bash
pip install sigma-cli
sigma plugin install splunk
sigma convert -t splunk -p sysmon rules/sigma/net_connection_win_shell_external.yml
```

As regras Sigma e as queries foram escritas para este projeto e validadas **sintaticamente**
(YAML/XML nos testes). Elas não foram executadas contra instâncias reais das plataformas:
teste com dados do seu ambiente e ajuste os falsos positivos antes de gerar alertas.
