# Queries Elastic (Winlogbeat/Elastic Agent + Sysmon, campos ECS)

> Ajuste nomes de campo ao seu pipeline de ingestão. Não testadas contra uma stack real.

## 1. KQL - shell com conexão de saída externa

```kql
event.code : "3" and process.name : ("cmd.exe" or "powershell.exe" or "pwsh.exe" or "mshta.exe" or "wscript.exe" or "cscript.exe")
  and network.direction : "egress"
  and not destination.ip : ("10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16" or "127.0.0.0/8" or "169.254.0.0/16")
```

## 2. KQL - portas típicas de payload (exceto navegadores)

```kql
event.code : "3" and network.direction : "egress"
  and destination.port : (1234 or 1337 or 4444 or 4445 or 5555 or 6666 or 7777 or 8888 or 9001 or 9999 or 12345 or 31337 or 54321)
  and not process.name : ("chrome.exe" or "msedge.exe" or "firefox.exe")
  and not destination.ip : ("10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16" or "127.0.0.0/8")
```

## 3. EQL - pai suspeito gerando shell

```eql
process where event.type == "start" and
  process.parent.name : ("winword.exe", "excel.exe", "outlook.exe", "w3wp.exe", "sqlservr.exe", "php.exe") and
  process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe")
```

## 4. EQL - shell iniciado seguido de conexão externa pelo mesmo processo (1 min)

```eql
sequence by host.id, process.entity_id with maxspan=1m
  [process where event.type == "start" and process.name : ("cmd.exe", "powershell.exe", "pwsh.exe")]
  [network where event.type == "start" and network.direction == "egress" and
   not cidrMatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]
```
