# Queries Microsoft Sentinel / Defender XDR (KQL)

> Usam as tabelas `DeviceNetworkEvents` e `DeviceProcessEvents` (Defender for Endpoint).
> Não testadas contra um workspace real: valide e ajuste antes de criar regras analíticas.

## 1. Shell com conexão externa

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, RemoteIP, RemotePort
| order by Timestamp desc
```

## 2. Portas típicas de payload (exceto navegadores)

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public"
| where RemotePort in (1234,1337,4444,4445,5555,6666,7777,8888,9001,9999,12345,31337,54321)
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe")
| summarize conexoes = count(), portas = make_set(RemotePort) by DeviceName, InitiatingProcessFileName, RemoteIP
```

## 3. Office/servidor web gerando shell

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe","w3wp.exe","sqlservr.exe","php.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## 4. Beaconing

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend delta = datetime_diff('second', Timestamp, prev(Timestamp)),
         same = (DeviceName == prev(DeviceName) and RemoteIP == prev(RemoteIP) and RemotePort == prev(RemotePort))
| where same
| summarize n = count(), media = avg(delta), desvio = stdev(delta)
          by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where n >= 8 and media >= 5 and desvio / media < 0.3
| order by desvio asc
```
