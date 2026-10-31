# Queries Splunk (Sysmon via Splunk Add-on for Sysmon)

> Ajuste `index`, `sourcetype` e nomes de campo ao seu ambiente. Queries não testadas contra
> uma instância real: valide em ambiente de teste antes de transformar em alerta.

## 1. Shell/interpretador com conexão de saída externa (Event ID 3)

```spl
index=sysmon EventCode=3 Initiated=true
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
   OR Image="*\\mshta.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe")
| where NOT (cidrmatch("10.0.0.0/8",DestinationIp) OR cidrmatch("172.16.0.0/12",DestinationIp)
    OR cidrmatch("192.168.0.0/16",DestinationIp) OR cidrmatch("127.0.0.0/8",DestinationIp)
    OR cidrmatch("169.254.0.0/16",DestinationIp))
| stats count min(_time) as first_seen max(_time) as last_seen
        values(DestinationPort) as ports by host, User, Image, DestinationIp
| convert ctime(first_seen) ctime(last_seen)
```

## 2. Conexões para portas típicas de payload, exceto navegadores

```spl
index=sysmon EventCode=3 Initiated=true
  DestinationPort IN (1234,1337,4444,4445,5555,6666,7777,8888,9001,9999,12345,31337,54321)
  NOT Image IN ("*\\chrome.exe","*\\msedge.exe","*\\firefox.exe")
| where NOT (cidrmatch("10.0.0.0/8",DestinationIp) OR cidrmatch("172.16.0.0/12",DestinationIp)
    OR cidrmatch("192.168.0.0/16",DestinationIp) OR cidrmatch("127.0.0.0/8",DestinationIp))
| stats count values(DestinationPort) as ports by host, Image, DestinationIp
```

## 3. Correlação processo + rede (processo pai suspeito com conexão externa)

```spl
index=sysmon host=* (EventCode=1 OR EventCode=3)
| eval ext=if(EventCode=3 AND NOT (cidrmatch("10.0.0.0/8",DestinationIp)
    OR cidrmatch("172.16.0.0/12",DestinationIp) OR cidrmatch("192.168.0.0/16",DestinationIp)
    OR cidrmatch("127.0.0.0/8",DestinationIp)),1,0)
| stats values(Image) as image values(ParentImage) as parent values(CommandLine) as cmdline
        values(DestinationIp) as dest values(DestinationPort) as dport sum(ext) as ext_conns
        by host, ProcessGuid
| where ext_conns>0
  AND match(mvindex(image,0),"(?i)(cmd|powershell|pwsh|mshta)\\.exe$")
  AND match(mvindex(parent,0),"(?i)(winword|excel|outlook|w3wp|sqlservr)\\.exe$")
```

## 4. Beaconing (intervalos regulares entre conexões ao mesmo destino)

```spl
index=sysmon EventCode=3 Initiated=true
| where NOT (cidrmatch("10.0.0.0/8",DestinationIp) OR cidrmatch("172.16.0.0/12",DestinationIp)
    OR cidrmatch("192.168.0.0/16",DestinationIp) OR cidrmatch("127.0.0.0/8",DestinationIp))
| sort 0 host, DestinationIp, DestinationPort, _time
| streamstats current=f last(_time) as prev_time by host DestinationIp DestinationPort
| eval delta=_time-prev_time
| where isnotnull(delta)
| stats count avg(delta) as avg_delta stdev(delta) as sd_delta
        by host, Image, DestinationIp, DestinationPort
| eval cv=round(sd_delta/avg_delta,2)
| where count>=8 AND avg_delta>=5 AND cv<0.3
| sort cv
```
