# Playbook: alerta de possível reverse shell

Vale para achados de severidade **alta** (ou médios com contexto ruim).

## 1. Preservar evidência (antes de mexer)
- Registre: horário, host, usuário, PID, processo, pai, linha de comando, IP:porta remotos.
- Exporte o relatório (`--json`) e, se possível, capture tráfego (`tcpdump`/`Wireshark`/`pktmon`).
- Não encerre o processo ainda: ele guarda memória, handles e conexões úteis na análise.

## 2. Conter
- Isole o host da rede (VLAN de quarentena, desabilitar NIC, regra de firewall/EDR) em vez de desligar.
- Bloqueie o IP/domínio remoto no firewall/proxy de borda.
- Se houver conta envolvida, force logoff e redefina credenciais (de preferência depois do isolamento).

## 3. Investigar
- **Árvore de processos:** quem iniciou o shell? (Office, navegador, serviço web, tarefa agendada?)
- **Persistência (Windows):** chaves `Run`/`RunOnce`, tarefas agendadas, serviços novos, pasta Startup, WMI subscriptions.
- **Persistência (Linux):** crontab, systemd units, `~/.bashrc`, `authorized_keys`.
- **Alcance:** busque o mesmo IP/porta nos logs de firewall/proxy/DNS para achar outros hosts.
- **Origem:** e-mail com anexo, download recente, vulnerabilidade em serviço exposto.

## 4. Erradicar e recuperar
- Reconstrua o host a partir de imagem confiável se houver indício de comprometimento real.
- Troque credenciais e segredos que estavam acessíveis ao host.
- Aplique o patch/configuração que permitiu o acesso inicial.

## 5. Lições aprendidas
- Ajuste allowlist/pesos para falsos positivos confirmados.
- Transforme os indicadores em regras (Sigma/SIEM) e atualize a blocklist.
- Registre o incidente e o tempo de detecção/contenção.
