# Testando em laboratório (sem criar nenhum shell)

Você não precisa de payload nenhum para validar a ferramenta.

## 1. Demo sintético
```bash
revshell-hunter demo
```
Roda os cenários de `demo.py` (nenhuma conexão real).

## 2. Regra de porta com tráfego benigno em loopback
Terminal A (um servidor TCP qualquer na porta 4444):
```bash
python -m http.server 4444 --bind 127.0.0.1
```
Terminal B (cliente que só abre a conexão e a mantém por um minuto):
```bash
python -c "import socket,time; s=socket.create_connection(('127.0.0.1',4444)); time.sleep(60)"
```
Terminal C (loopback é ignorado por padrão, então use `--include-private`):
```bash
revshell-hunter scan --include-private --min-score 3
```
Esperado: uma conexão do `python` para `127.0.0.1:4444` com `RSH-004` (porta típica) e `RSH-008`
(a linha de comando contém `python -c ... socket`). O processo não é um shell, então as regras
de shell não disparam. Os cenários com shell, pai suspeito e masquerading estão cobertos pelos
testes automatizados e pelo `demo`.

## 3. PCAP
Gere uma captura de tráfego do seu laboratório (ou use a de teste criada em `tests/test_pcap.py`
como referência de formato) e rode:
```bash
revshell-hunter pcap captura.pcap --html relatorio.html
```

## 4. Beaconing
Rode `revshell-hunter scan --watch 10 --include-private` enquanto um cliente de teste abre uma
conexão nova a cada ~60 s para um servidor seu em loopback. Após 6 conexões regulares a regra
`RSH-010` é disparada.
