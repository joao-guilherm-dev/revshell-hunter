# Contribuindo

1. Faça um fork e crie uma branch: `git checkout -b feat/minha-ideia`.
2. Instale o ambiente de desenvolvimento:
   ```bash
   python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   ```
3. Rode os checks antes do commit:
   ```bash
   ruff check .
   pytest
   ```
4. Toda regra nova precisa de: peso em `data/default_rules.yaml`, entrada em `catalog.py`,
   linha em `docs/detection-rules.md` e pelo menos um teste (o `tests/test_docs.py` quebra se faltar algo).
5. Abra o Pull Request descrevendo o cenário de ataque coberto **e** os possíveis falsos positivos.

Contribuições de regras Sigma/SIEM e de ajustes de falso positivo são muito bem-vindas.
Não aceitamos código ofensivo (geradores de payload, C2, etc.): o projeto é só detecção.
