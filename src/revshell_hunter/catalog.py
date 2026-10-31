"""Catálogo de regras: id -> (título, técnica MITRE ATT&CK)."""

from __future__ import annotations

from typing import Dict, Tuple

RULES: Dict[str, Tuple[str, str]] = {
    "RSH-001": ("Shell com conexão externa", "T1059"),
    "RSH-002": ("Ferramenta de rede/tunelamento com conexão externa", "T1095"),
    "RSH-003": ("LOLBin com conexão externa", "T1218"),
    "RSH-004": ("Porta de destino típica de payload/shell", "T1571"),
    "RSH-005": ("Porta de destino incomum", "T1571"),
    "RSH-006": ("Binário em diretório gravável/suspeito", "T1036"),
    "RSH-007": ("Processo pai suspeito gerou shell/LOLBin", "T1059"),
    "RSH-008": ("Linha de comando com padrão suspeito", "T1059"),
    "RSH-009": ("Binário de sistema fora dos diretórios do sistema", "T1036.005"),
    "RSH-010": ("Beaconing (reconexões regulares)", "T1071"),
    "RSH-011": ("Destino na blocklist", "T1071"),
    "PCAP-001": ("Sessão estabelecida em porta típica de shell", "T1571"),
    "PCAP-002": ("Fluxo sustentado em porta incomum", "T1571"),
    "PCAP-003": ("Fluxo interativo (muitos pacotes pequenos nos dois sentidos)", "T1059"),
    "PCAP-004": ("Beaconing (inícios de conexão regulares)", "T1071"),
    "PCAP-005": ("Destino na blocklist", "T1071"),
}


def mitre_for(rule_id: str) -> str:
    return RULES.get(rule_id, ("", ""))[1]


def title_for(rule_id: str) -> str:
    return RULES.get(rule_id, (rule_id, ""))[0]
