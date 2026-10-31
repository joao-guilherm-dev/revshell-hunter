"""Carregamento e validação das regras (YAML)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import yaml

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class ConfigError(ValueError):
    """Configuração inválida."""


LIST_KEYS = {
    "shells", "net_tools", "lolbins", "suspicious_parents", "common_ports",
    "suspicious_ports", "suspicious_paths", "trusted_processes",
    "windows_system_binaries", "trusted_system_dirs", "cmdline_patterns",
    "allowlist", "blocklist_ips",
}
DICT_KEYS = {"weights", "severity", "beacon"}
SCALAR_KEYS = {"min_score", "blocklist_file"}
ALLOWED_KEYS = LIST_KEYS | DICT_KEYS | SCALAR_KEYS


@dataclass(frozen=True)
class CmdPattern:
    name: str
    regex: "re.Pattern[str]"


@dataclass(frozen=True)
class AllowRule:
    process: Optional[str] = None
    parent: Optional[str] = None
    remote_cidr: Optional[IPNetwork] = None
    remote_port: Optional[int] = None

    def matches(self, process: str, parent: str, remote_ip: str, remote_port: int) -> bool:
        if self.process is not None and process != self.process:
            return False
        if self.parent is not None and parent != self.parent:
            return False
        if self.remote_port is not None and remote_port != self.remote_port:
            return False
        if self.remote_cidr is not None:
            try:
                addr = ipaddress.ip_address(remote_ip)
            except ValueError:
                return False
            if addr not in self.remote_cidr:
                return False
        return True


@dataclass(frozen=True)
class BeaconConfig:
    min_events: int = 6
    max_cv: float = 0.25
    min_interval_seconds: float = 5.0
    history_seconds: float = 3600.0


@dataclass
class Config:
    shells: Set[str]
    net_tools: Set[str]
    lolbins: Set[str]
    suspicious_parents: Set[str]
    common_ports: Set[int]
    suspicious_ports: Set[int]
    suspicious_paths: Tuple[str, ...]
    trusted_processes: Set[str]
    windows_system_binaries: Set[str]
    trusted_system_dirs: Tuple[str, ...]
    cmdline_patterns: List[CmdPattern]
    weights: Dict[str, int]
    severity: Dict[str, int]
    min_score: int
    beacon: BeaconConfig
    allowlist: List[AllowRule] = field(default_factory=list)
    blocklist: List[IPNetwork] = field(default_factory=list)

    # ------------------------------------------------------------------ helpers
    def weight(self, rule_id: str) -> int:
        return int(self.weights.get(rule_id, 0))

    def is_allowlisted(self, process: str, parent: str, remote_ip: str, remote_port: int) -> bool:
        return any(r.matches(process, parent, remote_ip, remote_port) for r in self.allowlist)

    def is_blocklisted(self, remote_ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(remote_ip.split("%")[0])
        except ValueError:
            return False
        return any(addr in net for net in self.blocklist)

    def severity_for(self, score: int) -> str:
        if score >= self.severity["high"]:
            return "high"
        if score >= self.severity["medium"]:
            return "medium"
        return "low"

    # --------------------------------------------------------------- construction
    @classmethod
    def from_dict(cls, data: Dict[str, Any], base_dir: Optional[Path] = None) -> "Config":
        unknown = set(data) - ALLOWED_KEYS
        if unknown:
            raise ConfigError(f"chaves desconhecidas na configuração: {sorted(unknown)}")

        def names(key: str) -> Set[str]:
            return {str(v).lower() for v in data.get(key, [])}

        def ports(key: str) -> Set[int]:
            out = set()
            for v in data.get(key, []):
                if not isinstance(v, int) or not 1 <= v <= 65535:
                    raise ConfigError(f"porta inválida em '{key}': {v!r}")
                out.add(v)
            return out

        patterns = []
        for item in data.get("cmdline_patterns", []):
            try:
                patterns.append(CmdPattern(item["name"], re.compile(item["regex"])))
            except (KeyError, TypeError, re.error) as exc:
                raise ConfigError(f"cmdline_pattern inválido: {item!r} ({exc})") from exc

        allow = [_parse_allow(item) for item in data.get("allowlist", [])]

        blocklist = [_parse_network(v) for v in data.get("blocklist_ips", [])]
        bl_file = data.get("blocklist_file")
        if bl_file:
            path = Path(bl_file)
            if not path.is_absolute() and base_dir is not None:
                path = base_dir / path
            blocklist.extend(_read_blocklist(path))

        sev = {k: int(v) for k, v in data.get("severity", {}).items()}
        for level in ("high", "medium", "low"):
            if level not in sev:
                raise ConfigError(f"severity.{level} ausente")

        return cls(
            shells=names("shells"),
            net_tools=names("net_tools"),
            lolbins=names("lolbins"),
            suspicious_parents=names("suspicious_parents"),
            common_ports=ports("common_ports"),
            suspicious_ports=ports("suspicious_ports"),
            suspicious_paths=tuple(str(p).lower() for p in data.get("suspicious_paths", [])),
            trusted_processes=names("trusted_processes"),
            windows_system_binaries=names("windows_system_binaries"),
            trusted_system_dirs=tuple(str(p).lower() for p in data.get("trusted_system_dirs", [])),
            cmdline_patterns=patterns,
            weights={str(k): int(v) for k, v in data.get("weights", {}).items()},
            severity=sev,
            min_score=int(data.get("min_score", 3)),
            beacon=BeaconConfig(**data.get("beacon", {})),
            allowlist=allow,
            blocklist=blocklist,
        )


def _parse_network(value: Any) -> IPNetwork:
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError as exc:
        raise ConfigError(f"IP/CIDR inválido: {value!r}") from exc


def _read_blocklist(path: Path) -> List[IPNetwork]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfigError(f"não foi possível ler blocklist_file '{path}': {exc}") from exc
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(_parse_network(line))
    return out


def _parse_allow(item: Any) -> AllowRule:
    if not isinstance(item, dict):
        raise ConfigError(f"item de allowlist inválido: {item!r}")
    unknown = set(item) - {"process", "parent", "remote_cidr", "remote_port"}
    if unknown:
        raise ConfigError(f"campos desconhecidos na allowlist: {sorted(unknown)}")
    if not item:
        raise ConfigError("item de allowlist vazio casaria com tudo")
    return AllowRule(
        process=str(item["process"]).lower() if "process" in item else None,
        parent=str(item["parent"]).lower() if "parent" in item else None,
        remote_cidr=_parse_network(item["remote_cidr"]) if "remote_cidr" in item else None,
        remote_port=int(item["remote_port"]) if "remote_port" in item else None,
    )


def default_dict() -> Dict[str, Any]:
    text = (
        resources.files("revshell_hunter")
        .joinpath("data")
        .joinpath("default_rules.yaml")
        .read_text(encoding="utf-8")
    )
    return yaml.safe_load(text)


def merge_config(base: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in user.items():
        if key.startswith("extra_") and key[len("extra_"):] in LIST_KEYS:
            target = key[len("extra_"):]
            merged[target] = list(merged.get(target, [])) + list(value)
        elif key in DICT_KEYS:
            merged[key] = {**merged.get(key, {}), **value}
        else:
            merged[key] = value
    return merged


def load_config(
    path: Optional[Union[str, Path]] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> Config:
    """Carrega as regras padrão e, opcionalmente, mescla um YAML do usuário e overrides."""
    data = default_dict()
    base_dir: Optional[Path] = None
    if path is not None:
        p = Path(path)
        try:
            user = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"não foi possível carregar '{p}': {exc}") from exc
        if not isinstance(user, dict):
            raise ConfigError(f"'{p}' precisa conter um mapa YAML")
        data = merge_config(data, user)
        base_dir = p.parent
    if overrides:
        data = merge_config(data, overrides)
    return Config.from_dict(data, base_dir=base_dir)
