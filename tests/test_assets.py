"""Valida arquivos de regras, docs e consistência do catálogo."""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from revshell_hunter.catalog import RULES

ROOT = Path(__file__).resolve().parent.parent
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def test_sigma_rules_are_valid():
    files = sorted((ROOT / "rules" / "sigma").glob("*.yml"))
    assert len(files) >= 6
    seen = set()
    for path in files:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        for key in ("title", "id", "status", "description", "logsource", "detection", "level"):
            assert key in rule, f"{path.name}: falta '{key}'"
        assert UUID.match(rule["id"]) and rule["id"] not in seen, path.name
        seen.add(rule["id"])
        assert "condition" in rule["detection"], path.name
        assert rule["level"] in {"informational", "low", "medium", "high", "critical"}
        # toda seleção citada na condição precisa existir
        names = set(re.findall(r"[a-z_]+", rule["detection"]["condition"])) - {
            "and", "or", "not", "of", "them", "all", "1"}
        assert names <= set(rule["detection"]), f"{path.name}: seleção inexistente {names}"


def test_sysmon_config_is_well_formed():
    root = ET.parse(ROOT / "sysmon" / "sysmon-revshell.xml").getroot()
    assert root.tag == "Sysmon" and root.find("EventFiltering") is not None


def test_docs_mention_every_rule():
    text = (ROOT / "docs" / "detection-rules.md").read_text(encoding="utf-8")
    missing = [rid for rid in RULES if rid not in text]
    assert not missing, f"docs/detection-rules.md sem: {missing}"


def test_required_repo_files_exist():
    for name in ("README.md", "LICENSE", "Dockerfile", "docker-compose.yml", "pyproject.toml",
                 ".github/workflows/ci.yml", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md"):
        assert (ROOT / name).exists(), name
