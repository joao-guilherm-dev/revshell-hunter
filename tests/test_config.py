import pytest

from revshell_hunter.catalog import RULES
from revshell_hunter.config import ConfigError, load_config


def test_default_config_loads_and_covers_every_rule(cfg):
    assert set(cfg.weights) == set(RULES)
    assert 4444 in cfg.suspicious_ports and 443 in cfg.common_ports
    assert all(p.regex.pattern for p in cfg.cmdline_patterns)


def test_extra_lists_and_dict_merge(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("extra_shells: [mysh]\nweights: {RSH-001: 9}\nmin_score: 5\n", encoding="utf-8")
    cfg = load_config(f)
    assert "mysh" in cfg.shells and "cmd.exe" in cfg.shells
    assert cfg.weight("RSH-001") == 9 and cfg.weight("RSH-002") == 4
    assert cfg.min_score == 5


def test_unknown_key_is_rejected(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("shels: [x]\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(f)


def test_invalid_port_and_empty_allowlist_rejected():
    with pytest.raises(ConfigError):
        load_config(overrides={"suspicious_ports": [70000]})
    with pytest.raises(ConfigError):
        load_config(overrides={"allowlist": [{}]})


def test_blocklist_file_relative_to_config(tmp_path):
    (tmp_path / "bl.txt").write_text("# comentário\n203.0.113.0/24\n8.8.4.4\n", encoding="utf-8")
    f = tmp_path / "c.yaml"
    f.write_text("blocklist_file: bl.txt\n", encoding="utf-8")
    cfg = load_config(f)
    assert cfg.is_blocklisted("203.0.113.9") and cfg.is_blocklisted("8.8.4.4")
    assert not cfg.is_blocklisted("1.1.1.1")


def test_severity_thresholds(cfg):
    assert [cfg.severity_for(s) for s in (1, 4, 7, 12)] == ["low", "medium", "high", "high"]
