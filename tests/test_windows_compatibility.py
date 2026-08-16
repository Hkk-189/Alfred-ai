"""Regression tests for Windows-compatible defaults and terminal output."""

from pathlib import Path

import yaml

from alfred.config.manager import ConfigManager


def test_default_windows_config_is_valid():
    """The shipped Windows configuration must validate unchanged."""
    manager = ConfigManager.__new__(ConfigManager)
    manager.platform = "Windows"

    assert manager.validate(manager._get_default_config()) == []


def test_legacy_windows_config_is_backed_up_and_migrated(tmp_path):
    """Only old default Windows entries are changed during migration."""
    manager = ConfigManager.__new__(ConfigManager)
    manager.platform = "Windows"
    manager.config_dir = tmp_path
    config_file = tmp_path / "config.yaml"
    legacy_config = manager._get_default_config()
    legacy_config["commands"]["cmd"] = {
        "path": r"C:\Windows\System32\cmd.exe",
        "args_pattern": r"^[a-zA-Z0-9_\-\.\:\\/ ]*$",
        "risk": "warning",
        "confirm": True,
    }
    legacy_config["security"]["allowed_command_paths"].remove(r"C:\Windows")
    with open(config_file, "w") as file:
        yaml.dump(legacy_config, file)

    manager._migrate_legacy_windows_config(config_file)

    with open(config_file) as file:
        migrated = yaml.safe_load(file)
    assert "cmd" not in migrated["commands"]
    assert r"C:\Windows" in migrated["security"]["allowed_command_paths"]
    assert list(tmp_path.glob("config.yaml.bak-*"))
