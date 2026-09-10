"""Configuration management for Alfred"""

import os
import platform
import re
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List
import yaml


class ConfigValidationError(Exception):
    """Raised when config validation fails"""
    pass


CONFIG_SCHEMA = {
    "ai": {
        "backend": {"type": str, "allowed": ["ollama", "api"]},
        "model": {"type": str},
        "api_provider": {"type": (str, type(None))},
        "api_key_env": {"type": str},
        "timeout": {"type": int, "min": 1, "max": 300},
        "max_tokens": {"type": int, "min": 1, "max": 10000},
    },
    "security": {
        "require_confirmation_for": {"type": list},
        "allowed_command_paths": {"type": list},
        "blocked_patterns": {"type": list},
    },
    "privacy": {
        "store_conversations": {"type": bool},
        "log_retention_days": {"type": int, "min": 1},
        "anonymize_logs": {"type": bool},
    },
}

RISK_LEVELS = ["safe", "warning", "destructive"]

ALLOWED_EXECUTABLE_PREFIXES = {
    "/usr/bin/", "/usr/local/bin/", "/bin/", "/snap/bin/",
    "/opt/", "/sbin/", "/usr/sbin/"
}

DANGEROUS_EXECUTABLES = {
    "python", "python2", "python3", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12",
    "bash", "sh", "dash", "zsh", "fish",
    "perl", "ruby", "php", "lua", "tcl",
    "node",
    "vim", "nano", "emacs", "subl",
    "curl", "wget", "nc", "netcat", "socat",
    "docker", "podman", "kubectl",
    "sudo", "su", "doas",
    "chmod", "chown", "chgrp",
    "dd", "mkfs", "fdisk", "parted",
    "shutdown", "reboot", "halt", "poweroff",
    "kill", "killall", "pkill",
    "eval", "exec",
}


class ConfigManager:
    """Manages Alfred configuration with platform-specific paths"""

    def __init__(self, validate: bool = True):
        self.platform = platform.system()
        self.config_dir = self._get_config_dir()
        self.data_dir = self._get_data_dir()
        self.cache_dir = self._get_cache_dir()
        self.log_dir = self._get_log_dir()
        
        # Ensure directories exist
        self._ensure_directories()
        
        # Load configuration
        self.config = self._load_config()
    
    def _get_config_dir(self) -> Path:
        """Get platform-specific config directory"""
        if self.platform == "Windows":
            base = os.environ.get("APPDATA", "")
            if not base:
                base = Path.home() / "AppData" / "Roaming"
            return Path(base) / "alfred"
        else:  # Linux
            base = os.environ.get("XDG_CONFIG_HOME", "")
            if not base:
                base = Path.home() / ".config"
            return Path(base) / "alfred"
    
    def _get_data_dir(self) -> Path:
        """Get platform-specific data directory"""
        if self.platform == "Windows":
            base = os.environ.get("LOCALAPPDATA", "")
            if not base:
                base = Path.home() / "AppData" / "Local"
            return Path(base) / "alfred"
        else:  # Linux
            base = os.environ.get("XDG_DATA_HOME", "")
            if not base:
                base = Path.home() / ".local" / "share"
            return Path(base) / "alfred"
    
    def _get_cache_dir(self) -> Path:
        """Get platform-specific cache directory"""
        if self.platform == "Windows":
            base = os.environ.get("TEMP", "")
            if not base:
                base = Path.home() / "AppData" / "Local" / "Temp"
            return Path(base) / "alfred"
        else:  # Linux
            base = os.environ.get("XDG_CACHE_HOME", "")
            if not base:
                base = Path.home() / ".cache"
            return Path(base) / "alfred"
    
    def _get_log_dir(self) -> Path:
        """Get platform-specific log directory"""
        if self.platform == "Windows":
            return self.data_dir / "logs"
        else:  # Linux
            return self.data_dir / "logs"
    
    def _ensure_directories(self):
        """Create necessary directories with appropriate permissions"""
        for directory in [self.config_dir, self.data_dir, self.cache_dir, self.log_dir]:
            if not directory.exists():
                if self.platform == "Windows":
                    directory.mkdir(parents=True, exist_ok=True)
                    self._set_windows_permissions(directory)
                else:
                    old_umask = os.umask(0o077)
                    try:
                        directory.mkdir(parents=True, exist_ok=True)
                    finally:
                        os.umask(old_umask)
                    os.chmod(directory, 0o700)
    
    def _set_windows_permissions(self, path: Path):
        """Set restrictive Windows ACLs (placeholder - requires pywin32)"""
        pass
    
    def _compute_config_hash(self, config_path: Path) -> str:
        """Compute SHA-256 hash of config file"""
        with open(config_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def _verify_config_integrity(self, config_file: Path) -> bool:
        """Verify config file hasn't been modified since last load"""
        hash_file = self.config_dir / ".config.hash"
        
        if not hash_file.exists():
            current_hash = self._compute_config_hash(config_file)
            with open(hash_file, 'w') as f:
                f.write(current_hash)
            return True
        
        with open(hash_file, 'r') as f:
            stored_hash = f.read().strip()
        
        current_hash = self._compute_config_hash(config_file)
        
        if stored_hash != current_hash:
            print("WARNING: Configuration file has been modified!")
            print("Please review changes before continuing.")
            return False
        
        return True
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        config_file = self.config_dir / "config.yaml"

        if config_file.exists():
            try:
                if not self._verify_config_integrity(config_file):
                    print("Using last known good config.")
                    return self._get_default_config()
                
                config = self._validate_and_load(config_file)
                return config if config else self._get_default_config()
            except ConfigValidationError as e:
                print(f"Config validation failed: {e}")
                print("Using default config.")
                return self._get_default_config()
            except Exception as e:
                print(f"Error loading config: {e}")
                return self._get_default_config()
        else:
            config = self._get_default_config()
            self.save_config(config)
            return config
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "ai": {
                "backend": "ollama",
                "model": "llama2",
                "api_provider": None,
                "api_key_env": "OPENAI_API_KEY",
                "timeout": 30,
                "max_tokens": 2000
            },
            "security": {
                "require_confirmation_for": ["destructive"],
                "allowed_command_paths": self._get_default_allowed_paths(),
                "blocked_patterns": [
                    ".*rm.*-rf.*",
                    ".*sudo.*",
                    ".*chmod.*777.*",
                    ".*dd.*if=.*"
                ]
            },
            "privacy": {
                "store_conversations": False,
                "log_retention_days": 30,
                "anonymize_logs": True
            },
            "commands": self._get_default_commands()
        }
    
    def _get_default_allowed_paths(self) -> list:
        """Get default allowed command paths based on platform"""
        if self.platform == "Windows":
            return [
                "C:\\Windows\\System32",
                "C:\\Program Files",
                "C:\\Program Files (x86)"
            ]
        else:  # Linux
            return [
                "/usr/bin",
                "/usr/local/bin",
                "/bin"
            ]
    
    def _get_default_commands(self) -> Dict[str, Dict[str, Any]]:
        """Get default whitelisted commands based on platform"""
        if self.platform == "Windows":
            return {
                "notepad": {
                    "path": "C:\\Windows\\System32\\notepad.exe",
                    "args_pattern": "^[a-zA-Z0-9_\\-\\.\\:\\\\/ ]+$",
                    "risk": "safe",
                    "confirm": False
                },
                "explorer": {
                    "path": "C:\\Windows\\explorer.exe",
                    "args_pattern": "^[a-zA-Z0-9_\\-\\.\\:\\\\/ ]+$",
                    "risk": "safe",
                    "confirm": False
                },
                "cmd": {
                    "path": "C:\\Windows\\System32\\cmd.exe",
                    "args_pattern": "^[a-zA-Z0-9_\\-\\.\\:\\\\/ ]*$",
                    "risk": "warning",
                    "confirm": True
                }
            }
        else:  # Linux
            return {
                "ls": {
                    "path": "/usr/bin/ls",
                    "args_pattern": "^[a-zA-Z0-9_\\-\\./~ ]*$",
                    "risk": "safe",
                    "confirm": False
                },
                "pwd": {
                    "path": "/usr/bin/pwd",
                    "args_pattern": "^[a-zA-Z0-9_\\-]*$",
                    "risk": "safe",
                    "confirm": False
                },
                "whoami": {
                    "path": "/usr/bin/whoami",
                    "args_pattern": "^$",
                    "risk": "safe",
                    "confirm": False
                },
                "date": {
                    "path": "/usr/bin/date",
                    "args_pattern": "^[a-zA-Z0-9_\\-%+: ]*$",
                    "risk": "safe",
                    "confirm": False
                },
                "uname": {
                    "path": "/usr/bin/uname",
                    "args_pattern": "^-[a-zrsvmpio]+$",
                    "risk": "safe",
                    "confirm": False
                },
                "which": {
                    "path": "/usr/bin/which",
                    "args_pattern": "^[a-zA-Z0-9_\\-\\./~ ]+$",
                    "risk": "safe",
                    "confirm": False
                },
                "echo": {
                    "path": "/usr/bin/echo",
                    "args_pattern": "^[a-zA-Z0-9_\\-\\./~ !?%@]+$",
                    "risk": "safe",
                    "confirm": False
                },
                "cat": {
                    "path": "/usr/bin/cat",
                    "args_pattern": "^[a-zA-Z0-9_\\-\\./~ ]+$",
                    "risk": "safe",
                    "confirm": False
                },
                "mkdir": {
                    "path": "/usr/bin/mkdir",
                    "args_pattern": "^-[pvm]+$|^[a-zA-Z0-9_\\-\\./~ ]+$",
                    "risk": "safe",
                    "confirm": False
                },
                "touch": {
                    "path": "/usr/bin/touch",
                    "args_pattern": "^[a-zA-Z0-9_\\-\\./~ ]+$",
                    "risk": "safe",
                    "confirm": False
                },
                "firefox": {
                    "path": "/usr/bin/firefox",
                    "args_pattern": "^https?://[a-zA-Z0-9\\-\\._~:/?#\\[\\]@!$&'()*+,;=%]+$",
                    "risk": "safe",
                    "confirm": False
                },
                "git": {
                    "path": "/usr/bin/git",
                    "args_pattern": "^(status|log|diff|pull|push|commit|add|checkout|branch|fetch|clone|init)\\s.*$",
                    "risk": "warning",
                    "confirm": True
                },
                "rm": {
                    "path": "/usr/bin/rm",
                    "args_pattern": "^-[rfiI]+$",
                    "risk": "destructive",
                    "confirm": True
                },
                "cp": {
                    "path": "/usr/bin/cp",
                    "args_pattern": "^-[irp]+$",
                    "risk": "destructive",
                    "confirm": True
                },
                "mv": {
                    "path": "/usr/bin/mv",
                    "args_pattern": "^-[fiIu]+$",
                    "risk": "destructive",
                    "confirm": True
                }
            }
    
    def save_config(self, config: Optional[Dict[str, Any]] = None):
        """Save configuration to file"""
        if config is None:
            config = self.config
        
        config_file = self.config_dir / "config.yaml"
        
        try:
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
            # Set restrictive permissions on config file
            if self.platform != "Windows":
                os.chmod(config_file, 0o600)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value by dot-notation key"""
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value
        self.save_config()

    def validate(self, config: Optional[Dict[str, Any]] = None) -> List[str]:
        """Validate config and return list of errors. Empty = valid."""
        if config is None:
            config = self.config

        errors = []

        for section, schema in CONFIG_SCHEMA.items():
            if section not in config:
                errors.append(f"Missing section: {section}")
                continue

            section_data = config[section]
            if not isinstance(section_data, dict):
                errors.append(f"Section '{section}' must be a dictionary")
                continue

            for key, spec in schema.items():
                if key not in section_data:
                    continue

                value = section_data[key]
                expected_type = spec["type"]

                if not isinstance(value, expected_type):
                    errors.append(
                        f"'{section}.{key}' must be {expected_type.__name__}, got {type(value).__name__}"
                    )
                    continue

                if "min" in spec and isinstance(value, (int, float)):
                    if value < spec["min"]:
                        errors.append(f"'{section}.{key}' must be >= {spec['min']}")
                    if value > spec.get("max", float("inf")):
                        errors.append(f"'{section}.{key}' must be <= {spec['max']}")

                if "allowed" in spec:
                    if isinstance(spec["allowed"], list) and value not in spec["allowed"]:
                        errors.append(f"'{section}.{key}' must be one of: {spec['allowed']}")

        if "commands" in config:
            for cmd_name, cmd_spec in config["commands"].items():
                if not isinstance(cmd_spec, dict):
                    errors.append(f"Command '{cmd_name}' must be a dictionary")
                    continue

                required = ["path", "args_pattern", "risk", "confirm"]
                for field in required:
                    if field not in cmd_spec:
                        errors.append(f"Command '{cmd_name}' missing field: {field}")

                if "risk" in cmd_spec and cmd_spec["risk"] not in RISK_LEVELS:
                    errors.append(f"Command '{cmd_name}' risk must be one of: {RISK_LEVELS}")

                if "args_pattern" in cmd_spec:
                    pattern = cmd_spec["args_pattern"]
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        errors.append(f"Command '{cmd_name}' regex invalid: {e}")

                    if pattern == ".*":
                        errors.append(f"Command '{cmd_name}' has overly permissive args_pattern: '{pattern}'")

                path = cmd_spec.get("path", "")
                if path:
                    exe_name = os.path.basename(path).lower()
                    if exe_name in DANGEROUS_EXECUTABLES:
                        errors.append(f"Command '{cmd_name}' uses dangerous executable: {exe_name}")
                    if not any(path.startswith(prefix) for prefix in ALLOWED_EXECUTABLE_PREFIXES):
                        errors.append(f"Command '{cmd_name}' path not in allowed prefixes: {path}")

        return errors

    def _validate_and_load(self, config_file: Path) -> Dict[str, Any]:
        """Load config with validation"""
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"Invalid YAML: {e}")
        except Exception as e:
            raise ConfigValidationError(f"Cannot read config: {e}")

        errors = self.validate(config)
        if errors:
            raise ConfigValidationError("\n".join(errors))

        return config
