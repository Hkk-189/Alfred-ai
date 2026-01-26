"""Configuration management for Alfred"""

import os
import platform
from pathlib import Path
from typing import Dict, Any, Optional
import yaml


class ConfigManager:
    """Manages Alfred configuration with platform-specific paths"""
    
    def __init__(self):
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
            directory.mkdir(parents=True, exist_ok=True)
            
            # On Unix systems, set restrictive permissions
            if self.platform != "Windows":
                os.chmod(directory, 0o700)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        config_file = self.config_dir / "config.yaml"
        
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    return config if config else self._get_default_config()
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
                "require_confirmation_for": ["destructive", "network"],
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
                }
            }
        else:  # Linux
            return {
                "firefox": {
                    "path": "/usr/bin/firefox",
                    "args_pattern": "^https?://.*$",
                    "risk": "safe",
                    "confirm": False
                },
                "ls": {
                    "path": "/usr/bin/ls",
                    "args_pattern": "^[a-zA-Z0-9_\\-\\./~ ]*$",
                    "risk": "safe",
                    "confirm": False
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
