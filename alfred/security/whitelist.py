"""Command validation and whitelisting"""

import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


DANGEROUS_EXECUTABLES = {
    "python", "python2", "python3", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12",
    "bash", "sh", "dash", "zsh", "fish",
    "perl", "ruby", "php", "lua", "tcl",
    "node",
    "vim", "nano", "emacs", "subl",
    "curl", "wget", "nc", "netcat", "socat",
    "docker", "podman", "kubectl",
    "sudo", "su", "doas",
    "eval", "exec",
}


@dataclass
class CommandSpec:
    """Specification for a whitelisted command"""
    name: str
    path: str
    args_pattern: str
    risk: str  # 'safe', 'warning', 'destructive'
    confirm: bool


class CommandWhitelist:
    """Manages whitelisted commands"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.commands = self._load_commands()
    
    def _load_commands(self) -> Dict[str, CommandSpec]:
        """Load whitelisted commands from config with path validation"""
        commands = {}
        command_config = self.config.get('commands', {})
        allowed_paths = self.config.get('security', {}).get('allowed_command_paths', [])
        
        for name, spec in command_config.items():
            cmd_path = spec.get('path', '')
            
            if not cmd_path:
                continue
            
            exe_name = os.path.basename(cmd_path).lower()
            if exe_name in DANGEROUS_EXECUTABLES:
                print(f"WARNING: Skipping command '{name}' - dangerous executable blocked: {exe_name}")
                continue
            
            if allowed_paths and not self._is_path_allowed(cmd_path, allowed_paths):
                print(f"WARNING: Skipping command '{name}' - path not in allowed directories: {cmd_path}")
                continue
            
            if not os.path.isfile(cmd_path):
                print(f"WARNING: Skipping command '{name}' - file not found: {cmd_path}")
                continue
            
            if not os.access(cmd_path, os.X_OK):
                print(f"WARNING: Skipping command '{name}' - file not executable: {cmd_path}")
                continue
            
            commands[name] = CommandSpec(
                name=name,
                path=cmd_path,
                args_pattern=spec.get('args_pattern', '.*'),
                risk=spec.get('risk', 'warning'),
                confirm=spec.get('confirm', True)
            )
        
        return commands
    
    def _is_path_allowed(self, cmd_path: str, allowed_paths: List[str]) -> bool:
        """Check if command path is within allowed directories"""
        try:
            cmd_resolved = Path(cmd_path).resolve()
            
            for allowed in allowed_paths:
                allowed_resolved = Path(allowed).resolve()
                try:
                    cmd_resolved.relative_to(allowed_resolved)
                    return True
                except ValueError:
                    continue
            
            return False
        except Exception:
            return False
    
    def is_whitelisted(self, command_name: str) -> bool:
        """Check if a command is whitelisted"""
        return command_name in self.commands
    
    def get_command_spec(self, command_name: str) -> Optional[CommandSpec]:
        """Get specification for a whitelisted command"""
        return self.commands.get(command_name)
    
    def list_commands(self) -> List[str]:
        """List all whitelisted command names"""
        return list(self.commands.keys())
    
    def get_executable_path(self, command_name: str) -> Optional[str]:
        """Get the executable path for a whitelisted command"""
        spec = self.get_command_spec(command_name)
        if spec and os.path.exists(spec.path):
            return spec.path
        return None
    
    def add_command(self, name: str, path: str, args_pattern: str = ".*",
                   risk: str = "warning", confirm: bool = True):
        """Add a new command to the whitelist"""
        self.commands[name] = CommandSpec(
            name=name,
            path=path,
            args_pattern=args_pattern,
            risk=risk,
            confirm=confirm
        )
        
        # Update config
        if 'commands' not in self.config:
            self.config['commands'] = {}
        
        self.config['commands'][name] = {
            'path': path,
            'args_pattern': args_pattern,
            'risk': risk,
            'confirm': confirm
        }
    
    def remove_command(self, name: str):
        """Remove a command from the whitelist"""
        if name in self.commands:
            del self.commands[name]
            if 'commands' in self.config and name in self.config['commands']:
                del self.config['commands'][name]
