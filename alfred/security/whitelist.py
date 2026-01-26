"""Command validation and whitelisting"""

import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


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
        """Load whitelisted commands from config"""
        commands = {}
        command_config = self.config.get('commands', {})
        
        for name, spec in command_config.items():
            commands[name] = CommandSpec(
                name=name,
                path=spec.get('path', ''),
                args_pattern=spec.get('args_pattern', '.*'),
                risk=spec.get('risk', 'warning'),
                confirm=spec.get('confirm', True)
            )
        
        return commands
    
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
