"""Policy enforcement and security validation"""

import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class PolicyViolation:
    """Represents a policy violation"""
    violation_type: str
    message: str
    details: Dict[str, Any]


class SecurityPolicy:
    """Enforces security boundaries and policies"""
    
    # Hard-coded security policies (CANNOT be overridden)
    FORBIDDEN_PATTERNS = [
        r'shell\s*=\s*True',  # No shell=True ever
        r'eval\s*\(',  # No eval
        r'exec\s*\(',  # No exec
        r'__import__\s*\(',  # No dynamic imports
        r'subprocess\.call\s*\([^,]*,\s*shell\s*=\s*True',
    ]
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.blocked_patterns = self._compile_blocked_patterns()
    
    def _compile_blocked_patterns(self) -> List[re.Pattern]:
        """Compile blocked command patterns from config"""
        patterns = self.config.get('security', {}).get('blocked_patterns', [])
        return [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    
    def validate_command(self, command: str, args: List[str]) -> Optional[PolicyViolation]:
        """
        Validate command against security policies.
        
        Returns:
            PolicyViolation if command violates policy, None if valid
        """
        # Check for forbidden patterns in command
        full_command = f"{command} {' '.join(args)}"
        
        for pattern in self.FORBIDDEN_PATTERNS:
            if re.search(pattern, full_command):
                return PolicyViolation(
                    violation_type="FORBIDDEN_PATTERN",
                    message=f"Command contains forbidden pattern: {pattern}",
                    details={'command': command, 'args': args}
                )
        
        # Check user-configured blocked patterns
        for pattern in self.blocked_patterns:
            if pattern.search(full_command):
                return PolicyViolation(
                    violation_type="BLOCKED_PATTERN",
                    message=f"Command matches blocked pattern",
                    details={'command': command, 'args': args, 'pattern': pattern.pattern}
                )
        
        return None
    
    def validate_path(self, path: str, allowed_dirs: Optional[List[str]] = None) -> Optional[PolicyViolation]:
        """
        Validate file path for security issues.
        
        Args:
            path: Path to validate
            allowed_dirs: List of allowed base directories (optional)
            
        Returns:
            PolicyViolation if path is invalid, None if valid
        """
        try:
            # Resolve to absolute path to detect traversal attempts
            resolved_path = Path(path).resolve()
            
            # Check for path traversal indicators
            if '..' in str(path):
                return PolicyViolation(
                    violation_type="PATH_TRAVERSAL",
                    message="Path contains traversal sequence (..)",
                    details={'path': path}
                )
            
            # If allowed directories specified, verify path is within them
            if allowed_dirs:
                allowed = False
                for allowed_dir in allowed_dirs:
                    allowed_base = Path(allowed_dir).resolve()
                    try:
                        # Check if resolved path is relative to allowed directory
                        resolved_path.relative_to(allowed_base)
                        allowed = True
                        break
                    except ValueError:
                        continue
                
                if not allowed:
                    return PolicyViolation(
                        violation_type="PATH_NOT_ALLOWED",
                        message="Path is outside allowed directories",
                        details={'path': str(resolved_path), 'allowed_dirs': allowed_dirs}
                    )
            
            return None
            
        except Exception as e:
            return PolicyViolation(
                violation_type="PATH_VALIDATION_ERROR",
                message=f"Error validating path: {str(e)}",
                details={'path': path}
            )
    
    def validate_arguments(self, args: List[str], pattern: str) -> Optional[PolicyViolation]:
        """
        Validate command arguments against allowed pattern.
        
        Args:
            args: List of arguments
            pattern: Regex pattern that arguments must match
            
        Returns:
            PolicyViolation if arguments don't match pattern, None if valid
        """
        try:
            arg_regex = re.compile(pattern)
            args_string = ' '.join(args)
            
            if not arg_regex.match(args_string):
                return PolicyViolation(
                    violation_type="INVALID_ARGUMENTS",
                    message="Arguments don't match allowed pattern",
                    details={'args': args, 'pattern': pattern}
                )
            
            # Additional length check to prevent excessively long arguments
            if len(args_string) > 4096:
                return PolicyViolation(
                    violation_type="ARGUMENTS_TOO_LONG",
                    message="Arguments exceed maximum length",
                    details={'length': len(args_string), 'max': 4096}
                )
            
            return None
            
        except Exception as e:
            return PolicyViolation(
                violation_type="ARGUMENT_VALIDATION_ERROR",
                message=f"Error validating arguments: {str(e)}",
                details={'args': args}
            )
    
    def requires_confirmation(self, risk_level: str) -> bool:
        """Check if a command with given risk level requires confirmation"""
        require_confirm_for = self.config.get('security', {}).get('require_confirmation_for', [])
        return risk_level in require_confirm_for
    
    def is_network_allowed(self) -> bool:
        """Check if network access is allowed"""
        # For now, network access depends on AI backend configuration
        backend = self.config.get('ai', {}).get('backend', 'ollama')
        return backend in ['api', 'openai', 'anthropic']
