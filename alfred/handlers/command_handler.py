"""Command handler for validating and executing whitelisted system commands"""

import subprocess
import os
import time
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from collections import defaultdict
from threading import Lock

from alfred.security.policy import SecurityPolicy, PolicyViolation
from alfred.security.whitelist import CommandWhitelist
from alfred.config.logging import AuditLogger


class RateLimiter:
    """Rate limiter for command execution"""
    def __init__(self, max_requests: int = 10, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(list)
        self.lock = Lock()
    
    def is_allowed(self) -> bool:
        with self.lock:
            now = time.time()
            self.requests['default'] = [
                req_time for req_time in self.requests['default']
                if now - req_time < self.time_window
            ]
            
            if len(self.requests['default']) >= self.max_requests:
                return False
            
            self.requests['default'].append(now)
            return True


@dataclass
class CommandResult:
    """Result of command execution"""
    success: bool
    output: str
    error: str
    return_code: int
    violated_policy: Optional[PolicyViolation] = None
    
    @property
    def status(self) -> str:
        if self.violated_policy:
            return "denied"
        elif self.success:
            return "success"
        else:
            return "failed"


class CommandHandler:
    """
    Validates and executes whitelisted system commands.
    
    SECURITY CRITICAL: This class enforces the boundary between AI suggestions
    and actual system execution. All commands MUST be validated before execution.
    """
    
    def __init__(self, config: Dict[str, Any], audit_logger: AuditLogger):
        self.config = config
        self.audit_logger = audit_logger
        self.policy = SecurityPolicy(config)
        self.whitelist = CommandWhitelist(config)
        self.rate_limiter = RateLimiter(max_requests=10, time_window=60)
        self.active_processes = 0
        self.max_concurrent = 3
        self.process_lock = Lock()
    
    def execute(self, command_name: str, args: List[str], 
                skip_confirmation: bool = False) -> CommandResult:
        """
        Execute a whitelisted command with full security validation.
        
        Args:
            command_name: Name of the command to execute
            args: List of arguments (NOT a single string)
            skip_confirmation: Skip user confirmation (for automated tests only)
            
        Returns:
            CommandResult with execution status
            
        SECURITY NOTE: This method NEVER uses shell=True
        """
        if not self.rate_limiter.is_allowed():
            violation = PolicyViolation(
                violation_type="RATE_LIMITED",
                message="Rate limit exceeded. Please wait before running more commands.",
                details={'command': command_name}
            )
            return CommandResult(
                success=False,
                output="",
                error=violation.message,
                return_code=-1,
                violated_policy=violation
            )
        
        with self.process_lock:
            if self.active_processes >= self.max_concurrent:
                return CommandResult(
                    success=False,
                    output="",
                    error=f"Too many concurrent commands ({self.max_concurrent} max)",
                    return_code=-1
                )
            self.active_processes += 1
        
        try:
            return self._execute_internal(command_name, args, skip_confirmation)
        finally:
            with self.process_lock:
                self.active_processes -= 1
    
    def _execute_internal(self, command_name: str, args: List[str], 
                         skip_confirmation: bool = False) -> CommandResult:
        # Step 1: Check if command is whitelisted
        if not self.whitelist.is_whitelisted(command_name):
            violation = PolicyViolation(
                violation_type="NOT_WHITELISTED",
                message=f"Command '{command_name}' is not in whitelist",
                details={'command': command_name}
            )
            self.audit_logger.log_policy_violation("NOT_WHITELISTED", violation.details)
            return CommandResult(
                success=False,
                output="",
                error=violation.message,
                return_code=-1,
                violated_policy=violation
            )
        
        # Step 2: Get command specification
        spec = self.whitelist.get_command_spec(command_name)
        if not spec:
            return CommandResult(
                success=False,
                output="",
                error="Command specification not found",
                return_code=-1
            )
        
        # Step 3: Validate executable and resolve path atomically (fixes TOCTOU)
        try:
            exec_path = Path(spec.path).resolve(strict=True)
        except FileNotFoundError:
            return CommandResult(
                success=False,
                output="",
                error=f"Executable not found: {spec.path}",
                return_code=-1
            )
        except Exception as e:
            return CommandResult(
                success=False,
                output="",
                error=f"Executable path error: {str(e)}",
                return_code=-1
            )
        
        # Resolve the target before use and ensure the resolved executable still
        # lives under a configured allowed directory.
        allowed_paths = self.config.get('security', {}).get('allowed_command_paths', [])
        if not self.whitelist._is_path_allowed(str(exec_path), allowed_paths):
            return CommandResult(
                success=False,
                output="",
                error="Executable path is outside allowed directories",
                return_code=-1
            )

        # Step 4: Validate arguments against policy
        arg_violation = self.policy.validate_arguments(args, spec.args_pattern)
        if arg_violation:
            self.audit_logger.log_policy_violation("INVALID_ARGUMENTS", arg_violation.details)
            return CommandResult(
                success=False,
                output="",
                error=arg_violation.message,
                return_code=-1,
                violated_policy=arg_violation
            )
        
        # Step 5: Validate command doesn't violate security policy
        cmd_violation = self.policy.validate_command(spec.path, args)
        if cmd_violation:
            self.audit_logger.log_policy_violation("COMMAND_VIOLATION", cmd_violation.details)
            return CommandResult(
                success=False,
                output="",
                error=cmd_violation.message,
                return_code=-1,
                violated_policy=cmd_violation
            )
        
        # Step 6: Check if confirmation is required
        if (spec.confirm or self.policy.requires_confirmation(spec.risk)) and not skip_confirmation:
            if not self._confirm_execution(command_name, args, spec.risk):
                return CommandResult(
                    success=False,
                    output="",
                    error="User cancelled execution",
                    return_code=-1
                )
        
        # Step 7: Execute command safely (NO shell=True)
        try:
            result = subprocess.run(
                [str(exec_path)] + args,  # Explicit argument list
                capture_output=True,
                timeout=30,
                check=False,
                text=True
            )
            
            # Log successful execution
            self.audit_logger.log_command_execution(
                command=command_name,
                args=args,
                result="success" if result.returncode == 0 else "failed"
            )
            
            return CommandResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr,
                return_code=result.returncode
            )
            
        except subprocess.TimeoutExpired:
            self.audit_logger.log_error(
                error_type="TIMEOUT",
                message=f"Command timed out: {command_name}",
                details={'command': command_name, 'args': args}
            )
            return CommandResult(
                success=False,
                output="",
                error="Command execution timed out",
                return_code=-1
            )
        except Exception as e:
            self.audit_logger.log_error(
                error_type="EXECUTION_ERROR",
                message=f"Error executing command: {str(e)}",
                details={'command': command_name, 'args': args, 'error': str(e)}
            )
            return CommandResult(
                success=False,
                output="",
                error=f"Execution error: {str(e)}",
                return_code=-1
            )
    
    def _confirm_execution(self, command: str, args: List[str], risk: str) -> bool:
        """
        Ask user to confirm command execution.
        
        Args:
            command: Command name
            args: Command arguments
            risk: Risk level ('safe', 'warning', 'destructive')
            
        Returns:
            True if user confirms, False otherwise
        """
        risk_colors = {
            'safe': '',
            'warning': '[WARNING] ',
            'destructive': '[DANGEROUS] '
        }
        
        print(f"\n{risk_colors.get(risk, '')}About to execute:")
        print(f"  Command: {command}")
        print(f"  Arguments: {' '.join(args)}")
        print(f"  Risk level: {risk}")
        
        response = input("\nProceed? (yes/no): ").strip().lower()
        return response in ['yes', 'y']
    
    def suggest_command(self, user_query: str) -> str:
        """
        Suggest commands based on user query (does NOT execute).
        
        This is a placeholder for AI integration - the AI handler
        would call this to format command suggestions.
        """
        available = self.whitelist.list_commands()
        return f"Available commands: {', '.join(available)}\n\nTo execute a command, use: /command_name [args]"
