"""Logging and audit functionality for Alfred"""

import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class AuditLogger:
    """Security-focused audit logging"""
    
    def __init__(self, log_dir: Path, anonymize: bool = True):
        self.log_dir = log_dir
        self.anonymize = anonymize
        
        # Setup loggers
        self._setup_loggers()
    
    def _setup_loggers(self):
        """Setup separate loggers for different purposes"""
        
        # Audit logger (security events)
        self.audit_logger = logging.getLogger('alfred.audit')
        self.audit_logger.setLevel(logging.INFO)
        audit_handler = logging.FileHandler(
            self.log_dir / f'audit_{datetime.now().strftime("%Y%m%d")}.log'
        )
        audit_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.audit_logger.addHandler(audit_handler)
        
        # Command logger (all executed commands)
        self.command_logger = logging.getLogger('alfred.commands')
        self.command_logger.setLevel(logging.INFO)
        command_handler = logging.FileHandler(
            self.log_dir / f'commands_{datetime.now().strftime("%Y%m%d")}.log'
        )
        command_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(message)s')
        )
        self.command_logger.addHandler(command_handler)
        
        # Error logger
        self.error_logger = logging.getLogger('alfred.errors')
        self.error_logger.setLevel(logging.ERROR)
        error_handler = logging.FileHandler(
            self.log_dir / f'errors_{datetime.now().strftime("%Y%m%d")}.log'
        )
        error_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.error_logger.addHandler(error_handler)
    
    def _sanitize_for_logging(self, value: Any) -> Any:
        """Sanitize value for safe logging (prevents log injection)"""
        if isinstance(value, str):
            sanitized = value.replace('\n', '\\n').replace('\r', '\\r')
            sanitized = sanitized.replace('\x00', '').replace('\t', '\\t')
            sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\n\r\t')
            if len(sanitized) > 1000:
                sanitized = sanitized[:1000] + '...[truncated]'
            return sanitized
        elif isinstance(value, list):
            return [self._sanitize_for_logging(item) for item in value]
        elif isinstance(value, dict):
            return {k: self._sanitize_for_logging(v) for k, v in value.items()}
        else:
            return self._safe_str(value)
    
    def _safe_str(self, value: Any) -> str:
        """Safely convert value to string for logging"""
        if isinstance(value, str):
            return value[:1000]
        elif isinstance(value, (int, float, bool, type(None))):
            return str(value)
        else:
            return f"<{type(value).__name__}>"
    
    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from log data"""
        if not self.anonymize:
            return self._validate_log_data(data)
        
        sensitive_keys = ['api_key', 'password', 'token', 'secret', 'credential']
        
        sanitized = {}
        for key, value in data.items():
            if not isinstance(key, str):
                key = str(key)[:100]
            
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_data(value)
            elif isinstance(value, (list, tuple)):
                sanitized[key] = [self._safe_str(item) for item in value]
            else:
                sanitized[key] = self._safe_str(value)
        
        return sanitized
    
    def _validate_log_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize log data structure"""
        validated = {}
        for key, value in data.items():
            if not isinstance(key, str):
                key = str(key)[:100]
            
            validated[key] = self._sanitize_for_logging(value)
        
        return validated
    
    def log_command_execution(self, command: str, args: list, result: str, 
                             user: Optional[str] = None):
        """Log a command execution"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'args': args,
            'result': result,
            'user': user or 'default'
        }
        
        sanitized_data = self._sanitize_data(log_data)
        self.command_logger.info(json.dumps(sanitized_data))
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log a security-related event"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details
        }
        
        sanitized_data = self._sanitize_data(log_data)
        self.audit_logger.warning(json.dumps(sanitized_data))
    
    def log_policy_violation(self, violation_type: str, details: Dict[str, Any]):
        """Log a policy violation"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'violation_type': violation_type,
            'details': details
        }
        
        sanitized_data = self._sanitize_data(log_data)
        self.audit_logger.error(json.dumps(sanitized_data))
    
    def log_error(self, error_type: str, message: str, details: Optional[Dict[str, Any]] = None):
        """Log an error"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'error_type': error_type,
            'message': message,
            'details': details or {}
        }
        
        sanitized_data = self._sanitize_data(log_data)
        self.error_logger.error(json.dumps(sanitized_data))
