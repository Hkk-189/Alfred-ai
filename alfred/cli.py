"""Main CLI interface for Alfred"""

import shlex
import sys
from pathlib import Path

from alfred.config.manager import ConfigManager
from alfred.config.logging import AuditLogger
from alfred.handlers.router import InputRouter, HandlerType
from alfred.handlers.command_handler import CommandHandler
from alfred.handlers.ai_handler import AIHandler


ERROR_MESSAGES = {
    "NOT_WHITELISTED": "Command not allowed",
    "PATH_TRAVERSAL": "Invalid path specified",
    "INVALID_ARGUMENTS": "Invalid command arguments",
    "EXECUTABLE_NOT_FOUND": "Command not available",
    "BLOCKED_PATTERN": "Command matches blocked pattern",
    "RATE_LIMITED": "Too many requests. Please wait.",
    "COMMAND_VIOLATION": "Command violates security policy",
}


class AlfredCLI:
    """Command-line interface for Alfred AI Assistant"""
    
    def __init__(self):
        # Initialize configuration
        self.config_manager = ConfigManager()
        
        # Initialize logging
        self.audit_logger = AuditLogger(
            log_dir=self.config_manager.log_dir,
            anonymize=self.config_manager.get('privacy.anonymize_logs', True)
        )
        
        # Initialize handlers
        self.router = InputRouter()
        self.command_handler = CommandHandler(
            config=self.config_manager.config,
            audit_logger=self.audit_logger
        )
        self.ai_handler = AIHandler(config=self.config_manager.config)
        
        # Display welcome message
        self._show_welcome()
    
    def _show_welcome(self):
        """Display welcome message"""
        print("=" * 60)
        print("  Alfred - Privacy-first AI Assistant")
        print("=" * 60)
        print()
        print("  AI Backend:", self.config_manager.get('ai.backend', 'ollama'))
        print("  Config Dir:", self.config_manager.config_dir)
        print("  Log Dir:", self.config_manager.log_dir)
        print()
        print("  Type 'help' for commands, 'exit' to quit")
        print("=" * 60)
        print()
    
    def run(self):
        """Main interaction loop"""
        user_input = ""
        while True:
            try:
                # Get user input
                user_input = input("alfred> ").strip()
                
                if not user_input:
                    continue
                
                # Handle special commands
                if user_input.lower() in ['exit', 'quit', 'q']:
                    print("\nGoodbye!")
                    break
                elif user_input.lower() == 'help':
                    self._show_help()
                    continue
                elif user_input.lower() == 'status':
                    self._show_status()
                    continue
                elif user_input.lower() == 'commands':
                    self._list_commands()
                    continue
                
                # Route input to appropriate handler
                self._process_input(user_input)
                
            except KeyboardInterrupt:
                print("\n\nInterrupted. Type 'exit' to quit.")
            except Exception as e:
                print("\nAn error occurred. Check logs for details.")
                self.audit_logger.log_error(
                    error_type="CLI_ERROR",
                    message=str(e),
                    details={'input': user_input}
                )
    
    def _process_input(self, user_input: str):
        """Process user input by routing to appropriate handler"""
        # Route input
        handler_type, cleaned_input = self.router.route(user_input)
        
        if handler_type == HandlerType.COMMAND:
            self._handle_command(cleaned_input)
        elif handler_type == HandlerType.AI:
            self._handle_ai_query(cleaned_input)
        else:
            print("I'm not sure how to handle that input.")
    
    def _handle_command(self, command_input: str):
        """Handle system command execution"""
        # Sanitize input: strip null bytes and normalize line endings
        cleaned_input = command_input.replace('\x00', '').replace('\n', ' ').replace('\r', ' ')

        try:
            parts = shlex.split(cleaned_input)
        except ValueError as e:
            print(f"Invalid command syntax: {e}")
            return

        if not parts:
            print("No command specified")
            return

        command_name = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # Reject any arg containing a null byte
        for arg in args:
            if '\x00' in arg:
                print("Invalid argument: contains null byte")
                return
        
        # Execute command through handler
        result = self.command_handler.execute(command_name, args)
        
        # Display result
        print()
        if result.status == "denied":
            if result.violated_policy:
                safe_msg = ERROR_MESSAGES.get(
                    result.violated_policy.violation_type,
                    "Command cannot be executed"
                )
                print(f"Denied: {safe_msg}")
            else:
                print(f"Denied: {result.error}")
        elif result.status == "success":
            print(f"Command executed successfully")
            if result.output:
                print("\nOutput:")
                print(result.output)
        else:
            print(f"Command failed (exit code: {result.return_code})")
            if result.error:
                print(f"Error: {result.error}")
        print()
    
    def _handle_ai_query(self, query: str):
        """Handle AI-powered query"""
        print("\nGenerating response...\n")
        response = self.ai_handler.respond(query)
        print(response)
        print()
    
    def _show_help(self):
        """Show help information"""
        print()
        print("Alfred Commands:")
        print("-" * 60)
        print("  help            - Show this help message")
        print("  status          - Show system status")
        print("  commands        - List available whitelisted commands")
        print("  exit/quit/q     - Exit Alfred")
        print()
        print("Command Execution:")
        print("  /command args   - Execute whitelisted command")
        print("  command args    - Execute whitelisted command")
        print()
        print("AI Queries:")
        print("  Any question or request without / prefix")
        print("  Example: 'How do I list files?'")
        print()
        print("Security:")
        print("  - Only whitelisted commands can be executed")
        print("  - Dangerous commands require confirmation")
        print("  - All actions are logged")
        print("-" * 60)
        print()
    
    def _show_status(self):
        """Show system status"""
        print()
        print("System Status:")
        print("-" * 60)
        print(f"  Platform: {self.config_manager.platform}")
        print(f"  AI Backend: {self.config_manager.get('ai.backend', 'unknown')}")
        print(f"  AI Model: {self.config_manager.get('ai.model', 'unknown')}")
        print(f"  Store Conversations: {self.config_manager.get('privacy.store_conversations', False)}")
        print(f"  Config Directory: {self.config_manager.config_dir}")
        print(f"  Log Directory: {self.config_manager.log_dir}")
        
        # Check AI backend availability
        if self.ai_handler.backend.is_available():
            print(f"  AI Status: ✓ Available")
        else:
            print(f"  AI Status: ✗ Not Available")
        
        # Count whitelisted commands
        num_commands = len(self.command_handler.whitelist.list_commands())
        print(f"  Whitelisted Commands: {num_commands}")
        print("-" * 60)
        print()
    
    def _list_commands(self):
        """List all whitelisted commands"""
        commands = self.command_handler.whitelist.list_commands()
        
        print()
        print("Available Commands:")
        print("-" * 60)
        
        if not commands:
            print("  No commands configured")
        else:
            for cmd_name in sorted(commands):
                spec = self.command_handler.whitelist.get_command_spec(cmd_name)
                if spec:
                    risk_indicator = {
                        'safe': '[safe]',
                        'warning': '[warning]',
                        'destructive': '[destructive]'
                    }.get(spec.risk, '[unknown]')
                    
                    print(f"  {risk_indicator} {cmd_name}")
                    print(f"      Path: {spec.path}")
                    print(f"      Risk: {spec.risk}")
                    if spec.confirm:
                        print(f"      Requires confirmation")
                    print()
        
        print("-" * 60)
        print()


def main():
    """Main entry point"""
    try:
        cli = AlfredCLI()
        cli.run()
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
