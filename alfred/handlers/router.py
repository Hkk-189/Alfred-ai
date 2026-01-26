"""Input router for classifying user intent and routing to appropriate handler"""

import re
from enum import Enum
from typing import Tuple, Optional


class HandlerType(Enum):
    """Types of handlers available"""
    AI = "ai"
    COMMAND = "command"
    UNKNOWN = "unknown"


class InputRouter:
    """Routes user input to appropriate handler WITHOUT executing anything"""
    
    # Patterns that indicate command intent
    COMMAND_PATTERNS = [
        r'^/\w+',  # Starts with slash (e.g., /open, /run)
        r'^(run|execute|launch|start|open|kill|stop)\s+',  # Command verbs
        r'^(ls|cd|pwd|cat|grep|find|ps|top|kill)',  # Unix commands
        r'^(dir|cd|type|find|tasklist|taskkill)',  # Windows commands
    ]
    
    # Patterns that indicate AI query intent
    AI_PATTERNS = [
        r'^(what|how|why|when|where|who|explain|tell me|help)',
        r'\?$',  # Ends with question mark
    ]
    
    def __init__(self):
        # Compile patterns for efficiency
        self.command_regex = [re.compile(pattern, re.IGNORECASE) 
                             for pattern in self.COMMAND_PATTERNS]
        self.ai_regex = [re.compile(pattern, re.IGNORECASE) 
                        for pattern in self.AI_PATTERNS]
    
    def route(self, user_input: str) -> Tuple[HandlerType, str]:
        """
        Route input to appropriate handler.
        
        Returns:
            Tuple of (handler_type, cleaned_input)
            
        Security note: This function ONLY classifies intent.
        It does NOT execute anything.
        """
        if not user_input or not user_input.strip():
            return HandlerType.UNKNOWN, ""
        
        cleaned_input = user_input.strip()
        
        # Check for explicit command indicators
        if self._matches_command_pattern(cleaned_input):
            return HandlerType.COMMAND, self._clean_command_input(cleaned_input)
        
        # Check for explicit AI query indicators
        if self._matches_ai_pattern(cleaned_input):
            return HandlerType.AI, cleaned_input
        
        # Default to AI for ambiguous input (fail-safe approach)
        return HandlerType.AI, cleaned_input
    
    def _matches_command_pattern(self, input_str: str) -> bool:
        """Check if input matches command patterns"""
        return any(regex.match(input_str) for regex in self.command_regex)
    
    def _matches_ai_pattern(self, input_str: str) -> bool:
        """Check if input matches AI query patterns"""
        return any(regex.match(input_str) for regex in self.ai_regex)
    
    def _clean_command_input(self, input_str: str) -> str:
        """Clean command input by removing prefix markers"""
        # Remove leading slash if present
        if input_str.startswith('/'):
            return input_str[1:].strip()
        return input_str
    
    def get_handler_suggestion(self, user_input: str) -> str:
        """Get a human-readable suggestion for what handler will be used"""
        handler_type, _ = self.route(user_input)
        
        if handler_type == HandlerType.COMMAND:
            return "This looks like a system command. I'll validate and execute it if allowed."
        elif handler_type == HandlerType.AI:
            return "This looks like a query. I'll use the AI model to respond."
        else:
            return "I'm not sure how to handle this input."
