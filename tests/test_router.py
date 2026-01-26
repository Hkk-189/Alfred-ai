"""Test input routing"""

import pytest
from alfred.handlers.router import InputRouter, HandlerType


class TestInputRouter:
    """Test the input router"""
    
    def setup_method(self):
        """Setup router"""
        self.router = InputRouter()
    
    def test_command_patterns(self):
        """Test command pattern detection"""
        command_inputs = [
            "/open firefox",
            "run ls -la",
            "execute notepad",
            "ls /home",
            "cd /tmp",
        ]
        
        for input_str in command_inputs:
            handler_type, _ = self.router.route(input_str)
            assert handler_type == HandlerType.COMMAND, f"Failed to detect command: {input_str}"
    
    def test_ai_patterns(self):
        """Test AI query pattern detection"""
        ai_inputs = [
            "What is the meaning of life?",
            "How do I use git?",
            "Explain quantum computing",
            "Tell me about Python",
            "Why is the sky blue?",
        ]
        
        for input_str in ai_inputs:
            handler_type, _ = self.router.route(input_str)
            assert handler_type == HandlerType.AI, f"Failed to detect AI query: {input_str}"
    
    def test_empty_input(self):
        """Test empty input handling"""
        handler_type, cleaned = self.router.route("")
        assert handler_type == HandlerType.UNKNOWN
        assert cleaned == ""
    
    def test_ambiguous_defaults_to_ai(self):
        """Test that ambiguous input defaults to AI (fail-safe)"""
        ambiguous_inputs = [
            "hello",
            "test",
            "something",
        ]
        
        for input_str in ambiguous_inputs:
            handler_type, _ = self.router.route(input_str)
            # Should default to AI for safety
            assert handler_type == HandlerType.AI
    
    def test_command_cleaning(self):
        """Test command input cleaning"""
        handler_type, cleaned = self.router.route("/open firefox")
        assert handler_type == HandlerType.COMMAND
        assert cleaned == "open firefox"  # Slash removed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
