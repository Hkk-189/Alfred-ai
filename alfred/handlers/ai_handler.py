"""AI handler for generating text responses using local or API models"""

import os
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class AIBackend(ABC):
    """Abstract base class for AI backends"""
    
    @abstractmethod
    def generate(self, prompt: str, max_tokens: int = 2000) -> str:
        """Generate a text response from the AI model"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the backend is available"""
        pass


class OllamaBackend(AIBackend):
    """Local Ollama backend (privacy-first default)"""
    
    def __init__(self, model: str = "llama2", timeout: int = 30):
        self.model = model
        self.timeout = timeout
    
    def generate(self, prompt: str, max_tokens: int = 2000) -> str:
        """
        Generate response using local Ollama.
        
        NOTE: This is a placeholder implementation.
        Actual implementation would use requests to call Ollama API at localhost.
        """
        try:
            # Placeholder - would call Ollama API
            # import requests
            # response = requests.post('http://localhost:11434/api/generate', ...)
            
            return (
                "Note: Ollama integration not yet implemented.\n"
                "Install Ollama and uncomment the API call code.\n"
                f"Your query: {prompt[:100]}..."
            )
        except Exception as e:
            return f"Error calling Ollama: {str(e)}"
    
    def is_available(self) -> bool:
        """Check if Ollama is running locally"""
        try:
            # Placeholder - would check if Ollama is running
            # import requests
            # response = requests.get('http://localhost:11434/api/tags', timeout=2)
            # return response.status_code == 200
            return False  # Until implementation is complete
        except:
            return False


class OpenAIBackend(AIBackend):
    """OpenAI API backend (opt-in, requires API key)"""
    
    def __init__(self, api_key_env: str = "OPENAI_API_KEY", 
                 model: str = "gpt-3.5-turbo", timeout: int = 30):
        self.api_key = os.environ.get(api_key_env)
        self.model = model
        self.timeout = timeout
    
    def generate(self, prompt: str, max_tokens: int = 2000) -> str:
        """
        Generate response using OpenAI API.
        
        NOTE: This is a placeholder implementation.
        Actual implementation would use openai library.
        """
        if not self.api_key:
            return "Error: OpenAI API key not found in environment"
        
        try:
            # Placeholder - would call OpenAI API
            # import openai
            # openai.api_key = self.api_key
            # response = openai.ChatCompletion.create(...)
            
            return (
                "Note: OpenAI integration not yet implemented.\n"
                "Set OPENAI_API_KEY environment variable and uncomment the API call code.\n"
                f"Your query: {prompt[:100]}..."
            )
        except Exception as e:
            return f"Error calling OpenAI: {str(e)}"
    
    def is_available(self) -> bool:
        """Check if API key is configured"""
        return self.api_key is not None


class AIHandler:
    """
    Handles AI-powered text generation.
    
    SECURITY NOTE: This handler ONLY generates text.
    It must NEVER:
    - Execute commands
    - Access filesystem
    - Make decisions about system operations
    - Use eval() or exec() on AI output
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.backend = self._create_backend()
    
    def _create_backend(self) -> AIBackend:
        """Create appropriate AI backend based on config"""
        ai_config = self.config.get('ai', {})
        backend_type = ai_config.get('backend', 'ollama')
        model = ai_config.get('model', 'llama2')
        timeout = ai_config.get('timeout', 30)
        
        if backend_type == 'ollama':
            return OllamaBackend(model=model, timeout=timeout)
        elif backend_type in ['openai', 'api']:
            api_key_env = ai_config.get('api_key_env', 'OPENAI_API_KEY')
            return OpenAIBackend(api_key_env=api_key_env, model=model, timeout=timeout)
        else:
            # Default to Ollama for unknown backends
            return OllamaBackend(model=model, timeout=timeout)
    
    def respond(self, user_query: str) -> str:
        """
        Generate a text response to user query.
        
        Args:
            user_query: User's question or request
            
        Returns:
            AI-generated text response
            
        SECURITY: This method only returns text. It does NOT execute
        any commands suggested by the AI model.
        """
        if not self.backend.is_available():
            return self._get_fallback_response(user_query)
        
        try:
            max_tokens = self.config.get('ai', {}).get('max_tokens', 2000)
            
            # Generate response
            response = self.backend.generate(user_query, max_tokens)
            
            # CRITICAL: Do NOT eval(), exec(), or execute any code in the response
            # Just return the text
            return response
            
        except Exception as e:
            return f"Error generating response: {str(e)}"
    
    def _get_fallback_response(self, query: str) -> str:
        """Provide a fallback response when AI backend is unavailable"""
        return (
            "AI backend is currently unavailable.\n\n"
            "To use AI features:\n"
            "1. For local (privacy-first): Install Ollama from https://ollama.ai\n"
            "2. For API (requires internet): Set API key in config and environment\n\n"
            f"Your query was: {query}"
        )
    
    def suggest_command(self, query: str, available_commands: list) -> str:
        """
        Have AI suggest a command based on user query.
        
        Returns:
            Formatted suggestion text (NOT executed)
        """
        prompt = (
            f"User wants to: {query}\n"
            f"Available commands: {', '.join(available_commands)}\n\n"
            "Suggest the most appropriate command and arguments. "
            "Format: /command_name arg1 arg2\n"
            "Only suggest commands from the available list."
        )
        
        suggestion = self.respond(prompt)
        
        # Format the suggestion clearly
        return (
            "AI Suggestion (not executed):\n"
            "─" * 50 + "\n"
            f"{suggestion}\n"
            "─" * 50 + "\n"
            "To execute, type the suggested command or confirm."
        )
