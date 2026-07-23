"""AI handler for generating text responses using local or cloud models"""

import os
import json
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


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

    DEFAULT_HOST = "http://localhost:11434"

    def __init__(self, model: str = None, timeout: int = 30, host: str = None):
        self.timeout = timeout
        self.host = host or os.environ.get("OLLAMA_HOST", self.DEFAULT_HOST)
        self._model = model

    @property
    def model(self) -> str:
        if self._model:
            available = self._list_models()
            if self._model in available:
                return self._model
            for m in available:
                if m.startswith(self._model + ":") or m.startswith(self._model.replace("-", "").replace("_", "") + ":"):
                    return m
            if available:
                return available[0]
            return self._model
        available = self._list_models()
        if available:
            return available[0]
        return "llama2"

    def _list_models(self) -> list:
        """List available Ollama models"""
        if not REQUESTS_AVAILABLE:
            return []
        try:
            url = f"{self.host}/api/tags"
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                data = response.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            pass
        return []

    def generate(self, prompt: str, max_tokens: int = 2000) -> str:
        """Generate response using local Ollama."""
        if not REQUESTS_AVAILABLE:
            return "Error: requests library not installed"

        try:
            url = f"{self.host}/api/generate"
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "thinking": False
                }
            }
            response = requests.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "No response from model")
        except requests.exceptions.ConnectionError:
            return "Error: Cannot connect to Ollama. Is Ollama running?"
        except requests.exceptions.Timeout:
            return "Error: Ollama request timed out"
        except requests.exceptions.HTTPError as e:
            return f"Error: Ollama HTTP error: {e}"
        except json.JSONDecodeError:
            return "Error: Invalid response from Ollama"
        except Exception as e:
            return f"Error calling Ollama: {str(e)}"

    def is_available(self) -> bool:
        """Check if Ollama is running locally"""
        if not REQUESTS_AVAILABLE:
            return False

        try:
            url = f"{self.host}/api/tags"
            response = requests.get(url, timeout=2)
            return response.status_code == 200
        except Exception:
            return False


class OllamaCloudBackend(AIBackend):
    """Ollama Cloud API backend (requires API key)"""

    DEFAULT_BASE_URL = "https://api.ollama.com/v1"

    def __init__(self, api_key_env: str = "OLLAMA_CLOUD_API_KEY",
                 model: str = "llama2", timeout: int = 30, base_url: str = None):
        self.api_key = os.environ.get(api_key_env)
        self.model = model
        self.timeout = timeout
        self.base_url = base_url or os.environ.get("OLLAMA_BASE_URL", self.DEFAULT_BASE_URL)

    def generate(self, prompt: str, max_tokens: int = 2000) -> str:
        """Generate response using Ollama Cloud API."""
        if not self.api_key:
            return "Error: Ollama Cloud API key not found in environment"

        if not REQUESTS_AVAILABLE:
            return "Error: requests library not installed"

        try:
            url = f"{self.base_url}/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens
            }
            response = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "No response from model")
            return "No response from model"
        except requests.exceptions.ConnectionError:
            return "Error: Cannot connect to Ollama Cloud API"
        except requests.exceptions.Timeout:
            return "Error: Ollama Cloud API request timed out"
        except requests.exceptions.HTTPError as e:
            return f"Error: Ollama Cloud API error: {e}"
        except json.JSONDecodeError:
            return "Error: Invalid response from Ollama Cloud API"
        except Exception as e:
            return f"Error calling Ollama Cloud API: {str(e)}"

    def is_available(self) -> bool:
        """Check if API key is configured"""
        return self.api_key is not None and REQUESTS_AVAILABLE


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
        model = ai_config.get('model')
        timeout = ai_config.get('timeout', 30)

        if backend_type == 'ollama':
            return OllamaBackend(model=model, timeout=timeout)
        elif backend_type == 'ollama_cloud':
            api_key_env = ai_config.get('api_key_env', 'OLLAMA_CLOUD_API_KEY')
            return OllamaCloudBackend(api_key_env=api_key_env, model=model, timeout=timeout)
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
