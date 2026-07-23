# Alfred - Privacy-first AI Assistant

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Status](https://img.shields.io/badge/status-alpha-orange.svg)

**Alfred** is a security-first AI assistant that combines the convenience of AI-powered text processing with the safety of deterministic system control.

## 🔒 Core Principle

> **AI models are TEXT GENERATORS ONLY**
> 
> Alfred maintains strict separation between AI intelligence and system execution:
> - AI generates suggestions
> - Humans make decisions  
> - Deterministic code executes actions

## ✨ Features

- **Privacy-First**: Local AI by default (Ollama), optional API models
- **Security-Focused**: Whitelisted commands, no shell injection, policy enforcement
- **Cross-Platform**: Works on Linux and Windows
- **Auditable**: All actions logged, no hidden telemetry
- **User Control**: Explicit confirmation for risky operations

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Hkk-189/Alfred-ai.git
cd alfred-ai

# Install dependencies
pip install -r requirements.txt

# Run Alfred
python main.py
```

### First Run

On first run, Alfred creates its configuration:

- **Linux**: `~/.config/alfred/`
- **Windows**: `%APPDATA%\alfred\`

### Configuration

Copy the example configuration:

```bash
cp config.example.yaml ~/.config/alfred/config.yaml
```

Edit the configuration to:
- Add whitelisted commands
- Configure AI backend (Ollama or API)
- Set security policies

## 📋 Usage

### Interactive Mode

```bash
python main.py
```

### Commands

```bash
alfred> help                    # Show help
alfred> status                  # Show system status
alfred> commands                # List whitelisted commands
alfred> /ls -la                 # Execute command
alfred> What is Python?         # AI query
alfred> exit                    # Quit
```

### Command Execution

Commands must be whitelisted in the configuration:

```yaml
commands:
  ls:
    path: /usr/bin/ls
    args_pattern: "^[a-zA-Z0-9_\\-\\./~ ]*$"
    risk: safe
    confirm: false
```

### AI Queries

Ask questions naturally:

```
alfred> How do I list files in a directory?
```

Alfred uses local AI (Ollama) by default - no internet required.

## 🔐 Security Features

### No Shell Injection

- **NEVER** uses `shell=True`
- All commands use explicit argument lists
- Input validation on all parameters

### Command Whitelisting

- Only pre-approved commands can execute
- Regex validation for arguments
- Risk levels: safe, warning, destructive

### Policy Enforcement

- Path traversal prevention (Unicode normalization + URL decoding)
- Blocked patterns (e.g., `rm -rf`)
- Argument length limits
- Confirmation for risky operations
- Rate limiting (10 requests per 60 seconds)
- Concurrent process limits (3 max)
- Config integrity verification (SHA-256 hash)
- Dangerous executable blocking (python, bash, curl, etc.)
- ReDoS protection for regex patterns

### Audit Logging

- All command executions logged
- Security events tracked
- Sensitive data redacted
- Configurable retention

## 🛠️ Architecture

```
┌─────────────────────────────────────┐
│         USER INPUT                  │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│    DETERMINISTIC ROUTER             │
│    • Intent classification          │
│    • Input validation               │
└──────────────┬──────────────────────┘
               ↓
       ┌───────┴───────┐
       ↓               ↓
┌────────────┐  ┌──────────────┐
│ AI HANDLER │  │  COMMAND     │
│            │  │  HANDLER     │
│ • Generate │  │  • Whitelist │
│   text     │  │  • Validate  │
│ • Suggest  │  │  • Execute   │
└────────────┘  └──────────────┘
```

## 📦 Project Structure

```
alfred-ai/
├── alfred/
│   ├── __init__.py
│   ├── cli.py                 # CLI interface
│   ├── config/
│   │   ├── manager.py         # Configuration management
│   │   └── logging.py         # Audit logging
│   ├── handlers/
│   │   ├── router.py          # Input routing
│   │   ├── ai_handler.py      # AI text generation
│   │   └── command_handler.py # Command execution
│   └── security/
│       ├── policy.py          # Policy enforcement
│       └── whitelist.py       # Command whitelisting
├── tests/
│   ├── test_security.py       # Security tests
│   └── test_router.py         # Router tests
├── config.example.yaml        # Example configuration
├── requirements.txt           # Dependencies
├── pyproject.toml            # Project metadata
└── README.md                 # This file
```

## 🧪 Testing

Run security tests:

```bash
pip install pytest pytest-cov
pytest tests/test_security.py -v
```

Critical security tests:
- ✅ No shell injection
- ✅ Path traversal prevention
- ✅ Whitelist enforcement
- ✅ No arbitrary code execution
- ✅ Rate limiting
- ✅ Input sanitization
- ✅ Per-argument validation
- ✅ ReDoS protection

## 🔧 Configuration

### AI Backends

**Local (Default - Privacy-first)**
```yaml
ai:
  backend: ollama
  model: llama2
```

**API (Opt-in)**
```yaml
ai:
  backend: api
  api_provider: openai
  api_key_env: OPENAI_API_KEY
```

### Security Policies

```yaml
security:
  require_confirmation_for:
    - destructive
    - network
  blocked_patterns:
    - ".*rm.*-rf.*"
    - ".*sudo.*"
```

### Privacy Settings

```yaml
privacy:
  store_conversations: false
  log_retention_days: 30
  anonymize_logs: true
```

## 🚫 Non-Goals

Alfred is **NOT**:
- ❌ An autonomous agent
- ❌ A plugin ecosystem
- ❌ A background service
- ❌ A cloud-synced tool
- ❌ A self-updating system

## 📝 Development

### Code Review Checklist

Before merging any code:

- [ ] No `shell=True` anywhere
- [ ] All user input is validated
- [ ] Commands are whitelisted
- [ ] Paths are sanitized
- [ ] No `eval()`/`exec()` of AI output
- [ ] Credentials are protected
- [ ] Errors fail safely
- [ ] Logging doesn't expose secrets

### Contributing

1. Read [Context.md](Context.md) for architecture details
2. Follow security guidelines strictly
3. Add tests for all security-critical code
4. Update documentation

## 📄 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- Inspired by Alfred launcher for macOS
- Built with security principles from OpenBSD and security.txt
- Follows principle of least privilege

## ⚠️ Disclaimer

This is alpha software. Review all whitelisted commands carefully. The developers are not responsible for any damage caused by misconfiguration or misuse.

## 🔗 Links

- **Documentation**: See [Context.md](Context.md) for detailed architecture
- **Issues**: Report bugs via GitHub issues
- **Security**: Report security issues privately to maintainers

---

**Remember**: Alfred is a tool for enhancing human productivity, not replacing human judgment.

