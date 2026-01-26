# Alfred-style Private AI Assistant

## Project Identity

**Name:** Alfred (Private AI Assistant)  
**Type:** Launcher + AI Assistant (NOT an autonomous agent)  
**Target Platforms:** Linux (Arch/Wayland/Hyprland), Windows  
**Primary Use Case:** Privacy-first AI assistance with deterministic system control  
**Status:** In Development

---

## Executive Summary

Alfred is a **security-first AI assistant** that combines the convenience of AI-powered text processing with the safety of deterministic system commands. It runs locally by default, supports optional API models, and maintains strict boundaries between AI intelligence and system control.

**Core Principle:** AI generates suggestions; humans make decisions; deterministic code executes actions.

---

## Critical Architecture Rules

### The Golden Rule

> **AI models are TEXT GENERATORS ONLY**
> 
> They may NEVER:
> - Execute commands
> - Decide permissions
> - Access the filesystem
> - Open network connections
> - Modify system state
> - Control the shell

### Enforcement Architecture

```
┌─────────────────────────────────────────────────┐
│              USER INPUT                         │
└────────────────┬────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────┐
│      DETERMINISTIC ROUTER                       │
│  • Intent classification                        │
│  • Input validation                             │
│  • Route to handler                             │
└────────────────┬────────────────────────────────┘
                 ↓
        ┌────────┴────────┐
        ↓                 ↓
┌──────────────┐  ┌──────────────────┐
│  AI HANDLER  │  │  COMMAND HANDLER │
│              │  │                  │
│ • Generate   │  │ • Whitelist      │
│   text       │  │   check          │
│ • Suggest    │  │ • Argument       │
│   actions    │  │   validation     │
│ • Explain    │  │ • Policy         │
│              │  │   enforcement    │
└──────────────┘  └────────┬─────────┘
                           ↓
                  ┌─────────────────┐
                  │ CONFIRMATION?   │
                  │ (if needed)     │
                  └────────┬────────┘
                           ↓
                  ┌─────────────────┐
                  │ SAFE EXECUTOR   │
                  │ • No shell      │
                  │ • Logged        │
                  │ • Isolated      │
                  └─────────────────┘
```

---

## Component Specifications

### 1. Input Router

**Responsibility:** Classify user intent and route to appropriate handler

**Must Do:**
- Parse input safely
- Detect command vs query intent
- Route to AI or command handler
- Never pass raw input to shell

**Must NOT Do:**
- Execute anything
- Make permission decisions
- Modify system state

**Implementation Requirements:**
- Pure Python function
- No AI model calls
- Pattern matching or simple heuristics
- Fail-safe defaults (when unsure → treat as AI query)

---

### 2. AI Handler

**Responsibility:** Generate text responses using local or API models

**Supported Backends:**

**Local (Default):**
- Provider: Ollama
- Models: llama2, mistral, codellama, etc.
- Acceleration: CUDA (NVIDIA GPU)
- Network: None required
- Telemetry: None
- Cost: Free

**API (Opt-in):**
- Providers: OpenAI, Anthropic, etc.
- Authentication: User-provided API keys
- Storage: Local config file (XDG_CONFIG_HOME)
- Network: Only when enabled
- Telemetry: Provider-dependent
- Cost: User's responsibility

**Must Do:**
- Generate helpful text responses
- Suggest commands (formatted clearly)
- Explain system concepts
- Respect context window limits

**Must NOT Do:**
- Execute suggested commands
- Access filesystem
- Make network requests (except to AI provider)
- Store conversation history (unless explicitly enabled)

**Implementation Requirements:**
- Backend-agnostic interface
- Graceful fallback if model unavailable
- Clear error messages
- Timeout handling
- No eval() or exec() of AI output

---

### 3. Command Handler

**Responsibility:** Validate and execute whitelisted system commands

**Whitelist System:**
- Commands stored in human-readable config (YAML/TOML)
- Each command has:
  - Executable path
  - Allowed arguments (regex patterns)
  - Risk level (safe/warning/destructive)
  - Confirmation required (bool)

**Example Whitelist Entry:**
```yaml
commands:
  open_browser:
    executable: /usr/bin/firefox
    args_pattern: "^https?://.*$"
    risk: safe
    confirm: false
  
  delete_file:
    executable: /usr/bin/rm
    args_pattern: "^/home/user/.*$"
    risk: destructive
    confirm: true
    blocked_patterns:
      - ".*-rf.*"
      - ".*/\\..*"  # hidden files
```

**Must Do:**
- Check whitelist before execution
- Validate all arguments
- Use subprocess with explicit args (NO shell=True)
- Log all executions
- Require confirmation for risky operations
- Sanitize paths and prevent traversal

**Must NOT Do:**
- Trust AI model output
- Use shell interpretation
- Execute unknown commands
- Skip validation for "trusted" input

**Implementation Requirements:**
- Subprocess with explicit argument lists
- Path sanitization (os.path.realpath, checks for ..)
- Argument validation (regex + length limits)
- Confirmation UI for destructive ops
- Execution logging (timestamp, command, user, result)

---

### 4. Policy Layer

**Responsibility:** Enforce security boundaries and user preferences

**Policy Types:**

**Security Policies (Hard-coded):**
- No shell=True ever
- No arbitrary code execution
- No self-modification
- No credential logging
- No automatic software installation

**User Policies (Configurable):**
- Allowed commands whitelist
- Confirmation requirements
- API model enablement
- Conversation storage
- Log retention

**Must Do:**
- Block violations immediately
- Log policy denials
- Provide clear denial messages
- Allow user override (for user policies only)

**Must NOT Do:**
- Allow security policy overrides
- Make assumptions
- Hide policy violations

---

## Security Constraints

### Mandatory Requirements

**1. No Shell Execution**
```python
# ✅ CORRECT
subprocess.run(["/usr/bin/ls", "-l", "/home/user"], check=True)

# ❌ WRONG
subprocess.run("ls -l /home/user", shell=True)
subprocess.run(f"ls -l {user_input}", shell=True)
os.system(command)
```

**2. Input Sanitization**
```python
# ✅ CORRECT
import os.path
path = os.path.realpath(user_path)
if not path.startswith("/home/user/"):
    raise SecurityError("Path outside allowed directory")

# ❌ WRONG
subprocess.run(["/usr/bin/cat", user_input])  # No validation
```

**3. No Dynamic Code Execution**
```python
# ❌ WRONG
eval(ai_response)
exec(suggested_code)
__import__(ai_suggested_module)
```

**4. Credential Protection**
```python
# ✅ CORRECT
- Store API keys in config with restricted permissions (0600)
- Never log API keys
- Never commit keys to git (.gitignore)
- Use environment variables or keyring

# ❌ WRONG
- Hard-coded keys
- Keys in logs
- Keys in error messages
```

---

## Data Handling

### Storage Locations

**Config:**
- Linux: `~/.config/alfred/`
- Windows: `%APPDATA%\alfred\`

**Logs:**
- Linux: `~/.local/share/alfred/logs/`
- Windows: `%LOCALAPPDATA%\alfred\logs\`

**Cache:**
- Linux: `~/.cache/alfred/`
- Windows: `%TEMP%\alfred\`

### Privacy Rules

**Default Behavior:**
- ✅ Store: config, whitelist, logs
- ❌ Store: conversations, user queries, AI responses

**Opt-in Storage:**
- User must explicitly enable conversation history
- Clear retention policy (auto-delete after N days)
- Easy export and deletion

**Network Communication:**
- None required for local models
- API models: only to provider endpoints
- No telemetry, analytics, or crash reporting
- User controls all outbound connections

---

## Development Rules for AI Coding Agents

### When Writing Code

**ALWAYS:**
- Use explicit argument lists with subprocess
- Validate all user input
- Check whitelists before execution
- Separate AI logic from execution logic
- Write pure functions when possible
- Log security-relevant actions
- Fail safely (deny by default)

**NEVER:**
- Use shell=True
- Trust AI model output for execution
- Execute arbitrary code from strings
- Skip input validation
- Hard-code credentials
- Assume user intent
- Mix routing and execution logic

### Code Review Checklist

Before accepting any code change, verify:

- [ ] No shell=True anywhere
- [ ] All user input is validated
- [ ] Commands are whitelisted
- [ ] Paths are sanitized
- [ ] No eval/exec of AI output
- [ ] Credentials are protected
- [ ] Errors fail safely
- [ ] Logging doesn't expose secrets
- [ ] Separation of concerns maintained
- [ ] Dependencies are minimal and justified

---

## Architecture Patterns

### Pattern 1: Intent Detection

```python
def route_input(user_input: str) -> Handler:
    """Route input to appropriate handler WITHOUT executing anything"""
    if user_input.startswith('/'):
        return CommandHandler
    elif looks_like_system_command(user_input):
        return CommandHandler
    else:
        return AIHandler
```

### Pattern 2: Command Suggestion

```python
def ai_suggest_command(query: str) -> str:
    """AI suggests but NEVER executes"""
    response = ai_model.generate(query)
    # Return text suggestion only
    return f"Suggested command: {response}\n\nRun this? (y/n)"
```

### Pattern 3: Safe Execution

```python
def execute_command(cmd: Command) -> Result:
    """Execute only if whitelisted and validated"""
    if not whitelist.contains(cmd):
        raise SecurityError("Command not whitelisted")
    
    if not validate_args(cmd.args):
        raise ValidationError("Invalid arguments")
    
    if cmd.requires_confirmation and not confirm():
        return Result.cancelled()
    
    # Execute WITHOUT shell
    result = subprocess.run(
        [cmd.executable] + cmd.args,
        capture_output=True,
        timeout=30,
        check=False
    )
    
    log_execution(cmd, result)
    return result
```

---

## Non-Goals (What NOT to Build)

**Do NOT implement:**

- ❌ Autonomous decision-making
- ❌ Self-updating code
- ❌ Plugin ecosystem
- ❌ Web scraping or crawling
- ❌ Background services or daemons
- ❌ Cloud sync or backup
- ❌ Social features or sharing
- ❌ Automatic software installation
- ❌ File watching or monitoring
- ❌ Scheduled tasks or cron jobs

If a feature requires any of the above, it's out of scope.

---

## Development Phases

### Phase 1: Foundation
- Input router
- Config management
- Local AI integration (Ollama)
- Basic command whitelist
- CLI interface

### Phase 2: Security
- Argument validation
- Path sanitization
- Confirmation dialogs
- Audit logging
- Policy enforcement

### Phase 3: AI Enhancement
- API model support
- Context management
- Command suggestion formatting
- Error explanation

### Phase 4: Polish
- UI improvements
- Documentation
- Example configs
- Testing
- Performance optimization

---

## Testing Requirements

### Security Tests (Critical)

```python
def test_no_shell_injection():
    """Verify shell injection is impossible"""
    malicious_inputs = [
        "file.txt; rm -rf /",
        "file.txt && evil.sh",
        "`cat /etc/passwd`",
        "$(malicious)",
    ]
    for input in malicious_inputs:
        result = execute_command(input)
        assert result.denied or result.escaped_safely

def test_path_traversal():
    """Verify path traversal is blocked"""
    malicious_paths = [
        "../../../etc/passwd",
        "/etc/shadow",
        "~/.ssh/id_rsa",
    ]
    for path in malicious_paths:
        assert not is_path_allowed(path)

def test_whitelist_enforcement():
    """Verify only whitelisted commands run"""
    result = execute_command("/bin/unknown_command")
    assert result.status == "denied"
```

---

## Configuration Example

```yaml
# ~/.config/alfred/config.yaml

ai:
  backend: ollama  # or 'api'
  model: llama2
  api_provider: null  # or 'openai', 'anthropic'
  api_key_env: OPENAI_API_KEY  # never store key directly

security:
  require_confirmation_for:
    - destructive
    - network
  allowed_command_paths:
    - /usr/bin
    - /usr/local/bin
  blocked_patterns:
    - ".*rm.*-rf.*"
    - ".*sudo.*"

privacy:
  store_conversations: false
  log_retention_days: 30
  anonymize_logs: true

commands:
  firefox:
    path: /usr/bin/firefox
    args_pattern: "^https?://.*$"
    risk: safe
  
  systemctl:
    path: /usr/bin/systemctl
    args_pattern: "^(start|stop|restart) [a-z0-9-]+$"
    risk: warning
    confirm: true
```

---

## Key Takeaways for AI Agents

When developing this project:

1. **Think like a paranoid sysadmin**, not a helpful assistant
2. **Default to denial** when uncertain
3. **Separate intelligence from control** (AI suggests, code decides)
4. **Validate everything** from users and AI models
5. **Never use shell=True**, ever, for any reason
6. **Make security violations obvious** in code reviews
7. **Keep the AI model isolated** from system APIs
8. **Prefer explicit over implicit** in all decisions
9. **Make auditability a feature**, not an afterthought
10. **User control beats convenience** every single time

This is not a framework for building agents. This is a tool for safely enhancing human productivity with AI assistance.