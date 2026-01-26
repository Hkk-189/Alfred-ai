# Setup Guide for Alfred AI Assistant

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- (Optional) Ollama for local AI - https://ollama.ai

## Installation Steps

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Or install in a virtual environment (recommended):

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Alfred

On first run, Alfred will create a default configuration. You can customize it:

#### Windows
```bash
# Config will be created at: %APPDATA%\alfred\config.yaml
# Logs will be at: %LOCALAPPDATA%\alfred\logs\
```

#### Linux
```bash
# Config will be created at: ~/.config/alfred/config.yaml
# Logs will be at: ~/.local/share/alfred/logs/
```

Copy the example configuration:
```bash
# View the example first
cat config.example.yaml

# Then customize your config after first run
# Edit %APPDATA%\alfred\config.yaml (Windows)
# or ~/.config/alfred/config.yaml (Linux)
```

### 3. Set Up AI Backend

#### Option A: Local AI (Privacy-first, recommended)

1. Install Ollama from https://ollama.ai
2. Pull a model:
   ```bash
   ollama pull llama2
   # or
   ollama pull mistral
   ```
3. Verify it's running:
   ```bash
   ollama list
   ```

Your config should have:
```yaml
ai:
  backend: ollama
  model: llama2
```

#### Option B: API-based AI (requires internet)

1. Get an API key from OpenAI or Anthropic
2. Set environment variable:
   ```bash
   # Windows (PowerShell)
   $env:OPENAI_API_KEY = "your-key-here"
   
   # Linux
   export OPENAI_API_KEY="your-key-here"
   ```
3. Update config:
   ```yaml
   ai:
     backend: api
     api_provider: openai
     api_key_env: OPENAI_API_KEY
   ```

### 4. Configure Whitelisted Commands

Edit your config file to add safe commands:

#### Windows Example
```yaml
commands:
  notepad:
    path: C:\Windows\System32\notepad.exe
    args_pattern: "^[a-zA-Z0-9_\\-\\.\\:\\\\/ ]+$"
    risk: safe
    confirm: false
  
  explorer:
    path: C:\Windows\explorer.exe
    args_pattern: "^[a-zA-Z0-9_\\-\\.\\:\\\\/ ]+$"
    risk: safe
    confirm: false
```

#### Linux Example
```yaml
commands:
  ls:
    path: /usr/bin/ls
    args_pattern: "^[a-zA-Z0-9_\\-\\./~ ]*$"
    risk: safe
    confirm: false
  
  cat:
    path: /usr/bin/cat
    args_pattern: "^[a-zA-Z0-9_\\-\\./~ ]+$"
    risk: safe
    confirm: false
```

### 5. Run Alfred

```bash
python main.py
```

You should see:
```
============================================================
  Alfred - Privacy-first AI Assistant
============================================================

  AI Backend: ollama
  Config Dir: [your config directory]
  Log Dir: [your log directory]

  Type 'help' for commands, 'exit' to quit
============================================================

alfred>
```

## Testing the Installation

### Test 1: Check Status
```
alfred> status
```

Should show system configuration and AI backend status.

### Test 2: List Commands
```
alfred> commands
```

Should show your whitelisted commands.

### Test 3: Execute a Safe Command (if configured)
```
alfred> /ls
```
or
```
alfred> /notepad
```

### Test 4: Ask an AI Question
```
alfred> What is Python?
```

Note: If Ollama is not installed, you'll get a helpful message about setting it up.

## Troubleshooting

### "AI backend is currently unavailable"

- **For Ollama**: Make sure Ollama is running (`ollama list`)
- **For API**: Check your API key is set correctly in environment variables

### "Command not whitelisted"

- Add the command to your config.yaml file
- Restart Alfred

### Config file not found

- Run Alfred once to create the default config
- Then edit it at the location shown in the status output

### Permission denied (Linux)

- Check file permissions on executables
- Make sure paths in config.yaml are correct

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run security tests (IMPORTANT)
pytest tests/test_security.py -v

# Run all tests
pytest tests/ -v
```

All security tests should pass before using Alfred in production.

## Security Checklist

Before running Alfred:

- [ ] Review all whitelisted commands
- [ ] Set appropriate risk levels
- [ ] Enable confirmation for destructive operations
- [ ] Check blocked patterns in security section
- [ ] Review allowed command paths
- [ ] Set up logging retention policy
- [ ] Test with safe commands first

## Next Steps

1. Read [README.md](README.md) for usage guide
2. Read [Context.md](Context.md) for architecture details
3. Customize your whitelist
4. Set up your preferred AI backend
5. Start using Alfred safely!

## Support

- Check [README.md](README.md) for documentation
- Review [Context.md](Context.md) for security principles
- Check logs in your log directory for troubleshooting

---

**Remember**: Alfred is a tool for enhancing productivity, not replacing judgment. Always review commands before confirming execution.
