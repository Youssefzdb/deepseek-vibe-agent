# DeepSeek Vibe Agent

Unofficial Python CLI for [chat.deepseek.com](https://chat.deepseek.com) — login, PoW, streaming chat, and a ReAct agent with file/command tools.

## Quick Start

```bash
pip install requests

# Set credentials (any method works)
export DEEPSEEK_EMAIL="your@email.com"
export DEEPSEEK_PASSWORD="your_password"

# Or create config.json: {"email":"...", "password":"..."}
python deepseek_vibe.py --config config.json

# Interactive mode
python deepseek_vibe.py

# Single message
python deepseek_vibe.py "Write a Python HTTP server"

# With Tor (bypass rate limits)
python deepseek_vibe.py --tor "Create a React component"

# Streaming output
python deepseek_vibe.py --stream "Explain recursion"
```

## Interactive Commands

| Command | Description |
|---------|-------------|
| `/exit` | Quit |
| `/clear` | Clear history |
| `/model <name>` | Switch model |
| `/tools` | List agent tools |
| `/help` | Show commands |

## Agent Tools

The AI can write files, run commands, etc. It outputs tool calls as:
```
TOOL: {"name":"write_file","args":{"path":"hello.py","content":"print('hi')"}}
```

Tools: write_file, read_file, edit_file, delete_file, list_dir, exec, glob

## How It Works

1. Login via DeepSeek's private API (`/api/v0/users/login`)
2. Create chat session
3. Solve Proof-of-Work (DeepSeekHashV1 — Keccak-based)
4. Stream SSE chat completions
5. ReAct loop: parse AI tool calls → execute → return

The C source for PoW (`deepseek_hash.c`) auto-compiles to `.so` for speed. Without a C compiler, it falls back to pure Python (slower).

## Files

- `deepseek_vibe.py` — Main standalone script
- `deepseek_hash.c` — PoW solver (auto-compiled)
- `requirements.txt` — Python deps
