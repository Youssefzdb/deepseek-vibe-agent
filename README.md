# DeepSeek Vibe Agent

A complete Python CLI tool for interacting with [chat.deepseek.com](https://chat.deepseek.com)'s private API. Features automatic login, Proof-of-Work solving, session persistence, streaming chat, and a **ReAct agent** that can write files, run commands, and more.

## Features

- 🧠 **Full DeepSeek API client** — login, session management, PoW, SSE streaming
- 🔄 **Session persistence** — tokens cached in `.session.json`, no re-login
- 🛠️ **ReAct agent** — AI can write files, read files, edit files, run shell commands
- 🌐 **Tor support** — `--tor` flag for rate-limit avoidance via circuit rotation
- 📜 **Streaming mode** — real-time token-by-token output with `--stream`
- 💬 **Interactive mode** — full chat loop with commands

## Quick Start

```bash
pip install -r requirements.txt

# Interactive mode
python deepseek_vibe.py

# Single message
python deepseek_vibe.py "Create a React Button component"

# With Tor proxy
python deepseek_vibe.py --tor "Write a Python HTTP server"

# Streaming
python deepseek_vibe.py --stream "Explain quantum computing"

# Custom model
python deepseek_vibe.py --model deepseek-r1 "Write a binary search in Rust"
```

## Interactive Commands

| Command | Description |
|---------|-------------|
| `/exit` | Quit |
| `/clear` | Clear conversation history |
| `/session` | Show current session ID |
| `/tools` | List available agent tools |
| `/model <name>` | Switch model (deepseek-v3, deepseek-r1, etc.) |

## Agent Tools

When the AI decides to use a tool, it outputs:
```
TOOL: {"name":"write_file","args":{"path":"hello.py","content":"print('hi')"}}
```

Available tools:
- **write_file**(path, content) — create/overwrite file
- **read_file**(path) — read file content
- **edit_file**(path, old, new) — find and replace
- **delete_file**(path) — delete file
- **list_dir**(path="") — list directory
- **exec**(command) — run shell command
- **glob**(pattern) — find files

## How It Works

1. **Login** via `POST /api/v0/users/login` with email/password
2. **Create session** via `POST /api/v0/chat_session/create`
3. **PoW** — solves `DeepSeekHashV1` challenge (Keccak-based) for each request
4. **Chat** — sends messages with SSE streaming, parses response fragments
5. **ReAct loop** — detects tool calls in AI output, executes them, returns result

## Files

- `deepseek_vibe.py` — Main script (standalone)
- `deepseek_hash.c` — C source for fast PoW solving (auto-compiled)
- `requirements.txt` — Python deps

## Credentials

Default credentials are configured in the script. Change via `--email` and `--password` flags or edit the defaults in `main()`.
