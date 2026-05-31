#!/usr/bin/env python3
"""
DeepSeek Vibe Agent — complete CLI tool for chat.deepseek.com
Includes login, PoW, streaming chat, and a ReAct agent loop (write_file, exec, etc.)
"""
import json, os, sys, time, uuid, base64, subprocess, socket, re, glob as gb, io
from pathlib import Path

BASE_URL = "https://chat.deepseek.com"
APM_TOKEN = "772f2fcc08224a50b0134f8d3c139a21"

# ── PoW: try C lib, fall back to pure Python ──────────────────────────

HASH_C_SRC = Path(__file__).parent / "deepseek_hash.c"
HASH_SO = Path(__file__).parent / "deepseek_hash.so"

def _build_hash_lib():
    """Compile the C hash library on demand."""
    if HASH_SO.exists():
        return str(HASH_SO)
    if not HASH_C_SRC.exists():
        return None
    try:
        subprocess.run(
            ["cc", "-O3", "-shared", "-fPIC", "-o", str(HASH_SO), str(HASH_C_SRC), "-lcrypto"],
            capture_output=True, timeout=30
        )
        if HASH_SO.exists():
            return str(HASH_SO)
    except Exception:
        pass
    return None

class PoWSolver:
    """Proof-of-Work solver using DeepSeekHashV1 (Keccak-based)."""
    def __init__(self):
        lib_path = _build_hash_lib()
        if lib_path:
            import ctypes
            self.lib = ctypes.CDLL(lib_path)
            self.lib.solve_pow.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_double, ctypes.POINTER(ctypes.c_double)]
            self.lib.solve_pow.restype = ctypes.c_int
            self.mode = "c"
        else:
            self.mode = "py"
            print("  [No C lib — using pure Python PoW (slow)]", file=sys.stderr)

    def solve(self, challenge_hex, prefix, difficulty):
        if self.mode == "c":
            return self._solve_c(challenge_hex, prefix, difficulty)
        return self._solve_py(challenge_hex, prefix, difficulty)

    def _solve_c(self, challenge_hex, prefix, difficulty):
        import ctypes
        ans = ctypes.c_double()
        r = self.lib.solve_pow(challenge_hex.encode(), prefix.encode(), float(difficulty), ctypes.byref(ans))
        if r == 1:
            return int(ans.value)
        raise ValueError("PoW not found (C)")

    def _solve_py(self, challenge_hex, prefix, difficulty):
        chal_bytes = bytes.fromhex(challenge_hex)
        for nonce in range(int(difficulty)):
            full = prefix + str(nonce)
            h = self._hash(full.encode())
            if h == chal_bytes:
                return nonce
        raise ValueError("PoW not found (Python)")

    @staticmethod
    def _hash(data):
        """Pure Python DeepSeekHashV1 (Keccak-136/32, skipping first round)."""
        PLEN, OLEN = 136, 32
        RC = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
            0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        ]
        ROT = lambda x, n: ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

        state = [0] * 25
        off = 0
        while off + PLEN <= len(data):
            for i in range(PLEN // 8):
                v = int.from_bytes(data[off + i*8:off + i*8 + 8], 'little')
                state[i] ^= v
            # keccak_f1600 skip round 0
            a = state[:]
            for rnd in range(1, 24):
                C = [a[0]^a[5]^a[10]^a[15]^a[20],
                     a[1]^a[6]^a[11]^a[16]^a[21],
                     a[2]^a[7]^a[12]^a[17]^a[22],
                     a[3]^a[8]^a[13]^a[18]^a[23],
                     a[4]^a[9]^a[14]^a[19]^a[24]]
                D = [C[4] ^ ROT(C[1], 1),
                     C[0] ^ ROT(C[2], 1),
                     C[1] ^ ROT(C[3], 1),
                     C[2] ^ ROT(C[4], 1),
                     C[3] ^ ROT(C[0], 1)]
                for i in range(5):
                    a[i] ^= D[0]; a[i+5] ^= D[0]; a[i+10] ^= D[0]; a[i+15] ^= D[0]; a[i+20] ^= D[0]
                b = [
                    ROT(a[1], 1),   ROT(a[6], 44),   ROT(a[9], 20),   ROT(a[22], 61),
                    ROT(a[14], 18),  ROT(a[20], 18),  ROT(a[2], 62),   ROT(a[12], 43),
                    ROT(a[13], 25),  ROT(a[19], 8),   ROT(a[23], 41),  ROT(a[8], 45),
                    ROT(a[16], 45),  ROT(a[7], 6),    ROT(a[11], 10),  ROT(a[21], 2),
                    ROT(a[24], 14),  ROT(a[5], 36),   ROT(a[10], 3),   ROT(a[17], 15),
                    ROT(a[18], 21),  ROT(a[15], 41),  ROT(a[3], 28),   ROT(a[4], 27),
                ]
                # simplify: just use C's arrangement
                a = [a[0], a[6], a[12], a[18], a[24],
                     a[5], a[11], a[17], a[23], a[4],
                     a[10], a[16], a[22], a[3], a[9],
                     a[15], a[21], a[2], a[8], a[14],
                     a[20], a[1], a[7], a[13], a[19]]
                for i in range(5):
                    for j in range(5):
                        idx = 5*j + i
                        a[idx] = b[idx] ^ (~b[(idx+1)%25] & b[(idx+2)%25])
                a[0] ^= RC[rnd]
            state = a
            off += PLEN

        final = bytearray(PLEN)
        final[:len(data)-off] = data[off:]
        final[len(data)-off] = 0x06
        final[-1] |= 0x80
        for i in range(PLEN // 8):
            v = int.from_bytes(final[i*8:i*8+8], 'little')
            state[i] ^= v

        a = state[:]
        for rnd in range(1, 24):
            C = [a[0]^a[5]^a[10]^a[15]^a[20],
                 a[1]^a[6]^a[11]^a[16]^a[21],
                 a[2]^a[7]^a[12]^a[17]^a[22],
                 a[3]^a[8]^a[13]^a[18]^a[23],
                 a[4]^a[9]^a[14]^a[19]^a[24]]
            D = [C[4] ^ ROT(C[1], 1), C[0] ^ ROT(C[2], 1), C[1] ^ ROT(C[3], 1),
                 C[2] ^ ROT(C[4], 1), C[3] ^ ROT(C[0], 1)]
            for i in range(5):
                a[i] ^= D[0]; a[i+5] ^= D[0]; a[i+10] ^= D[0]; a[i+15] ^= D[0]; a[i+20] ^= D[0]
            b = [a[0], ROT(a[1], 1), ROT(a[2], 62), ROT(a[3], 28), ROT(a[4], 27),
                 ROT(a[5], 36), ROT(a[6], 44), ROT(a[7], 6), ROT(a[8], 55), ROT(a[9], 20),
                 ROT(a[10], 3), ROT(a[11], 10), ROT(a[12], 43), ROT(a[13], 25), ROT(a[14], 39),
                 ROT(a[15], 41), ROT(a[16], 45), ROT(a[17], 15), ROT(a[18], 21), ROT(a[19], 8),
                 ROT(a[20], 18), ROT(a[21], 2), ROT(a[22], 61), ROT(a[23], 56), ROT(a[24], 14)]
            for i in range(25):
                a[i] = b[i] ^ (~b[(i+1)%25] & b[(i+2)%25])
            a[0] ^= RC[rnd]
        state = a

        out = bytearray(OLEN)
        for i in range(OLEN // 8):
            out[i*8:i*8+8] = state[i].to_bytes(8, 'little')
        return bytes(out)

# ── Tor rotation ─────────────────────────────────────────────────────

def rotate_tor(cookie_path=None):
    try:
        cp = cookie_path or os.environ.get("TOR_COOKIE") or "/root/.tor/control_auth_cookie"
        if not os.path.exists(cp):
            return False
        with open(cp, "rb") as f:
            cookie = f.read()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", 9051))
        s.send(f"AUTHENTICATE {cookie.hex()}\r\n".encode())
        time.sleep(0.5)
        if b"250" not in s.recv(1024):
            s.close(); return False
        s.send(b"SIGNAL NEWNYM\r\n")
        time.sleep(2)
        r = s.recv(1024); s.close()
        return b"250" in r
    except Exception:
        return False

# ── DeepSeek Client ──────────────────────────────────────────────────

import requests

SESSION_FILE = Path(".session.json")

class DeepSeekClient:
    def __init__(self, email, password, proxies=None, workspace="workspace"):
        self.powsolver = PoWSolver()
        self.email, self.password = email, password
        self.workspace = Path(workspace)
        self.workspace.mkdir(exist_ok=True)
        self.token = None
        self.user_id = None
        self.session_id = None
        self.http = requests.Session()
        self.http.headers.update({
            "User-Agent": "DeepSeek/2.1.1 (Android 14; Build/AP3A.240905.015)",
            "Content-Type": "application/json",
            "Accept-Language": "en",
            "x-client-platform": "android",
            "x-client-version": "2.1.1",
            "x-auth-token": APM_TOKEN,
        })
        if proxies:
            self.http.proxies.update(proxies)
        self.proxies = proxies or {}
        self._try_load()
        if not self.token:
            self.login()
        if not self.session_id:
            self.create_session()

    def _try_load(self):
        if not SESSION_FILE.exists():
            return False
        try:
            data = json.loads(SESSION_FILE.read_text())
            self.token = data.get("token")
            self.user_id = data.get("user_id")
            self.session_id = data.get("session_id")
            if self.token:
                self.http.headers["Authorization"] = f"Bearer {self.token}"
                r = self.http.get(f"{BASE_URL}/api/v0/users/me", timeout=15)
                if r.status_code == 200:
                    return True
        except Exception:
            pass
        self.token = None
        self.session_id = None
        return False

    def _save(self):
        try:
            SESSION_FILE.write_text(json.dumps({
                "token": self.token, "user_id": self.user_id, "session_id": self.session_id
            }))
        except Exception:
            pass

    def login(self):
        for attempt in range(5):
            try:
                r = self.http.post(f"{BASE_URL}/api/v0/users/login", json={
                    "email": self.email, "password": self.password,
                    "device_id": str(uuid.uuid4()), "os": "android",
                }, timeout=30)
                d = r.json()
                if d.get("code") == 40029:
                    wait = 10 * (attempt + 1)
                    print(f"  [Rate limited, waiting {wait}s]", file=sys.stderr)
                    if attempt >= 2:
                        print("  [Rotating Tor...]", file=sys.stderr)
                        rotate_tor()
                        time.sleep(3)
                    time.sleep(wait)
                    continue
                if d.get("code") != 0:
                    raise Exception(f"Login error: {d}")
                user = d["data"]["biz_data"]["user"]
                self.token = user["token"]
                self.user_id = user["id"]
                self.http.headers["Authorization"] = f"Bearer {self.token}"
                self._save()
                print(f"  [Logged in as {user.get('name', self.email)}]", file=sys.stderr)
                return True
            except requests.exceptions.ConnectionError:
                if attempt < 4:
                    time.sleep(5)
                else:
                    raise
            except Exception:
                if attempt < 4:
                    time.sleep(3)
                else:
                    raise

    def create_session(self):
        r = self.http.post(f"{BASE_URL}/api/v0/chat_session/create", json={}, timeout=30)
        d = r.json()
        if d.get("code") != 0:
            raise Exception(f"Session error: {d}")
        self.session_id = d["data"]["biz_data"]["chat_session"]["id"]
        self._save()
        return self.session_id

    def solve_pow(self, target_path):
        r = self.http.post(f"{BASE_URL}/api/v0/chat/create_pow_challenge",
            json={"target_path": target_path}, timeout=30)
        d = r.json()
        if d.get("code") != 0:
            raise Exception(f"PoW error: {d}")
        chal = d["data"]["biz_data"]["challenge"]
        prefix = f"{chal['salt']}_{chal['expire_at']}_"
        answer = self.powsolver.solve(chal['challenge'], prefix, chal['difficulty'])
        pow_data = {"algorithm": "DeepSeekHashV1", "challenge": chal['challenge'],
            "salt": chal['salt'], "answer": answer, "signature": chal['signature'],
            "target_path": chal['target_path']}
        return base64.b64encode(json.dumps(pow_data).encode()).decode()

    def send_message(self, messages, model="deepseek-v3", stream=False):
        """Send messages to DeepSeek. Returns parsed text."""
        prompt = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        pow_header = self.solve_pow("/api/v0/chat/completion")
        body = {"messages": messages, "chat_session_id": self.session_id,
                "stream": True, "model": model, "prompt": prompt, "ref_file_ids": []}
        r = self.http.post(f"{BASE_URL}/api/v0/chat/completion", json=body,
            headers={"x-ds-pow-response": pow_header}, timeout=120, stream=True)
        if r.status_code == 429:
            print("  [429, rotating Tor...]", file=sys.stderr)
            rotate_tor()
            time.sleep(10)
            self.login()
            self.create_session()
            return self.send_message(messages, model)
        if r.status_code == 401:
            print("  [401, re-logging...]", file=sys.stderr)
            self.login()
            return self.send_message(messages, model)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}: {r.text[:300]}")

        if stream:
            return r  # raw response for streaming

        content = ""
        for line in r.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            raw = line[6:]
            if not raw.startswith("{"):
                continue
            if '"v":"[DONE]"' in raw:
                break
            try:
                d = json.loads(raw)
                v = d.get("v")
                p = d.get("p")
                if isinstance(v, str):
                    if not p:
                        content += v
                    elif p.endswith("content") and d.get("o") == "APPEND":
                        content += v
                elif isinstance(v, dict):
                    for f in v.get("response", {}).get("fragments", []):
                        c = f.get("content", "")
                        if c and not content:
                            content = c
            except (json.JSONDecodeError, TypeError):
                pass
        return content

    def stream_message(self, messages, model="deepseek-v3"):
        """Generator that yields content tokens as they arrive."""
        r = self.send_message(messages, model, stream=True)
        for line in r.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            raw = line[6:]
            if not raw.startswith("{"):
                continue
            if '"v":"[DONE]"' in raw:
                break
            try:
                d = json.loads(raw)
                v = d.get("v")
                p = d.get("p")
                if isinstance(v, str):
                    if not p:
                        yield v
                    elif p.endswith("content") and d.get("o") == "APPEND":
                        yield v
                elif isinstance(v, dict):
                    for f in v.get("response", {}).get("fragments", []):
                        c = f.get("content", "")
                        if c:
                            yield c
            except (json.JSONDecodeError, TypeError):
                pass

    # ── Tools ─────────────────────────────────────────────────────────

    TOOLS_MAP = {
        "write_file": "write_file", "read_file": "read_file",
        "edit_file": "edit_file", "delete_file": "delete_file",
        "list_dir": "list_dir", "exec": "exec", "glob": "glob",
    }

    def write_file(self, path, content):
        p = self.workspace / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return f"Written {len(content)} bytes to {path}"

    def read_file(self, path):
        p = self.workspace / path.lstrip("/")
        if not p.exists():
            return f"Error: not found: {path}"
        return p.read_text()

    def edit_file(self, path, old, new):
        p = self.workspace / path.lstrip("/")
        if not p.exists():
            return "Error: not found"
        content = p.read_text()
        if old not in content:
            return "Error: pattern not found"
        p.write_text(content.replace(old, new, 1))
        return f"Edited {path}"

    def delete_file(self, path):
        p = self.workspace / path.lstrip("/")
        if p.exists():
            p.unlink()
            return f"Deleted {path}"
        return "Error: not found"

    def list_dir(self, path=""):
        p = self.workspace / path.lstrip("/")
        if not p.exists():
            return "Error: not found"
        items = []
        for name in sorted(p.iterdir()):
            items.append({"name": name.name, "type": "dir" if name.is_dir() else "file", "size": name.stat().st_size if name.is_file() else 0})
        return json.dumps(items)

    def exec(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30, cwd=self.workspace)
            out = result.stdout + result.stderr
            return out[:5000] if out else f"Exit code: {result.returncode}"
        except subprocess.TimeoutExpired:
            return "Timed out after 30s"
        except Exception as e:
            return f"Error: {e}"

    def glob(self, pattern):
        matches = gb.glob(os.path.join(str(self.workspace), pattern), recursive=True)
        rel = [os.path.relpath(m, str(self.workspace)) for m in matches]
        return json.dumps(rel)

    # ── ReAct Agent ───────────────────────────────────────────────────

    REACT_SYSTEM = """You are a coding AI agent that writes real code to files.

Tools:
- write_file(path, content) — create/overwrite file
- read_file(path) — read file
- edit_file(path, old, new) — replace text
- delete_file(path) — delete file
- list_dir(path="") — list directory
- exec(command) — run shell command
- glob(pattern) — find files

To use a tool, put on its own line:
TOOL: {"name":"write_file","args":{"path":"hello.txt","content":"Hello World!"}}"""

    def _parse_tool_calls(self, text):
        calls = []
        FUNC_PAT = re.compile(r'^(\w+)\s*\((.+)\)\s*$', re.DOTALL)
        for line in text.split("\n"):
            stripped = line.strip()
            m = FUNC_PAT.match(stripped)
            if m and m.group(1) in self.TOOLS_MAP:
                args = {}
                for kv in re.findall(r'(\w+)\s*=\s*("[^"]*"|\'[^\']*\'|\S+)', m.group(2)):
                    args[kv[0]] = kv[1].strip("\"'")
                alias = {"file_path": "path", "filepath": "path", "cmd": "command"}
                for old, new in alias.items():
                    if old in args and new not in args:
                        args[new] = args.pop(old)
                calls.append((m.group(1), args))
                continue
            js = stripped
            if stripped.startswith("TOOL:"):
                js = stripped[5:].strip()
            if js.startswith("{"):
                depth, start = 0, -1
                for i, c in enumerate(js):
                    if c == '{' and start < 0:
                        start = i
                    if c == '{': depth += 1
                    if c == '}': depth -= 1
                    if depth == 0 and start >= 0:
                        try:
                            d = json.loads(js[start:i+1])
                            name = d.get("tool") or d.get("name") or d.get("function")
                            if name and name in self.TOOLS_MAP:
                                args = d.get("arguments") or d.get("args") or d.get("parameters") or {}
                                calls.append((name, args))
                        except Exception:
                            pass
                        start = -1
        for m in re.finditer(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL):
            try:
                d = json.loads(m.group(1))
                name = d.get("tool") or d.get("name") or d.get("function")
                if name and name in self.TOOLS_MAP:
                    args = d.get("arguments") or d.get("args") or d.get("parameters") or {}
                    calls.append((name, args))
            except Exception:
                pass
        seen = set()
        uniq = []
        for name, args in calls:
            k = (name, json.dumps(args, sort_keys=True))
            if k not in seen:
                seen.add(k); uniq.append((name, args))
        return uniq

    def _strip_tool_markup(self, text):
        lines = []
        for line in text.split("\n"):
            s = line.strip()
            if s.startswith("TOOL:") or s.startswith("<<TOOL>>"):
                continue
            if re.match(r'^(\w+)\s*\(', s) and re.match(r'^(\w+)\s*\((.+)\)\s*$', s, re.DOTALL):
                m = re.match(r'^(\w+)\s*\(', s)
                if m and m.group(1) in self.TOOLS_MAP:
                    continue
            if s.replace("```","").replace("json","").strip().startswith("{"):
                lines.append(""); continue
            lines.append(line)
        clean = "\n".join(lines).strip().replace("<<TOOL>>", "")
        while clean.endswith("}") or clean.endswith(")"):
            clean = clean[:-1].strip()
        return clean

    def chat_react(self, messages, model="deepseek-v3"):
        """ReAct loop: execute tools from AI response, return combined result."""
        full = []
        has_sys = messages and messages[0].get("role") == "system"
        full.append(messages[0] if has_sys else {"role": "system", "content": self.REACT_SYSTEM})
        first_user = True
        for m in messages:
            if m.get("role") == "system": continue
            msg = dict(m)
            if m.get("role") == "user" and first_user:
                msg["content"] = m["content"] + "\n\nTo use a tool: TOOL: {\"name\":\"write_file\",\"args\":{\"path\":\"f.txt\",\"content\":\"...\"}}"
                first_user = False
            full.append(msg)

        for _ in range(10):
            response_text = self.send_message(full, model)
            tool_calls = self._parse_tool_calls(response_text)
            clean = self._strip_tool_markup(response_text)
            if not tool_calls:
                return clean, full
            outputs = []
            for name, args in tool_calls:
                method = getattr(self, name, None)
                if method:
                    outputs.append(f"[{name}: {method(**args) if isinstance(args, dict) else method(args)}]")
                else:
                    outputs.append(f"[{name}: unknown tool]")
            combined = clean + "\n" + "\n".join(outputs) if clean else "\n".join(outputs)
            return combined.strip(), full
        return "Max rounds.", full

    # ── Interactive ───────────────────────────────────────────────────

    def interactive(self, model="deepseek-v3"):
        """Interactive chat loop."""
        print("\n  DeepSeek Vibe Agent — interactive mode", file=sys.stderr)
        print("  Commands: /help /model <name> /session /clear /tools /exit", file=sys.stderr)
        messages = []
        while True:
            try:
                user = input("\n>>> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not user:
                continue
            if user == "/exit":
                break
            elif user == "/clear":
                messages.clear()
                print("  [Cleared]", file=sys.stderr)
                continue
            elif user == "/session":
                print(f"  Session: {self.session_id}", file=sys.stderr)
                continue
            elif user == "/tools":
                print("  Tools: write_file, read_file, edit_file, delete_file, list_dir, exec, glob", file=sys.stderr)
                continue
            elif user.startswith("/model "):
                model = user.split(maxsplit=1)[1]
                print(f"  [Model set to {model}]", file=sys.stderr)
                continue
            elif user == "/help":
                print("  /exit /clear /session /tools /model <name>", file=sys.stderr)
                continue

            messages.append({"role": "user", "content": user})
            result, _ = self.chat_react(messages, model)
            print(f"\n{result}")
            messages.append({"role": "assistant", "content": result})

    def noninteractive(self, message, model="deepseek-v3"):
        """Single-shot message, print result."""
        result, _ = self.chat_react([{"role": "user", "content": message}], model)
        print(result)


# ── CLI ──────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="DeepSeek Vibe Agent — unofficial CLI for chat.deepseek.com",
        epilog="Credentials: set DEEPSEEK_EMAIL / DEEPSEEK_PASSWORD env vars, "
               "or create config.json: {\"email\":\"x\",\"password\":\"y\"}"
    )
    parser.add_argument("message", nargs="*", help="Message to send (omit for interactive mode)")
    parser.add_argument("--email", default=None, help="DeepSeek account email (or DEEPSEEK_EMAIL)")
    parser.add_argument("--password", default=None, help="DeepSeek account password (or DEEPSEEK_PASSWORD)")
    parser.add_argument("--config", default=None, help="Path to JSON config file with email/password")
    parser.add_argument("--model", default="deepseek-v3", help="Model name (deepseek-v3, deepseek-r1, etc.)")
    parser.add_argument("--tor", action="store_true", help="Use Tor proxy (socks5://127.0.0.1:9050)")
    parser.add_argument("--stream", action="store_true", help="Stream response token by token")
    parser.add_argument("--workspace", default="workspace", help="Working directory for file tools")
    args = parser.parse_args()

    # Load credentials: CLI > config file > env vars
    email = args.email or os.environ.get("DEEPSEEK_EMAIL")
    password = args.password or os.environ.get("DEEPSEEK_PASSWORD")
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config) as f:
                cfg = json.load(f)
            email = email or cfg.get("email")
            password = password or cfg.get("password")
        except Exception:
            print("  [Warning: could not read config file]", file=sys.stderr)
    if not email or not password:
        print("Error: email and password required. Use --email/--password, env vars DEEPSEEK_EMAIL/PASSWORD, or --config", file=sys.stderr)
        sys.exit(1)

    proxies = {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"} if args.tor else {}

    print("  [Connecting to DeepSeek...]", file=sys.stderr)
    client = DeepSeekClient(email, password, proxies=proxies, workspace=args.workspace)

    msg = " ".join(args.message) if args.message else None

    if args.stream and msg:
        print(f"\n{msg}\n" + "─" * 40)
        for token in client.stream_message([{"role": "user", "content": msg}], args.model):
            print(token, end="", flush=True)
        print()
    elif msg:
        client.noninteractive(msg, args.model)
    else:
        client.interactive(args.model)

if __name__ == "__main__":
    main()
