# secure-term-chat

> End-to-end encrypted terminal chat — XChaCha20-Poly1305, X25519 ECDH, Ed25519 signatures, TOFU fingerprinting

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Textual](https://img.shields.io/badge/UI-Textual-purple)](https://github.com/Textualize/textual)
[![Status: Beta](https://img.shields.io/badge/status-beta-orange)]()

> ⚠️ **Beta software.** Core crypto and networking are functional; some advanced features (room key distribution, P2P, keystore) have known issues tracked below.

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
git clone https://github.com/Gzeu/secure-term-chat
cd secure-term-chat
pip install -r requirements.txt
```

### 2. Start the server
```bash
# Plain (local testing)
python server.py

# With TLS (recommended for production)
python server.py --tls
```

### 3. Launch the client UI
```bash
python launch_modern.py
```

Press **Ctrl+N** to open the connection dialog, fill in server address, nickname, and room, then connect.

---

## 🔐 Security Model

| Layer | Implementation |
|-------|---------------|
| Symmetric encryption | XChaCha20-Poly1305 |
| Key exchange | X25519 ECDH |
| Identity signatures | Ed25519 |
| Forward secrecy | Symmetric ratchet per PM session |
| Peer verification | TOFU fingerprinting (RAM-only store) |
| Transport | Optional TLS with certificate pinning (TOFU) |
| Room encryption | Shared room key derived via `derive_room_key` |
| Anti-replay | `AntiReplayFilter` per message hash |

**What the server cannot do:** read message contents, impersonate users (Ed25519 signatures on every frame).

**Current limitations:**
- Room key is distributed via server without additional encryption — see Known Issues
- TOFU store is RAM-only; fingerprints reset on restart
- Post-quantum (PQ) mode is disabled pending performance optimization

---

## 💬 Commands

### Chat
| Command | Description |
|---------|-------------|
| `/help` | Show all commands |
| `/connect` | Open connection dialog |
| `/disconnect` | Disconnect from server |
| `/join #room` | Join or create a room |
| `/rooms` | List available rooms |
| `/users` | Show users in current room |
| `/pm @user message` | Send encrypted private message |
| `/filesend path` | Send encrypted file |
| `/clear` | Clear chat history |
| `/quit` | Exit and wipe keys |

### Info
| Command | Description |
|---------|-------------|
| `/identity` | Show your Ed25519 fingerprint |
| `/keys` | Show all known peer fingerprints |
| `/verify @user` | Show a specific peer's fingerprint |
| `/status` | Show connection status |

### Keyboard Shortcuts
| Shortcut | Action |
|----------|--------|
| Ctrl+N | New connection |
| Ctrl+S | Settings |
| Ctrl+L | Clear chat |
| Ctrl+H | Help |
| Ctrl+R | Room list |
| Ctrl+U | User list |
| F1 | Toggle side panel |
| F2 | Toggle status bar |
| Escape | Close modal |

---

## 🏗️ Architecture

```
secure-term-chat/
├── Core
│   ├── client.py              # Network client, crypto sessions, TOFU, file reassembly
│   ├── server.py              # Async TCP server, room routing, frame relay
│   └── utils.py               # Crypto primitives, ratchet, frame protocol, sanitization
│
├── UI
│   ├── modern_ui.py           # Main Textual application (ModernChatApp)
│   └── launch_modern.py       # Entry point
│
├── Features
│   ├── encrypted_keystore.py  # Password-protected Ed25519 key storage (Argon2/bcrypt/PBKDF2)
│   ├── p2p_manager.py         # P2P layer (optional, requires aiortc)
│   ├── file_transfer.py       # Chunked encrypted file transfer
│   ├── room_manager.py        # Multi-room lifecycle and permissions
│   ├── user_manager.py        # Role-based user management
│   ├── audit_compliance.py    # Audit logging and compliance reporting
│   └── performance_monitor.py # Metrics collection and alerting
│
└── requirements.txt
```

### Frame Protocol

Every frame: `[4-byte length][1-byte type][payload][64-byte Ed25519 signature]`

Message types: `HELLO`, `HELLO_ACK`, `ROOM_JOIN`, `ROOM_CHAT`, `ROOM_PM`, `USER_LIST`, `KEY_EXCHANGE`, `ROOM_KEY`, `FILE_CHUNK`, `ROOM_LIST`, `PING`, `PONG`, `ERROR`

---

## 📋 Requirements

```
cryptography>=41.0.0
textual>=0.41.0
pynacl>=1.5.0
rich>=13.0.0
aiofiles>=23.0.0
```

Optional (for P2P mode):
```
aiortc>=1.6.0
aioice>=0.9.0
```

---

## 🐛 Known Issues

These bugs have been identified and are tracked for fixing:

### Critical
| # | File | Issue |
|---|------|-------|
| 1 | `modern_ui.py` | `ChatNetworkClient` called with wrong argument order — `nick` passed as `port` (int). Connection always fails from UI. |
| 2 | `modern_ui.py` | `receive_loop()` never started — incoming messages never arrive. |
| 3 | `modern_ui.py` | `render()` methods return `Static(table)` instead of `table` directly — breaks Textual rendering. |
| 4 | `client.py` | Room key seed sent unencrypted to server (`room_seed.hex()` in plaintext JSON). |

### Important
| # | File | Issue |
|---|------|-------|
| 5 | `modern_ui.py` | `handle_messages()` uses busy polling (`sleep(0.1)`) instead of `await queue.get()`. |
| 6 | `modern_ui.py` | `UIState.CONNECTING` immediately overwritten by 1-second status timer. |
| 7 | `client.py` | `ChatNetworkClient.__init__` ignores `nick` from UI — generates random nickname instead. |
| 8 | `modern_ui.py` | `disconnect()` does not cancel `handle_messages()` task — task continues after disconnect. |
| 9 | `modern_ui.py` | Several class methods accidentally defined at module level (wrong indentation). |
| 10 | `modern_ui.py` | `open_file_transfer()` references undefined `file_data` variable. |

### Minor
| # | File | Issue |
|---|------|-------|
| 11 | `client.py` | `TLSCertStore` stores fingerprint as plain text with no integrity check. |
| 12 | `client.py` | `FileReassembler` has no timeout — incomplete transfers leak memory indefinitely. |
| 13 | `modern_ui.py` | Startup prints 5 separate "initialized" messages — should be silent or batched. |

---

## 📦 Installation Notes

- Python **3.12+** required (uses `tuple[bool, bool]` syntax in type hints)
- TLS requires generating a self-signed certificate: `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes`
- First connection with TLS stores the server certificate fingerprint (TOFU). To reset: `rm ~/.secure-term-chat/server_fingerprint.txt`
- Identity keys are ephemeral by default (RAM-only). Use `/keystore save` to persist them.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
