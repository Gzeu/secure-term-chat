# secure-term-chat

> Anonymous E2EE encrypted terminal chat with group chat support

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ready-blue)]()

---

## 🚀 Quick Start

### 1. Start Server
```bash
python server.py --tls
```

### 2. Connect Clients
```bash
# Anonymous client
python client.py localhost:12345 --room crypto --tls

# With persistent identity
python client.py localhost:12345 --room crypto --tls --identity alice --password mypass
```

### 3. Verify Fingerprints
Server and client show fingerprints - verify out-of-band for security.

---

## 💬 Commands

### Chat Commands
- `/help` - Show all commands
- `/join #room` - Join/create room
- `/rooms` - List available rooms
- `/users` - Show users in current room
- `/pm @user message` - Send private message
- `/quit` - Exit and wipe keys

### Security Commands
- `/identity` - Show your fingerprint
- `/keys` - Show all known fingerprints
- `/verify @user` - Show user's fingerprint
- `/filesend path` - Send encrypted file

---

## 🔐 Security

- **End-to-End Encryption**: XChaCha20-Poly1305
- **Key Exchange**: X25519 ECDH + Ed25519 signatures
- **Forward Secrecy**: Double ratchet per session
- **TLS**: Certificate pinning with TOFU
- **Zero-Knowledge**: Server cannot read messages

---

## 📦 Installation

```bash
git clone https://github.com/Gzeu/secure-term-chat
cd secure-term-chat
pip install -e .
```

---

## 🔐 About

Ultra-secure encrypted terminal chat room with:

- **XChaCha20-Poly1305** - Military-grade encryption
- **X25519 ECDH** - Secure key exchange  
- **Ed25519** - Digital signatures
- **Double Ratchet-inspired PFS** - Forward secrecy
- **TOFU fingerprints** - Trust-on-first-use verification
- **asyncio** - High-performance networking
- **Textual TUI** - Modern terminal interface

---

## 📋 Requirements

- Python 3.12+
- `cryptography>=41.0.0`
- `textual>=0.41.0`
- `pynacl>=1.5.0`

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.
