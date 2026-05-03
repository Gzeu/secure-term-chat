# secure-term-chat

> Enterprise-grade encrypted terminal chat with advanced security and management features

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ready-blue)]()
[![Enterprise](https://img.shields.io/badge/Enterprise-ready-green)]()

---

## 🚀 Quick Start

### 1. Start Server
```bash
python server.py --tls
```

### 2. Launch Modern UI (Recommended)
```bash
python launch_modern.py
```

### 3. Connect Individual Components
```bash
# Multi-room management
python launch_multi_room.py

# File transfer system
python launch_file_transfer.py

# User management
python launch_user_management.py

# Audit and compliance
python launch_audit_compliance.py
```

---

## 🌟 Enterprise Features

### 🔒 Security Layer
- **Encrypted Keystore**: Password-protected key storage with AES-256 encryption
- **P2P WebRTC**: Direct peer-to-peer communication with fallback
- **End-to-end Encryption**: Hybrid crypto protocol with post-quantum support
- **Authentication**: Multi-factor authentication and session management

### 📊 Performance Layer
- **Real-time Monitoring**: CPU, memory, network, and performance metrics
- **Auto-scaling**: Dynamic resource allocation based on load
- **Performance Dashboard**: Interactive monitoring interface
- **Alert System**: Proactive performance issue detection

### 🏠 Advanced Features
- **Multi-room Management**: Complete room lifecycle with permissions
- **Enhanced File Transfer**: Secure sharing with compression and encryption
- **User Management**: Role-based access control with statistics
- **Audit & Compliance**: Multi-framework compliance monitoring (GDPR, HIPAA, SOX, ISO27001)

### 🎨 Modern UI
- **Textual Interface**: Modern terminal-based user interface
- **Modular Architecture**: Independent launch scripts for each component
- **Integrated Experience**: Seamless component interaction
- **Responsive Design**: Adaptive to different terminal sizes

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

### Enterprise Commands
- `/admin` - Open admin panel
- `/audit` - View audit logs
- `/performance` - Show performance metrics
- `/compliance` - Check compliance status

---

## 🔐 Security

- **End-to-End Encryption**: XChaCha20-Poly1305 + post-quantum support
- **Key Exchange**: X25519 ECDH + Ed25519 signatures
- **Forward Secrecy**: Double ratchet per session
- **TLS**: Certificate pinning with TOFU
- **Zero-Knowledge**: Server cannot read messages
- **Enterprise Compliance**: GDPR, HIPAA, SOX, ISO27001 support
- **Audit Trail**: Complete logging and compliance monitoring

---

## 📦 Installation

```bash
git clone https://github.com/Gzeu/secure-term-chat
cd secure-term-chat
pip install -r requirements.txt
```

---

## 🏗️ Architecture

```
secure-term-chat/
├── � Security Layer
│   ├── encrypted_keystore.py     # Password-protected storage
│   ├── p2p_manager.py          # WebRTC communication
│   └── hybrid_crypto.py         # End-to-end encryption
├── 📊 Performance Layer
│   ├── performance_monitor.py   # Real-time monitoring
│   ├── auto_scaling.py         # Dynamic resource management
│   └── scaling_controller.py   # Resource allocation
├── 🏠 Advanced Features
│   ├── room_manager.py          # Multi-room management
│   ├── file_transfer.py         # Secure file sharing
│   ├── user_manager.py          # User access control
│   └── audit_compliance.py      # Compliance monitoring
├── 🎨 Modern UI
│   ├── modern_ui.py             # Main interface
│   ├── multi_room_ui.py         # Room management UI
│   ├── file_transfer_ui.py       # File transfer UI
│   ├── user_management_ui.py      # User management UI
│   └── audit_compliance_ui.py    # Audit interface
├── 🚀 Launch Scripts
│   ├── launch_modern.py          # Main application
│   ├── launch_multi_room.py      # Room management
│   ├── launch_file_transfer.py    # File transfer
│   ├── launch_user_management.py   # User management
│   └── launch_audit_compliance.py  # Audit system
└── 📚 Core System
    ├── client.py                 # Network client
    ├── server.py                 # Chat server
    └── utils.py                  # Utilities
```

---

## 📋 Requirements

- Python 3.12+
- `cryptography>=41.0.0`
- `textual>=0.41.0`
- `pynacl>=1.5.0`
- `websockets>=12.0`
- `aiofiles>=23.0.0`
- `rich>=13.0.0`

---

## 🔐 About

Enterprise-grade encrypted terminal chat with advanced features:

- **Military-grade Encryption**: XChaCha20-Poly1305 + post-quantum support
- **Secure Key Exchange**: X25519 ECDH + Ed25519 signatures
- **Digital Signatures**: Ed25519 for identity verification
- **Forward Secrecy**: Double ratchet-inspired PFS
- **TOFU Fingerprints**: Trust-on-first-use verification
- **P2P Communication**: WebRTC with fallback
- **Performance Monitoring**: Real-time metrics and auto-scaling
- **User Management**: Role-based access control
- **Compliance**: Multi-framework audit and reporting
- **Modern UI**: Textual-based terminal interface
- **High Performance**: asyncio-based networking

---

## 🎯 Use Cases

- **Enterprise Communications**: Secure internal messaging
- **Government Agencies**: Compliance with security standards
- **Healthcare**: HIPAA-compliant communication
- **Financial Services**: SOX-compliant audit trails
- **Legal Firms**: Client-attorney privileged communication
- **Research Teams**: Secure collaboration
- **Privacy-Conscious Users**: Maximum security and anonymity

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.
