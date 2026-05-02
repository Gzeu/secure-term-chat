# 📁 Secure Term Chat - Project Structure

## 🏗️ **Production Architecture**

```
secure-term-chat/
├── 📄 Core Files
│   ├── server.py              # Relay server with room key distribution
│   ├── client.py              # TUI client with group chat support
│   ├── utils.py               # Crypto primitives and wire protocol
│   └── performance_optimizations.py # Performance enhancements
│
├── 🔐 Cryptography Modules
│   ├── hybrid_crypto.py       # Post-Quantum hybrid cryptography
│   ├── double_ratchet_custom.py # Custom double ratchet implementation
│   └── signal_sender_keys.py # Signal-style group chat keys
│
├── 📋 Configuration
│   ├── pyproject.toml         # Package configuration
│   ├── requirements.txt       # Production dependencies
│   ├── requirements-dev.txt   # Development dependencies
│   └── pytest.ini            # Test configuration
│
├── 🧪 Testing
│   └── tests/
│       ├── test_simple.py     # Core crypto tests
│       └── __pycache__/        # Test cache
│
├── 🐳 Docker
│   ├── Dockerfile             # Multi-stage container build
│   └── .dockerignore          # Docker ignore rules
│
├── 🔧 Development Tools
│   ├── .pre-commit-config.yaml # Pre-commit hooks
│   ├── .github/               # CI/CD workflows
│   └── scripts/               # Development utilities
│
├── 📚 Documentation
│   ├── README.md              # Main documentation
│   ├── OPTIMIZATIONS_SUMMARY.md # Performance improvements
│   ├── DEPLOYMENT_GUIDE.md    # Production deployment guide
│   └── LICENSE                # MIT License
│
├── 🔑 TLS Certificates (Runtime)
│   ├── server_cert.pem        # Self-signed server certificate
│   └── server_key.pem         # Server private key
│
├── 📦 Reports
│   ├── BUG_FIX_REPORT.md      # Frame corruption fix documentation
│   └── ROOM_KEY_FIX_REPORT.md # Room key distribution fix
│
└── 📦 Build Artifacts
    ├── dist/                  # Package distribution
    ├── secure_term_chat.egg-info/ # Package metadata
    └── __pycache__/           # Python cache
```

---

## 🎯 **Core Components**

### **🚀 Server (`server.py`)**
- **Room Key Distribution**: Functional group chat support
- **Performance Optimized**: Frame pooling, SSL pooling, broadcast optimization
- **Async Architecture**: Single-threaded asyncio for scalability
- **Security**: RAM-only, encrypted key storage only

### **🎨 Client (`client.py`)**
- **Group Chat Support**: Room key generation and sharing
- **Modern UI**: Textual TUI with real-time updates
- **Security**: End-to-end encryption, TOFU fingerprinting
- **Features**: Private messages, file transfer, identity management

### **🔧 Utils (`utils.py`)**
- **Crypto Primitives**: XChaCha20-Poly1305, X25519, Ed25519
- **Wire Protocol**: Frame building/parsing, message types
- **Security**: Anti-replay, forward secrecy, memory wiping

### **⚡ Performance (`performance_optimizations.py`)**
- **Frame Pooling**: Memory management for buffers
- **SSL Pooling**: Connection reuse for TLS performance
- **Broadcast Optimization**: Concurrent message delivery
- **Monitoring**: Real-time performance metrics

---

## 📊 **Performance Features**

### **✅ Active Optimizations**
- **Frame Pooling**: Memory reuse and GC pressure reduction
- **SSL Pooling**: Connection reuse for better performance
- **Broadcast Optimization**: Concurrent message delivery
- **Performance Monitoring**: Automated 60-second reports

### **🔍 Real-time Monitoring**
```
=== Performance Report ===
Frame Pool: 85/100 (Hit Rate: 92.3%)
SSL Pool: 8/10 (In Use: 2)
Broadcast: 1500 total, 0 failed
=========================
```

---

## 🔐 **Security Architecture**

### **🛡️ End-to-End Encryption**
- **Algorithm**: XChaCha20-Poly1305 (24-byte nonce)
- **Key Exchange**: X25519 ECDH + HKDF-SHA512
- **Authentication**: Ed25519 signatures + TOFU
- **Forward Secrecy**: Symmetric ratchet per session

### **🔑 Room Key Distribution**
- **Server Coordination**: Encrypted key storage and distribution
- **Peer-to-Peer**: Direct key exchange between users
- **Group Chat**: Shared room keys for multi-user communication
- **Security**: Server cannot decrypt message content

---

## 🚀 **Quick Start**

### **1. Start Server**
```bash
python server.py --tls --debug
```

### **2. Connect Clients**
```bash
# Anonymous client
python client.py localhost:12345 --room crypto --tls

# With persistent identity
python client.py localhost:12345 --room crypto --tls --identity alice --password mypass
```

### **3. Test Communication**
```
# In client 1
Hello from Alice - can anyone see this?

# In client 2
Hello from Bob - testing communication
```

---

## 🎯 **Production Features**

### **✅ Group Chat**
- **Room Key Distribution**: Automatic key sharing
- **Multi-user Support**: Functional group conversations
- **Message Visibility**: All users see each other's messages
- **Security**: End-to-end encrypted group chat

### **✅ Performance Optimized**
- **Frame Pooling**: Memory reuse and GC reduction
- **SSL Pooling**: Connection reuse for TLS
- **Broadcast Optimization**: Concurrent message delivery
- **Real-time Monitoring**: Performance metrics dashboard

### **✅ Security Features**
- **End-to-End Encryption**: XChaCha20-Poly1305
- **Zero-Knowledge**: Server cannot read messages
- **Forward Secrecy**: Symmetric ratchet per session
- **Authentication**: Ed25519 signatures + TOFU

---

## 📋 **Dependencies**

### **Production**
```
cryptography>=41.0.0
textual>=0.41.0
pynacl>=1.5.0
```

---

## 🏆 **Status**

**✅ Production Ready** - Group chat functional

- **Room Key Distribution**: Implemented and working
- **Message Visibility**: Users can see each other's messages
- **Performance**: Optimized with pooling and monitoring
- **Security**: Enterprise-grade encryption maintained

**🚀 Ready for multi-user deployment!**
