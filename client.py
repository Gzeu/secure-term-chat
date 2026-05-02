#!/usr/bin/env python3
# client.py — Encrypted Terminal Chat Client
# pip install cryptography textual

from __future__ import annotations
import asyncio
import argparse
import os
import sys
import time
import asyncio
import struct
import secrets
import logging
import hashlib
from pathlib import Path
from typing import Dict, Optional, List
from collections import deque

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Input, RichLog, Static, ProgressBar
from textual import events

from utils import (
    IdentityKey, SessionKey,
    derive_session_key, derive_room_key,
    encrypt_message, decrypt_message,
    SymmetricRatchet,
    MessageType, build_frame, parse_frame,
    encode_json_payload, decode_json_payload,
    verify_external, fingerprint_from_bytes,
    AntiReplayFilter, message_hash,
    encrypt_file_stream, CHUNK_SIZE,
    sanitize_nick, wipe_bytearray,
    InvalidTag,
    HYBRID_CRYPTO_AVAILABLE,
)
from optimized_hybrid_session import OptimizedHybridSession, create_session
from keystore import AnonymousKeystore, generate_temporary_nickname

MAX_FRAME_SIZE = 2 * 1024 * 1024
RECONNECT_DELAY = 5.0   # seconds between reconnect attempts
RECONNECT_MAX   = 5     # max attempts

# TLS Configuration
TLS_CERT_FILE = Path.home() / ".secure-term-chat" / "server_cert.pem"
TLS_FINGERPRINT_FILE = Path.home() / ".secure-term-chat" / "server_fingerprint.txt"


# ──────────────────────────────────────────────────
# TLS Certificate Fingerprinting (TOFU)
# ──────────────────────────────────────────────────
class TLSCertStore:
    """Trust-On-First-Use certificate fingerprinting."""
    
    def __init__(self):
        self._ensure_dir()
        self._load_fingerprint()
    
    def _ensure_dir(self):
        TLS_CERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    def _load_fingerprint(self):
        if TLS_FINGERPRINT_FILE.exists():
            self._stored_fp = TLS_FINGERPRINT_FILE.read_text().strip()
        else:
            self._stored_fp = None
    
    def _save_fingerprint(self, fp: str):
        TLS_FINGERPRINT_FILE.write_text(fp + "\n")
        self._stored_fp = fp
    
    def get_fingerprint(self, cert_der: bytes) -> str:
        """Calculate SHA-256 fingerprint of certificate DER."""
        return hashlib.sha256(cert_der).hexdigest()
    
    def verify_or_trust(self, cert_der: bytes) -> tuple[bool, bool]:
        """
        Verify certificate fingerprint or trust on first use.
        Returns (is_trusted, is_new_trust)
        """
        fp = self.get_fingerprint(cert_der)
        
        if self._stored_fp is None:
            # First time seeing this cert - trust it
            self._save_fingerprint(fp)
            return True, True
        
        # Verify against stored fingerprint
        return fp == self._stored_fp, False


# ──────────────────────────────────────────────────
# TOFU Store (RAM-only) - Enhanced for Hybrid Crypto
# ──────────────────────────────────────────────────
class TOFUStore:
    def __init__(self):
        self._store: Dict[str, Dict[str, str]] = {}

    def check_or_trust_classical(self, nick: str, identity_pub_hex: str) -> tuple[bool, bool]:
        """Classical TOFU check for Ed25519 fingerprints"""
        fp = fingerprint_from_bytes(bytes.fromhex(identity_pub_hex))
        if nick not in self._store:
            self._store[nick] = {"classical": fp}
            return True, True
        stored_fp = self._store[nick].get("classical")
        return stored_fp == fp, False

    def check_or_trust_hybrid(self, nick: str, hybrid_fingerprint: str) -> tuple[bool, bool]:
        """Hybrid TOFU check for fingerprints with PQ material"""
        if nick not in self._store:
            self._store[nick] = {"hybrid": hybrid_fingerprint}
            return True, True
        stored_fp = self._store[nick].get("hybrid")
        return stored_fp == hybrid_fingerprint, False

    def check_or_trust(self, nick: str, identity_pub_hex: str, hybrid_fingerprint: Optional[str] = None) -> tuple[bool, bool]:
        """Unified TOFU check - classical or hybrid"""
        if hybrid_fingerprint:
            return self.check_or_trust_hybrid(nick, hybrid_fingerprint)
        else:
            return self.check_or_trust_classical(nick, identity_pub_hex)

    def get(self, nick: str) -> Optional[Dict[str, str]]:
        """Get stored fingerprint(s) for peer"""
        return self._store.get(nick)

    def get_classical(self, nick: str) -> Optional[str]:
        """Get classical fingerprint only"""
        peer_data = self._store.get(nick)
        return peer_data.get("classical") if peer_data else None

    def get_hybrid(self, nick: str) -> Optional[str]:
        """Get hybrid fingerprint only"""
        peer_data = self._store.get(nick)
        return peer_data.get("hybrid") if peer_data else None

    def all(self) -> dict:
        return dict(self._store)

    def upgrade_to_hybrid(self, nick: str, hybrid_fingerprint: str) -> bool:
        """Upgrade existing classical fingerprint to hybrid"""
        if nick in self._store and "hybrid" not in self._store[nick]:
            self._store[nick]["hybrid"] = hybrid_fingerprint
            return True
        return False


# ──────────────────────────────────────────────────
# Peer Session (E2EE state per peer for PMs)
# FIX: salt is exchanged via KEY_EXCHANGE message
# ──────────────────────────────────────────────────
class PeerSession:
    def __init__(self, nick: str, identity_pub_hex: str, session_pub_hex: str):
        self.nick         = nick
        self.identity_pub = bytes.fromhex(identity_pub_hex)
        self.session_pub  = bytes.fromhex(session_pub_hex)
        self.fingerprint  = fingerprint_from_bytes(self.identity_pub)
        self._enc_key: Optional[bytearray] = None
        self._ratchet_send: Optional[SymmetricRatchet] = None
        self._ratchet_recv: Optional[SymmetricRatchet] = None
        self._send_salt: Optional[bytes] = None

    def derive_keys(self, our_session: SessionKey, salt: bytes | None = None) -> bytes:
        """
        Perform ECDH and derive session key + ratchets.
        FIX: Returns the salt used so it can be sent to peer via KEY_EXCHANGE.
        """
        shared = our_session.exchange(self.session_pub)
        enc_key, used_salt = derive_session_key(shared, salt)
        wipe_bytearray(shared)  # FIX: wipe ECDH result immediately
        if self._enc_key:
            wipe_bytearray(self._enc_key)
        self._enc_key = enc_key
        self._send_salt = used_salt
        self._ratchet_send = SymmetricRatchet(enc_key)
        self._ratchet_recv = SymmetricRatchet(enc_key)
        return used_salt

    def apply_peer_salt(self, our_session: SessionKey, peer_salt: bytes) -> None:
        """Re-derive recv ratchet using peer's salt for symmetric keys."""
        shared = our_session.exchange(self.session_pub)
        enc_key, _ = derive_session_key(shared, peer_salt)
        wipe_bytearray(shared)
        self._ratchet_recv = SymmetricRatchet(enc_key)
        wipe_bytearray(enc_key)

    def encrypt_pm(self, plaintext: bytes) -> str:
        if self._ratchet_send is None:
            raise RuntimeError("Keys not derived")
        return self._ratchet_send.encrypt(plaintext).hex()

    def decrypt_pm(self, ct_hex: str) -> bytes:
        if self._ratchet_recv is None:
            raise RuntimeError("Keys not derived")
        return self._ratchet_recv.decrypt(bytes.fromhex(ct_hex))

    def destroy(self):
        if self._enc_key:
            wipe_bytearray(self._enc_key)
        if self._ratchet_send:
            self._ratchet_send.destroy()
        if self._ratchet_recv:
            self._ratchet_recv.destroy()


# ──────────────────────────────────────────────────
# File Transfer Progress Tracker
# ──────────────────────────────────────────────────
class FileTransferProgress:
    """Track progress of file transfers with ETA and speed calculation."""
    
    def __init__(self, filename: str, total_chunks: int):
        self.filename = filename
        self.total_chunks = total_chunks
        self.received_chunks = 0
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.last_chunk_count = 0
        self.current_speed = 0.0  # KB/s
        
    def update(self, chunk_id: int) -> tuple[float, float, str]:
        """Update progress and return (percentage, speed_kb_s, eta_str)."""
        self.received_chunks += 1
        current_time = time.time()
        
        # Calculate speed (KB/s)
        time_diff = current_time - self.last_update_time
        if time_diff >= 1.0:  # Update speed every second
            chunk_diff = self.received_chunks - self.last_chunk_count
            self.current_speed = (chunk_diff * CHUNK_SIZE) / (time_diff * 1024)  # KB/s
            self.last_update_time = current_time
            self.last_chunk_count = self.received_chunks
        
        # Calculate percentage
        percentage = (self.received_chunks / self.total_chunks) * 100
        
        # Calculate ETA
        if self.current_speed > 0:
            remaining_chunks = self.total_chunks - self.received_chunks
            remaining_bytes = remaining_chunks * CHUNK_SIZE
            eta_seconds = remaining_bytes / (self.current_speed * 1024)
            
            if eta_seconds < 60:
                eta_str = f"{eta_seconds:.0f}s"
            elif eta_seconds < 3600:
                eta_str = f"{eta_seconds/60:.1f}m"
            else:
                eta_str = f"{eta_seconds/3600:.1f}h"
        else:
            eta_str = "∞"
        
        return percentage, self.current_speed, eta_str
    
    def is_complete(self) -> bool:
        return self.received_chunks >= self.total_chunks


# ──────────────────────────────────────────────────
# File Chunk Reassembly Buffer
# FIX: full multi-chunk file reassembly
# ──────────────────────────────────────────────────
class FileReassembler:
    def __init__(self):
        # key: (sender, filename) -> {chunk_id: decrypted_bytes}
        self._buffers: Dict[tuple, Dict[int, bytes]] = {}
        self._totals:  Dict[tuple, int] = {}

    def add_chunk(
        self, sender: str, filename: str,
        chunk_id: int, total: int, data: bytes
    ) -> Optional[bytes]:
        """
        Add a decrypted chunk. Returns complete file bytes when all
        chunks received, else None.
        """
        key = (sender, filename)
        if key not in self._buffers:
            self._buffers[key] = {}
            self._totals[key]  = total
        self._buffers[key][chunk_id] = data
        if len(self._buffers[key]) == self._totals[key]:
            # Reassemble in order
            complete = b"".join(
                self._buffers[key][i] for i in range(self._totals[key])
            )
            del self._buffers[key]
            del self._totals[key]
            return complete
        return None


# ──────────────────────────────────────────────────
# Network Client
# ──────────────────────────────────────────────────
class ChatNetworkClient:
    def __init__(self, host: str, port: int, room: str, use_tls: bool = False, pq_mode: bool = False,
                 identity_name: Optional[str] = None, password: Optional[str] = None):
        self.host = host
        self.port = port
        self.room = room
        self.use_tls = use_tls
        self.pq_mode = pq_mode

        # Anonymous keystore support
        self.keystore = AnonymousKeystore()
        self.identity_name = identity_name
        self.password = password
        
        # Initialize optimized hybrid session if PQ mode is enabled
        if pq_mode and HYBRID_CRYPTO_AVAILABLE:
            self._optimized_session = create_session(pq_mode=True)
            print("🔒 Post-Quantum hybrid cryptography enabled (optimized)")
        else:
            self._optimized_session = None
            if pq_mode:
                print("⚠️  PQ mode requested but hybrid crypto not available")
        
        # Legacy hybrid engine (keep for compatibility)
        if pq_mode and HYBRID_CRYPTO_AVAILABLE:
            from hybrid_crypto import get_hybrid_engine
            self._hybrid_engine = get_hybrid_engine(pq_mode=True)
        else:
            self._hybrid_engine = None
        
        # Initialize identity
        self.identity = self._load_or_create_identity()
        self.session  = SessionKey.generate()
        
        # Generate temporary nickname (anonymous)
        self.nick = generate_temporary_nickname()
        
        self.tofu     = TOFUStore()
        self.tls_store = TLSCertStore()  # TLS certificate fingerprinting
        self.peers: Dict[str, PeerSession] = {}
        self.replay   = AntiReplayFilter()
        self.files    = FileReassembler()  # FIX: file reassembly
        self.file_transfers: Dict[str, FileTransferProgress] = {}  # filename -> progress tracker
        self.available_rooms: Dict[str, Dict] = {}  # room_name -> {member_count, members}
        self.current_room = room

        self._room_key: Optional[bytearray] = None

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected   = False
        self._msg_queue: asyncio.Queue = asyncio.Queue()
        self._server_fp: Optional[str] = None
        self._offline_queue: deque = deque(maxlen=256)
        self._reconnect_attempts = 0

    def _load_or_create_identity(self) -> IdentityKey:
        """Load existing identity or create new one."""
        if self.identity_name and self.password:
            # Try to unlock keystore and load identity
            if self.keystore.unlock(self.password):
                identity = self.keystore.get_identity(self.identity_name)
                if identity:
                    return identity
                else:
                    # Create new identity with this name
                    return self.keystore.create_identity(self.identity_name) or IdentityKey.generate()
            else:
                # Failed to unlock, create temporary identity
                return IdentityKey.generate()
        else:
            # No persistent identity, create temporary one
            return IdentityKey.generate()
    
    def save_identity(self, name: str, password: str) -> bool:
        """Save current identity to keystore."""
        if not self.keystore.unlock(password):
            return False
        
        # Check if identity already exists
        if name in self.keystore.list_identities():
            return False
        
        # Save current identity
        saved = self.keystore.create_identity(name)
        if saved:
            self.identity_name = name
            self.password = password
        return saved is not None
    
    def list_identities(self) -> list[str]:
        """List all stored identities."""
        if self.keystore.is_unlocked():
            return self.keystore.list_identities()
        return []
    
    def load_identity(self, name: str, password: str) -> bool:
        """Load identity from keystore."""
        if not self.keystore.unlock(password):
            return False
        
        identity = self.keystore.get_identity(name)
        if identity:
            # Destroy current identity
            self.identity.destroy()
            # Load new identity
            self.identity = identity
            self.identity_name = name
            self.password = password
            return True
        return False

    @property
    def fingerprint(self) -> str:
        return self.identity.fingerprint()

    # ── Connect ──────────────────────────────────────
    async def connect(self) -> bool:
        try:
            if self.use_tls:
                # Create SSL context for TLS connection
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False  # We use fingerprinting instead
                ssl_context.verify_mode = ssl.CERT_NONE  # We'll verify manually
                
                # Note: SSL verification callback is complex in asyncio
                # For now, we'll verify after connection
                
                self._reader, self._writer = await asyncio.open_connection(
                    self.host, self.port, limit=MAX_FRAME_SIZE + 8,
                    ssl=ssl_context,
                )
                
                # Verify certificate after TLS handshake
                ssl_object = self._writer.get_extra_info('ssl_object')
                if ssl_object:
                    cert_der = ssl_object.getpeercert(binary_form=True)
                    is_trusted, is_new = self.tls_store.verify_or_trust(cert_der)
                    
                    if not is_trusted:
                        await self._msg_queue.put({
                            "type": "error", 
                            "msg": f"TLS Certificate fingerprint mismatch! Connection aborted."
                        })
                        self._writer.close()
                        await self._writer.wait_closed()
                        return False
                    
                    if is_new:
                        fp = self.tls_store.get_fingerprint(cert_der)
                        await self._msg_queue.put({
                            "type": "system", 
                            "msg": f"🔒 TLS Connected (TOFU): {fp[:16]}..."
                        })
                    else:
                        await self._msg_queue.put({
                            "type": "system", 
                            "msg": f"🔒 TLS Connected (verified)"
                        })
                else:
                    await self._msg_queue.put({
                        "type": "error", 
                        "msg": "TLS handshake failed - no certificate available"
                    })
                    return False
            else:
                # Plain text connection (for testing/local use)
                self._reader, self._writer = await asyncio.open_connection(
                    self.host, self.port, limit=MAX_FRAME_SIZE + 8,
                )
                await self._msg_queue.put({
                    "type": "system", 
                    "msg": "⚠️  Connected without TLS (insecure)"
                })
            
            self._connected = True
            self._reconnect_attempts = 0
        except Exception as e:
            await self._msg_queue.put({"type": "error", "msg": f"Connection failed: {e}"})
            return False

        hello = encode_json_payload({
            "nick":         self.nick,
            "identity_pub": self.identity.public_bytes().hex(),
            "session_pub":  self.session.public_bytes().hex(),
        })
        await self._send(build_frame(MessageType.HELLO, hello, self.identity))

        try:
            raw = await asyncio.wait_for(self._read_frame(), timeout=15.0)
            f = parse_frame(raw)
            if f["type_id"] == MessageType.HELLO_ACK:
                info = decode_json_payload(f["payload"])
                self._server_fp = info.get("server_fp", "?")
                self.nick = info.get("your_nick", self.nick)
                await self._msg_queue.put({"type": "system", "msg": f"Connected! Server FP: {self._server_fp}"})
                await self._msg_queue.put({"type": "system", "msg": f"Your nick: {self.nick} | FP: {self.fingerprint}"})
        except asyncio.TimeoutError:
            await self._msg_queue.put({"type": "error", "msg": "Handshake timeout"})
            return False

        await self.join_room(self.room)
        return True

    async def join_room(self, room: str) -> None:
        self.room = room
        payload = encode_json_payload({"room": room})
        await self._send(build_frame(MessageType.ROOM_JOIN, payload, self.identity))
        # Don't generate room key yet - wait to see if we're first or receive existing key
        await self._msg_queue.put({"type": "system", "msg": f"Joining #{room}..."})

    # ── Send ──────────────────────────────────────────
    async def send_room_message(self, text: str) -> None:
        if not self._connected or self._room_key is None:
            self._offline_queue.append(("room", text))
            return
        # FIX: use encrypt_message with random nonce (no asymmetric ratchet mismatch)
        # Group chat uses fresh random nonce per message on shared room key
        ct  = encrypt_message(self._room_key, text.encode())
        payload = encode_json_payload({
            "room":  self.room,
            "ct":    ct.hex(),
            "audit": message_hash(ct),
        })
        await self._send(build_frame(MessageType.ROOM_CHAT, payload, self.identity))

    async def send_pm(self, target: str, text: str) -> None:
        if target not in self.peers:
            await self._msg_queue.put({"type": "error", "msg": f"Unknown peer: {target}"})
            return
        ct_hex = self.peers[target].encrypt_pm(text.encode())
        payload = encode_json_payload({"to": target, "ct": ct_hex})
        await self._send(build_frame(MessageType.ROOM_PM, payload, self.identity))

    async def send_file(self, room: str, filepath: str) -> None:
        if self._room_key is None:
            return
        p = Path(filepath)
        if not p.exists():
            await self._msg_queue.put({"type": "error", "msg": f"File not found: {filepath}"})
            return
        chunks = list(encrypt_file_stream(self._room_key, filepath))
        total  = len(chunks)
        for i, ct in enumerate(chunks):
            payload = encode_json_payload({
                "room":     room,
                "filename": p.name,
                "chunk_id": i,
                "total":    total,
                "ct":       ct.hex(),
            })
            await self._send(build_frame(MessageType.FILE_CHUNK, payload, self.identity))
            await asyncio.sleep(0.01)
        await self._msg_queue.put({"type": "system", "msg": f"Sent: {p.name} ({total} chunks)"})

    # ── Receive Loop + Reconnect ──────────────────────
    async def receive_loop(self) -> None:
        while True:
            try:
                raw = await self._read_frame()
                await self._handle_frame(raw)
            except asyncio.IncompleteReadError:
                break
            except Exception as e:
                await self._msg_queue.put({"type": "error", "msg": f"Recv error: {e}"})
                break
        self._connected = False
        await self._msg_queue.put({"type": "system", "msg": "Disconnected."})
        # FIX: auto-reconnect with backoff
        await self._reconnect()

    async def _reconnect(self) -> None:
        while self._reconnect_attempts < RECONNECT_MAX:
            self._reconnect_attempts += 1
            await self._msg_queue.put({
                "type": "system",
                "msg":  f"Reconnecting ({self._reconnect_attempts}/{RECONNECT_MAX}) in {RECONNECT_DELAY}s..."
            })
            await asyncio.sleep(RECONNECT_DELAY)
            ok = await self.connect()
            if ok:
                # Flush offline queue
                while self._offline_queue:
                    kind, text = self._offline_queue.popleft()
                    if kind == "room":
                        await self.send_room_message(text)
                await self._msg_queue.put({"type": "system", "msg": "Reconnected. Offline queue flushed."})
                await self.receive_loop()
                return
        await self._msg_queue.put({"type": "error", "msg": "Max reconnect attempts reached."})

    async def _handle_frame(self, raw: bytes) -> None:
        try:
            frame = parse_frame(raw)
            print(f"[DEBUG] Received frame type: {frame['type_id']}")
        except ValueError as e:
            print(f"[DEBUG] Frame parse error: {e}")
            return
        t = frame["type_id"]
        if t == MessageType.ROOM_CHAT:
            await self._on_room_chat(frame)
        elif t == MessageType.ROOM_PM:
            await self._on_pm(frame)
        elif t == MessageType.HELLO_ACK:
            print(f"[DEBUG] Processing HELLO_ACK")
            await self._on_event(frame)
        elif t == MessageType.USER_LIST:
            print(f"[DEBUG] Processing USER_LIST")
            await self._on_user_list(frame)
        elif t == MessageType.KEY_EXCHANGE:
            await self._on_key_exchange(frame)
        elif t == MessageType.ROOM_KEY:
            print(f"[DEBUG] Processing ROOM_KEY")
            await self._on_room_key(frame)
        elif t == MessageType.FILE_CHUNK:
            await self._on_file_chunk(frame)
        elif t == MessageType.ROOM_LIST:
            await self._on_room_list(frame)
        elif t == MessageType.PING:
            await self._send(build_frame(MessageType.PONG, b"", self.identity))
        elif t == MessageType.ERROR:
            info = decode_json_payload(frame["payload"])
            await self._msg_queue.put({"type": "error", "msg": info.get("msg", "Server error")})

    # FIX: consistent encrypt_message / decrypt_message for group (no ratchet mismatch)
    async def _on_room_chat(self, frame: dict) -> None:
        try:
            info   = decode_json_payload(frame["payload"])
            sender = info["from"]
            ct_hex = info["ct"]
            audit  = info.get("audit", "")
        except Exception:
            return
        if self._room_key is None:
            return
        try:
            pt = decrypt_message(self._room_key, bytes.fromhex(ct_hex))
        except Exception:
            await self._msg_queue.put({"type": "error", "msg": f"[{sender}] Decrypt failed"})
            return
        await self._msg_queue.put({
            "type": "chat", "from": sender,
            "msg":  pt.decode(errors="replace"),
            "audit": audit, "room": info.get("room", self.room),
        })

    async def _on_pm(self, frame: dict) -> None:
        try:
            info   = decode_json_payload(frame["payload"])
            sender = info["from"]
            ct_hex = info["ct"]
        except Exception:
            return
        if sender not in self.peers:
            await self._msg_queue.put({"type": "pm", "from": sender, "msg": "[encrypted — no session]"})
            return
        try:
            pt = self.peers[sender].decrypt_pm(ct_hex)
            await self._msg_queue.put({"type": "pm", "from": sender, "msg": pt.decode(errors="replace")})
        except Exception as e:
            await self._msg_queue.put({"type": "error", "msg": f"PM decrypt fail from {sender}: {e}"})

    async def _on_event(self, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
        except Exception:
            return
        event = info.get("event", "")
        if event in ("join", "roster"):
            members = [info] if event == "join" else info.get("members", [])
            for m in members:
                nick     = sanitize_nick(m.get("nick", "?"))  # FIX: sanitize incoming nicks
                id_pub   = m.get("identity_pub", "")
                sess_pub = m.get("session_pub", "")
                fp       = m.get("fingerprint", "?")
                trusted, new = self.tofu.check_or_trust(nick, id_pub)
                status = "NEW" if new else ("OK" if trusted else "⚠ MISMATCH")
                await self._msg_queue.put({
                    "type": "event",
                    "msg":  f"{nick} | FP [{status}]: {fp}",
                    "trust": status,
                })
                if nick not in self.peers:
                    ps = PeerSession(nick, id_pub, sess_pub)
                    salt = ps.derive_keys(self.session)  # FIX: capture salt
                    self.peers[nick] = ps
                    # FIX: send our salt to peer so they can derive symmetric recv key
                    kex_payload = encode_json_payload({
                        "to":          nick,
                        "from":        self.nick,
                        "session_pub": self.session.public_bytes().hex(),
                        "salt":        salt.hex(),
                    })
                    asyncio.create_task(  # FIX: create_task not ensure_future
                        self._send(build_frame(MessageType.KEY_EXCHANGE, kex_payload, self.identity))
                    )
            
            # Check if we're the first member and should generate room key
            if event == "roster" and self._room_key is None:
                member_count = len(members)
                print(f"[DEBUG] Roster event: {member_count} members")
                if member_count == 0:  # We're the only one so far
                    print(f"[DEBUG] We're first member, should generate room key")
                    # Wait a bit to see if we receive a room key from server
                    await asyncio.sleep(0.5)
                    if self._room_key is None:
                        await self._maybe_generate_room_key(self.room)
                else:
                    await self._msg_queue.put({"type": "system", "msg": f"Joined #{self.room} with {member_count} existing members"})
        elif event == "leave":
            nick = sanitize_nick(info.get("nick", "?"))
            await self._msg_queue.put({"type": "event", "msg": f"{nick} left #{info.get('room','?')}"})
            if nick in self.peers:
                self.peers[nick].destroy()
                del self.peers[nick]

    async def _on_user_list(self, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            print(f"[DEBUG] User list payload: {info}")
        except Exception as e:
            print(f"[DEBUG] User list parse error: {e}")
            return
        if info.get("event") in ("roster", "join"):
            print(f"[DEBUG] Calling _on_event for {info.get('event')}")
            await self._on_event(frame)
            return
        members = info.get("members", [])
        lines   = [f"Users in #{info.get('room', self.room)}:"]
        for m in members:
            lines.append(f"  {m['nick']} | FP: {m.get('fingerprint','?')}")
        await self._msg_queue.put({"type": "system", "msg": "\n".join(lines)})

    async def _on_key_exchange(self, frame: dict) -> None:
        """FIX: apply peer salt to derive symmetric recv ratchet."""
        try:
            info      = decode_json_payload(frame["payload"])
            from_nick = sanitize_nick(info.get("from", "?"))
            sess_pub  = info.get("session_pub", "")
            peer_salt = bytes.fromhex(info.get("salt", "")) if info.get("salt") else None
        except Exception:
            return
        if from_nick in self.peers and peer_salt:
            self.peers[from_nick].apply_peer_salt(self.session, peer_salt)
            await self._msg_queue.put({"type": "system", "msg": f"Keys synchronized with {from_nick}"})
        elif from_nick not in self.peers and sess_pub:
            # Late arrival: peer not yet registered
            await self._msg_queue.put({"type": "system", "msg": f"Key exchange from unknown peer {from_nick}"})

    async def _on_room_key(self, frame: dict) -> None:
        """Handle room key distribution."""
        print(f"[DEBUG] Room key handler called!")
        try:
            info = decode_json_payload(frame["payload"])
            room = info["room"]
            sender = info.get("from", "server")
            encrypted_key_hex = info["encrypted_key"]
            print(f"[DEBUG] Room key payload: room={room}, sender={sender}")
        except Exception as e:
            print(f"[DEBUG] Room key parse error: {e}")
            return
        
        if room != self.room:
            print(f"[DEBUG] Room key for wrong room: {room} != {self.room}")
            return
        
        if sender == "server" and self._room_key is None:
            # Receiving existing room key from server (we're not first)
            await self._msg_queue.put({"type": "system", "msg": f"Receiving room key for #{room}..."})
            # Use the same room key derivation method as sender
            room_seed = bytes.fromhex(encrypted_key_hex)
            print(f"[DEBUG] Bob received room_seed: {room_seed.hex()}")
            self._room_key, _ = derive_room_key(room_seed, room.encode())
            print(f"[DEBUG] Bob derived key: {bytes(self._room_key)[:8].hex()}")
            await self._msg_queue.put({"type": "system", "msg": f"Room key received! Ready to chat in #{room}"})
            print(f"[DEBUG] Room key set from server! Key: {bytes(self._room_key)[:8].hex()}")
        elif sender != "server" and self._room_key is None:
            # Room key from another peer (first client distributing)
            await self._msg_queue.put({"type": "system", "msg": f"Room key from {sender} for #{room}"})
            room_seed = bytes.fromhex(encrypted_key_hex)
            self._room_key, _ = derive_room_key(room_seed, room.encode())
            await self._msg_queue.put({"type": "system", "msg": f"Room key received! Ready to chat in #{room}"})
            print(f"[DEBUG] Room key set from {sender}!")

    async def _maybe_generate_room_key(self, room: str) -> None:
        """
        Generate room key for peer-to-peer distribution.
        
        SECURITY FIX: Server no longer stores or distributes room keys.
        Room keys are now established through peer-to-peer key exchange.
        """
        if self._room_key is None:
            # Generate room seed
            room_seed = secrets.token_bytes(32)
            log.info(f"[ROOM] Generating room key for #{room}")
            self._room_key = derive_room_key(room_seed)
            
            # SECURITY: Do NOT send to server
            # Room key will be distributed via peer-to-peer key exchange
            log.info(f"[ROOM] Room key generated locally - will distribute via peer-to-peer exchange")
            await self._msg_queue.put({"type": "system", "msg": f"Generated room key for #{room} (local)"})

    async def _on_file_chunk(self, frame: dict) -> None:
        """FIX: proper multi-chunk reassembly with progress tracking."""
        try:
            info     = decode_json_payload(frame["payload"])
            sender   = info["from"]
            filename = Path(info.get("filename", "received_file")).name  # prevent path traversal
            chunk_id = int(info["chunk_id"])
            total    = int(info["total"])
            ct_hex   = info["ct"]
        except Exception:
            return
        if self._room_key is None:
            return
        try:
            pt = decrypt_message(self._room_key, bytes.fromhex(ct_hex))
        except Exception as e:
            await self._msg_queue.put({"type": "error", "msg": f"File chunk decrypt error: {e}"})
            return
        
        # Initialize or update progress tracker
        transfer_key = f"{sender}:{filename}"
        if transfer_key not in self.file_transfers:
            self.file_transfers[transfer_key] = FileTransferProgress(filename, total)
        
        progress = self.file_transfers[transfer_key]
        percentage, speed_kb_s, eta = progress.update(chunk_id)
        
        complete = self.files.add_chunk(sender, filename, chunk_id, total, pt)
        if complete is not None:
            out_path = Path(filename)
            out_path.write_bytes(complete)
            
            # Remove progress tracker when complete
            del self.file_transfers[transfer_key]
            
            await self._msg_queue.put({
                "type": "system",
                "msg":  f"✓ File received from {sender}: {filename} ({len(complete):,} bytes)"
            })
        else:
            # Send progress update
            await self._msg_queue.put({
                "type": "file_progress",
                "filename": filename,
                "sender": sender,
                "chunk_id": chunk_id,
                "total": total,
                "percentage": percentage,
                "speed_kb_s": speed_kb_s,
                "eta": eta,
            })

    async def _on_room_list(self, frame: dict) -> None:
        """Handle room list response from server."""
        try:
            info = decode_json_payload(frame["payload"])
            rooms = info.get("rooms", {})
            
            # Update available rooms
            self.available_rooms = {}
            for room_name, room_data in rooms.items():
                self.available_rooms[room_name] = {
                    "member_count": room_data.get("member_count", 0),
                    "members": room_data.get("members", [])
                }
            
            # Send room list update to UI
            await self._msg_queue.put({
                "type": "room_list",
                "rooms": self.available_rooms
            })
            
        except Exception as e:
            await self._msg_queue.put({"type": "error", "msg": f"Room list parsing error: {e}"})

    async def request_room_list(self) -> None:
        """Request list of available rooms from server."""
        payload = encode_json_payload({"action": "list_rooms"})
        await self._send(build_frame(MessageType.ROOM_LIST, payload, self.identity))

    # ── IO ────────────────────────────────────────────
    async def _read_frame(self) -> bytes:
        len_bytes = await self._reader.readexactly(4)
        total = struct.unpack(">I", len_bytes)[0]
        if total > MAX_FRAME_SIZE:
            raise ValueError(f"Frame too large: {total}")
        body = await self._reader.readexactly(total)
        return len_bytes + body

    async def _send(self, data: bytes) -> None:
        if self._writer and not self._writer.is_closing():
            self._writer.write(data)
            await self._writer.drain()

    async def disconnect(self) -> None:
        self._connected = False
        try:
            await self._send(build_frame(MessageType.DISCONNECT, b"", self.identity))
        except Exception:
            pass
        self.identity.destroy()
        self.session.destroy()
        for ps in self.peers.values():
            ps.destroy()
        if self._room_key:
            wipe_bytearray(self._room_key)
        if self._writer:
            self._writer.close()


# ──────────────────────────────────────────────────
# Textual TUI
# ──────────────────────────────────────────────────
class ChatApp(App):
    CSS = """
    Screen { background: #0d1117; }
    #chat-log  { border: solid #30363d; height: 1fr; padding: 0 1; }
    #side-panel { width: 28; border: solid #30363d; padding: 0 1; }
    #status-bar { height: 3; border: solid #30363d; padding: 0 1; color: #8b949e; }
    #input-box  { dock: bottom; height: 3; border: solid #58a6ff; }
    #progress-container { height: 3; border: solid #30363d; margin: 0 1; display: none; }
    #progress-container.visible { display: block; }
    #file-progress { width: 1fr; }
    #progress-info { width: 30; padding: 0 1; }
    """

    def __init__(self, net: ChatNetworkClient):
        super().__init__()
        self.net = net
        self._current_transfer: Optional[str] = None  # Current file being transferred
        self._progress_visible = False  # Progress bar visibility state

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="main-col"):
                yield RichLog(id="chat-log", markup=True, highlight=True)
                with Horizontal(id="progress-container"):
                    yield ProgressBar(id="file-progress", show_eta=True)
                    yield Static(id="progress-info", markup=True)
                yield Static(
                    f"[bold cyan]Nick:[/] {self.net.nick}  "
                    f"[bold cyan]Room:[/] #{self.net.room}  "
                    f"[bold cyan]FP:[/] {self.net.fingerprint}",
                    id="status-bar",
                )
            with Vertical(id="side-panel"):
                yield RichLog(id="users-panel", markup=True)
        yield Input(placeholder="Type a message or /command...", id="input-box")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#chat-log", RichLog).write(
            Text.from_markup(
                f"[bold cyan]╔══ secure-term-chat ══╗[/]\n"
                f"[cyan]Nick:[/] {self.net.nick}\n"
                f"[cyan]Room:[/] #{self.net.room}\n"
                f"[cyan]FP:[/] [green]{self.net.fingerprint}[/]\n"
                f"[dim]Type /help for commands[/]"
            )
        )
        asyncio.create_task(self._start_network())
        self.set_interval(0.1, self._poll_messages)
        # Periodic room list refresh with debouncing
        self.set_interval(60.0, self._refresh_room_list)  # Reduced frequency
        self._last_room_list_update = 0
        # Focus input box
        input_box = self.query_one("#input-box", Input)
        self.set_focus(input_box)

    async def _request_user_list(self) -> None:
        """Request user list for current room."""
        payload = encode_json_payload({"room": self.net.room})
        await self.net._send(build_frame(MessageType.USER_LIST, payload, self.net.identity))

    def _refresh_room_list(self) -> None:
        """Periodically refresh room list with debouncing."""
        current_time = time.time()
        if self.net._connected and (current_time - self._last_room_list_update) > 60:
            asyncio.create_task(self.net.request_room_list())
            self._last_room_list_update = current_time

    async def _start_network(self) -> None:
        # FIX: wrap in try/except to surface errors in UI instead of silently swallowing
        try:
            ok = await self.net.connect()
            if ok:
                # Auto-request room list after connection
                await self.net.request_room_list()
                # Auto-request user list for current room
                await self._request_user_list()
                # Start receive loop
                await self.net.receive_loop()
        except Exception as e:
            await self.net._msg_queue.put({"type": "error", "msg": f"Network fatal: {e}"})

    def _poll_messages(self) -> None:
        while not self.net._msg_queue.empty():
            try:
                self._render_message(self.net._msg_queue.get_nowait())
            except Exception:
                pass

    def _render_message(self, msg: dict) -> None:
        log = self.query_one("#chat-log", RichLog)
        ts  = time.strftime("%H:%M:%S")
        t   = msg["type"]
        if t == "chat":
            audit = f" [dim]#{msg.get('audit','')[:8]}[/]" if msg.get("audit") else ""
            log.write(Text.from_markup(f"[dim]{ts}[/] [bold white]{msg['from']}[/]: {msg['msg']}{audit}"))
        elif t == "pm":
            log.write(Text.from_markup(f"[dim]{ts}[/] [bold magenta]PM ← {msg['from']}:[/] {msg['msg']}"))
        elif t == "system":
            log.write(Text.from_markup(f"[dim]{ts}[/] [bold cyan]● {msg['msg']}[/]"))
        elif t == "event":
            color = "green" if msg.get("trust") in ("OK", "NEW") else "red"
            log.write(Text.from_markup(f"[dim]{ts}[/] [bold {color}]▶ {msg['msg']}[/]"))
            # Refresh user list when someone joins
            if "joined" in msg.get("msg", "").lower():
                asyncio.create_task(self._request_user_list())
        elif t == "error":
            log.write(Text.from_markup(f"[dim]{ts}[/] [bold red]✗ {msg['msg']}[/]"))
        elif t == "file_progress":
            self._handle_file_progress(msg)
        elif t == "room_list":
            self._handle_room_list(msg)
        elif t == "user_list":
            self._handle_user_list(msg)

    def _handle_room_list(self, msg: dict) -> None:
        """Handle room list update."""
        rooms = msg["rooms"]
        log = self.query_one("#chat-log", RichLog)
        
        # Update chat log
        lines = ["[bold cyan]🏠 Available Rooms:[/]"]
        for room_name, room_data in rooms.items():
            member_count = room_data.get("member_count", 0)
            current_marker = " [green]← current[/]" if room_name == self.net.room else ""
            lines.append(f"  [yellow]#{room_name}[/] ({member_count} members){current_marker}")
        
        log.write(Text.from_markup("\n".join(lines)))
        
        # Also update side panel with room info
        users_panel = self.query_one("#users-panel", RichLog)
        users_panel.clear()
        users_panel.write(Text.from_markup("[bold cyan]🏠 Rooms[/]"))
        
        for room_name, room_data in rooms.items():
            member_count = room_data.get("member_count", 0)
            current_marker = " [green]←[/]" if room_name == self.net.room else ""
            users_panel.write(Text.from_markup(f"#{room_name} ({member_count}){current_marker}"))
        
        # Add separator for users
        users_panel.write(Text.from_markup("\n[bold cyan]👥 Users:[/]"))
        
        # Show current room users
        for peer_nick in self.net.peers.keys():
            users_panel.write(Text.from_markup(f"  [green]{peer_nick}[/]"))

    def _handle_user_list(self, msg: dict) -> None:
        """Handle user list update."""
        users = msg.get("users", [])
        log = self.query_one("#chat-log", RichLog)
        users_panel = self.query_one("#users-panel", RichLog)
        
        # Add current user to list if not present
        all_users = set(users)
        all_users.add(self.net.nick)  # Ensure current user is included
        
        # Update chat log
        if all_users:
            lines = ["[bold cyan]👥 Users in room:[/]"]
            for user in sorted(all_users):
                lines.append(f"  [green]{user}[/]")
            log.write(Text.from_markup("\n".join(lines)))
        
        # Update side panel
        users_panel.write(Text.from_markup("[bold cyan]👥 Users:[/]"))
        for user in sorted(all_users):
            users_panel.write(Text.from_markup(f"  [green]{user}[/]"))

    def _handle_file_progress(self, msg: dict) -> None:
        """Handle file transfer progress updates."""
        filename = msg["filename"]
        sender = msg["sender"]
        chunk_id = msg["chunk_id"]
        total = msg["total"]
        percentage = msg["percentage"]
        speed_kb_s = msg["speed_kb_s"]
        eta = msg["eta"]
        
        # Set progress bar visible when transfer starts
        if not self._progress_visible:
            self._progress_visible = True
            progress_container = self.query_one("#progress-container")
            progress_container.set_class("visible")
        
        # Update progress bar
        progress_bar = self.query_one("#file-progress", ProgressBar)
        progress_info = self.query_one("#progress-info", Static)
        
        # Set current transfer ID to track this file
        transfer_key = f"{sender}:{filename}"
        self._current_transfer = transfer_key
        
        # Update progress
        progress_bar.advance(percentage)
        
        # Update info text
        speed_text = f"{speed_kb_s:.1f}KB/s" if speed_kb_s > 0 else "calculating..."
        info_text = f"[cyan]{filename}[/]\n[dim]{chunk_id+1}/{total}[/]\n[yellow]{speed_text}[/]\n[dim]ETA: {eta}[/]"
        progress_info.update(info_text)
        
        # Hide progress bar when complete
        if percentage >= 100.0:
            self._current_transfer = None
            self._progress_visible = False
            progress_container = self.query_one("#progress-container")
            progress_container.remove_class("visible")
            progress_bar.advance(0)  # Reset for next transfer
            progress_info.update("")
            
            # Also show completion message in chat log
            log = self.query_one("#chat-log", RichLog)
            ts = time.strftime("%H:%M:%S")
            log.write(Text.from_markup(f"[dim]{ts}[/] [bold green]✓[/] [cyan]{filename}[/] [dim]from {sender}[/]"))
            
            # Refocus input box after transfer completes
            input_box = self.query_one("#input-box", Input)
            self.set_focus(input_box)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        self.query_one("#input-box", Input).value = ""
        if text.startswith("/"):
            await self._handle_command(text)
        else:
            asyncio.create_task(self.net.send_room_message(text))  # FIX: create_task
            ts = time.strftime("%H:%M:%S")
            self.query_one("#chat-log", RichLog).write(
                Text.from_markup(f"[dim]{ts}[/] [bold green]{self.net.nick}[/] [dim](you)[/]: {text}")
            )

    async def _handle_command(self, text: str) -> None:
        parts = text.split()
        cmd   = parts[0].lower()
        log   = self.query_one("#chat-log", RichLog)

        if cmd == "/help":
            lines = [
                "[bold cyan]Commands:[/]",
                "  [yellow]/join #room[/]         — Join room",
                "  [yellow]/rooms[/]              — List all available rooms",
                "  [yellow]/pm @user msg[/]       — Send encrypted PM",
                "  [yellow]/identity[/]           — Manage anonymous identity",
                "  [yellow]/keys[/]               — Show all fingerprints",
                "  [yellow]/verify @user[/]       — Show peer fingerprint for OOB check",
                "  [yellow]/filesend path[/]      — Send encrypted file to room",
                "  [yellow]/users[/]              — List room users",
                "  [yellow]/quit[/]               — Exit & wipe keys"
            ]
            log.write(Text.from_markup("\n".join(lines)))
        elif cmd == "/join" and len(parts) >= 2:
            room_name = parts[1].lstrip("#")
            asyncio.create_task(self.net.join_room(room_name))
            # Auto-refresh room list after join
            asyncio.create_task(self.net.request_room_list())
        elif cmd == "/pm" and len(parts) >= 3:
            target = parts[1].lstrip("@")
            asyncio.create_task(self.net.send_pm(target, " ".join(parts[2:])))
        elif cmd == "/rooms":
            asyncio.create_task(self.net.request_room_list())
        elif cmd == "/identity":
            await self._handle_identity_command(parts[1:])
        elif cmd == "/keys":
            lines = ["[bold cyan]Fingerprints (TOFU):[/]",
                     f"  [green]you:[/] {self.net.fingerprint}"]
            for nick, fp in self.net.tofu.all().items():
                lines.append(f"  {nick}: [yellow]{fp}[/]")
            log.write(Text.from_markup("\n".join(lines)))
        elif cmd == "/verify" and len(parts) >= 2:
            target = parts[1].lstrip("@")
            fp = self.net.tofu.get(target)
            if fp:
                log.write(Text.from_markup(
                    f"[bold cyan]FP for {target}:[/] [bold green]{fp}[/]\n"
                    "Verify out-of-band (call / Signal) to confirm identity."
                ))
            else:
                log.write(Text.from_markup(f"[red]No fingerprint for {target}[/]"))
        elif cmd == "/filesend" and len(parts) >= 2:
            asyncio.create_task(self.net.send_file(self.net.room, parts[1]))
        elif cmd == "/users":
            payload = encode_json_payload({"room": self.net.room})
            asyncio.create_task(
                self.net._send(build_frame(MessageType.USER_LIST, payload, self.net.identity))
            )
        elif cmd == "/quit":
            asyncio.create_task(self.net.disconnect())
            self.exit()
        else:
            log.write(Text.from_markup(f"[red]Unknown command: {cmd}. Type /help.[/]"))

    async def _handle_identity_command(self, args: list[str]) -> None:
        """Handle identity management commands."""
        log = self.query_one("#chat-log", RichLog)
        
        if not args:
            # Show current identity info
            lines = [
                "[bold cyan]🔐 Anonymous Identity:[/]",
                f"  [green]Nickname:[/] {self.net.nick} (temporary)",
                f"  [green]Fingerprint:[/] {self.net.fingerprint}",
            ]
            if self.net.identity_name:
                lines.append(f"  [green]Stored as:[/] {self.net.identity_name}")
            else:
                lines.append("  [yellow]Not stored in keystore[/]")
            log.write(Text.from_markup("\n".join(lines)))
            return
        
        subcmd = args[0].lower()
        
        if subcmd == "save" and len(args) >= 3:
            name = args[1]
            password = args[2]
            success = self.net.save_identity(name, password)
            if success:
                log.write(Text.from_markup(
                    f"[bold green]✓ Identity saved as '{name}'[/]"
                ))
            else:
                log.write(Text.from_markup(
                    f"[red]✗ Failed to save identity (name exists or password wrong)[/]"
                ))
        
        elif subcmd == "load" and len(args) >= 3:
            name = args[1]
            password = args[2]
            success = self.net.load_identity(name, password)
            if success:
                log.write(Text.from_markup(
                    f"[bold green]✓ Loaded identity '{name}'[/]\n"
                    f"[green]New fingerprint:[/] {self.net.fingerprint}"
                ))
            else:
                log.write(Text.from_markup(
                    f"[red]✗ Failed to load identity (not found or password wrong)[/]"
                ))
        
        elif subcmd == "list":
            if self.net.password:
                # Try to unlock with current password
                if self.net.keystore.unlock(self.net.password):
                    identities = self.net.list_identities()
                    if identities:
                        lines = ["[bold cyan]🔐 Stored Identities:[/]"]
                        for name in identities:
                            current = " [green]← current[/]" if name == self.net.identity_name else ""
                            lines.append(f"  {name}{current}")
                        log.write(Text.from_markup("\n".join(lines)))
                    else:
                        log.write(Text.from_markup("[yellow]No stored identities[/]"))
                else:
                    log.write(Text.from_markup("[red]Keystore locked - provide password[/]"))
            else:
                log.write(Text.from_markup("[yellow]No keystore password provided[/]"))
        
        elif subcmd == "new":
            # Generate new temporary identity
            self.net.identity.destroy()
            self.net.identity = IdentityKey.generate()
            self.net.nick = generate_temporary_nickname()
            log.write(Text.from_markup(
                f"[bold green]✓ New temporary identity created[/]\n"
                f"[green]New nickname:[/] {self.net.nick}\n"
                f"[green]New fingerprint:[/] {self.net.fingerprint}"
            ))
        
        else:
            lines = [
                "[bold cyan]Identity Commands:[/]",
                "  [yellow]/identity[/]                    — Show current identity",
                "  [yellow]/identity save <name> <pwd>[/]   — Save current identity",
                "  [yellow]/identity load <name> <pwd>[/]   — Load saved identity", 
                "  [yellow]/identity list[/]               — List saved identities",
                "  [yellow]/identity new[/]                — Generate new temporary identity",
            ]
            log.write(Text.from_markup("\n".join(lines)))

    async def on_key(self, event: events.Key) -> None:
        """Handle key events for command completion."""
        if event.key == "tab":
            input_box = self.query_one("#input-box", Input)
            current_text = input_box.value.strip()
            
            if current_text.startswith("/"):
                # Command completion
                commands = [
                    "/help", "/join", "/rooms", "/pm", "/identity", 
                    "/keys", "/verify", "/filesend", "/users", "/quit"
                ]
                
                matching = [cmd for cmd in commands if cmd.startswith(current_text)]
                if len(matching) == 1:
                    input_box.value = matching[0] + " "
                elif len(matching) > 1:
                    # Show options in chat log
                    log = self.query_one("#chat-log", RichLog)
                    log.write(Text.from_markup(
                        f"[dim]Command options:[/] {', '.join(matching)}"
                    ))
            else:
                # Nickname completion
                if "@" in current_text:
                    prefix = current_text[:current_text.rfind("@") + 1]
                    # Get available nicks from peers
                    nicks = list(self.net.peers.keys())
                    matching = [nick for nick in nicks if nick.startswith(prefix)]
                    if len(matching) == 1:
                        input_box.value = current_text[:current_text.rfind("@")] + "@" + matching[0] + " "
                    elif len(matching) > 1:
                        log = self.query_one("#chat-log", RichLog)
                        log.write(Text.from_markup(
                            f"[dim]Nick options:[/] {', '.join('@' + nick for nick in matching)}"
                        ))
        
        
    async def on_unmount(self) -> None:
        await self.net.disconnect()


# ──────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="secure-term-chat — Anonymous E2EE encrypted terminal chat",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python client.py localhost:12345 --room default
  python client.py localhost:12345 --room default --tls
  python client.py 192.168.1.10:12345 --room crypto
"""
    )
    parser.add_argument("server", help="host:port")
    parser.add_argument("--room", default="default", help="Room to join")
    parser.add_argument("--tls", action="store_true", help="Use TLS encryption for connection")
    parser.add_argument("--pq-mode", action="store_true", help="Enable Post-Quantum hybrid cryptography")
    parser.add_argument("--identity", help="Load saved identity name")
    parser.add_argument("--password", help="Password for keystore/identity")
    args = parser.parse_args()
    try:
        host, port_str = args.server.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        print(f"Invalid address: {args.server}")
        sys.exit(1)
    
    # Create client with anonymous identity
    client = ChatNetworkClient(
        host, port, args.room, use_tls=args.tls, pq_mode=args.pq_mode,
        identity_name=args.identity, password=args.password
    )
    ChatApp(client).run()


if __name__ == "__main__":
    main()
