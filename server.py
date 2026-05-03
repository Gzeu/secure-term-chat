#!/usr/bin/env python3
# server.py — Discovery & Relay Server for secure-term-chat
# Handles: room management, peer discovery, relay of encrypted blobs.
# Does NOT decrypt anything — operates on opaque ciphertext.

from __future__ import annotations
import asyncio
import argparse
import json
import logging
import secrets
import struct
import ssl
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

from utils import (
    MessageType, parse_frame, build_frame, encode_json_payload,
    HYBRID_CRYPTO_AVAILABLE,
    decode_json_payload, IdentityKey, verify_external,
    fingerprint_from_bytes, AntiReplayFilter, sanitize_nick,
)
from performance_optimizations import (
    FRAME_POOL, SSL_POOL, BROADCASTER, PERF_MONITOR
)
from advanced_optimizations import (
    CRYPTO_CACHE, ADVANCED_MEMORY_POOL, ADAPTIVE_COMPRESSOR,
    CONNECTION_MANAGER, PERFORMANCE_OPTIMIZER
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("server")

RATE_WINDOW    = 5.0
RATE_MAX_MSGS  = 30
MAX_QUEUE_SIZE = 512
MAX_FRAME_SIZE = 2 * 1024 * 1024

# TLS Configuration
TLS_CERT_FILE = "server_cert.pem"
TLS_KEY_FILE = "server_key.pem"
TLS_CA_FILE = "ca_cert.pem"  # For self-signed cert


class RateLimiter:
    def __init__(self, max_msgs: int = RATE_MAX_MSGS, window: float = RATE_WINDOW):
        self._window = window
        self._max = max_msgs
        self._timestamps: deque[float] = deque()

    def allow(self) -> bool:
        now = time.monotonic()
        while self._timestamps and self._timestamps[0] < now - self._window:
            self._timestamps.popleft()
        if len(self._timestamps) >= self._max:
            return False
        self._timestamps.append(now)
        return True


@dataclass
class Peer:
    nick: str
    identity_pub: bytes
    session_pub: bytes
    writer: asyncio.StreamWriter
    reader: asyncio.StreamReader
    rooms: Set[str] = field(default_factory=set)
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(MAX_QUEUE_SIZE))
    rate_limiter: RateLimiter = field(default_factory=RateLimiter)
    replay_filter: AntiReplayFilter = field(default_factory=AntiReplayFilter)
    addr: str = ""
    # Advanced optimizations
    connection_state: Optional[Any] = None
    crypto_cache_key: str = ""

    def __post_init__(self):
        """Initialize advanced optimizations"""
        self.connection_state = CONNECTION_MANAGER.get_connection(self.nick)
        self.crypto_cache_key = f"{self.nick}:{self.identity_pub.hex()[:16]}"

    @property
    def fingerprint(self) -> str:
        return fingerprint_from_bytes(self.identity_pub)

    def to_info(self) -> dict:
        return {
            "nick":         self.nick,
            "identity_pub": self.identity_pub.hex(),
            "session_pub":  self.session_pub.hex(),
            "fingerprint":  self.fingerprint,
        }
    
    def update_activity(self) -> None:
        """Update connection activity for optimization"""
        if self.connection_state:
            self.connection_state.update_activity()
    
    def get_optimized_stats(self) -> dict:
        """Get optimized statistics"""
        base_info = self.to_info()
        if self.connection_state:
            base_info.update(self.connection_state.get_stats())
        return base_info


def generate_tls_certificates():
    """Generate self-signed TLS certificates for the server."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    import ipaddress
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "secure-term-chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Save certificate and private key
    with open(TLS_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    with open(TLS_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    log.info(f"Generated TLS certificates: {TLS_CERT_FILE}, {TLS_KEY_FILE}")
    return cert, private_key


class ChatServer:
    def __init__(self, use_tls: bool = False, pq_mode: bool = False):
        self._peers: Dict[str, Peer] = {}
        self._rooms: Dict[str, Set[str]] = defaultdict(set)
        self._pq_mode = pq_mode
        
        # Initialize hybrid crypto engine if PQ mode is enabled
        if pq_mode and HYBRID_CRYPTO_AVAILABLE:
            from hybrid_crypto import get_hybrid_engine
            self._hybrid_engine = get_hybrid_engine(pq_mode=True)
            log.info("🔒 Post-Quantum hybrid cryptography enabled")
        else:
            self._hybrid_engine = None
            if pq_mode:
                log.warning("⚠️  PQ mode requested but hybrid crypto not available")
        # True zero-knowledge relay - server never stores room keys
        # Room keys are exchanged directly between peers
        self._use_tls = use_tls
        self._server_identity = IdentityKey.generate()
        log.info(f"Server fingerprint: {self._server_identity.fingerprint()}")
        
        if use_tls:
            self._ensure_tls_certificates()
    
    def _ensure_tls_certificates(self):
        """Ensure TLS certificates exist."""
        import os
        if not os.path.exists(TLS_CERT_FILE) or not os.path.exists(TLS_KEY_FILE):
            generate_tls_certificates()
        else:
            log.info(f"Using existing TLS certificates: {TLS_CERT_FILE}")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername", ("?", 0))
        addr_str = f"{addr[0]}:{addr[1]}"
        log.info(f"New connection from {addr_str}")
        peer: Optional[Peer] = None
        try:
            peer = await self._do_handshake(reader, writer, addr_str)
            if peer is None:
                return
            asyncio.create_task(self._writer_loop(peer))  # FIX: create_task
            await self._reader_loop(peer)
        except asyncio.IncompleteReadError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            log.warning(f"Client error {addr_str}: {e}")
        finally:
            if peer:
                await self._disconnect_peer(peer)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _do_handshake(self, reader, writer, addr_str) -> Optional[Peer]:
        try:
            raw = await asyncio.wait_for(self._read_frame(reader), timeout=15.0)
        except asyncio.TimeoutError:
            log.warning(f"Handshake timeout {addr_str}")
            return None

        try:
            frame = parse_frame(raw)
        except ValueError as e:
            log.warning(f"Bad frame from {addr_str}: {e}")
            return None

        if frame["type_id"] != MessageType.HELLO:
            return None

        try:
            hello        = decode_json_payload(frame["payload"])
            # FIX: sanitize nick to prevent ANSI injection
            nick         = sanitize_nick(hello["nick"])
            identity_pub = bytes.fromhex(hello["identity_pub"])
            session_pub  = bytes.fromhex(hello["session_pub"])
        except (KeyError, ValueError) as e:
            log.warning(f"Bad HELLO payload: {e}")
            return None

        if not verify_external(identity_pub, frame["signature"], frame["raw_body"]):
            log.warning(f"Invalid HELLO signature from {addr_str}")
            return None

        if nick in self._peers:
            # Reject connection with nick collision - let client choose different nick
            log.warning(f"Nick collision: {nick} already connected")
            error_payload = encode_json_payload({
                "error": "nick_collision",
                "message": f"Nick '{nick}' is already in use. Please choose a different nick."
            })
            error_frame = build_frame(MessageType.ERROR, error_payload, self._server_identity)
            await self._send_raw(writer, error_frame)
            return None

        peer = Peer(
            nick=nick,
            identity_pub=identity_pub,
            session_pub=session_pub,
            writer=writer,
            reader=reader,
            addr=addr_str,
        )
        self._peers[nick] = peer
        log.info(f"Peer: {nick} | fp={peer.fingerprint}")

        ack_payload = encode_json_payload({
            "server_fp":     self._server_identity.fingerprint(),
            "server_id_pub": self._server_identity.public_bytes().hex(),
            "rooms":         list(self._rooms.keys()),
            "your_nick":     nick,
        })
        ack_frame = build_frame(MessageType.HELLO_ACK, ack_payload, self._server_identity)
        log.debug(f"Sending HELLO_ACK to {addr_str}: {len(ack_frame)} bytes")
        await self._send_raw(writer, ack_frame)
        log.debug(f"HELLO_ACK sent successfully to {addr_str}")
        return peer

    async def _reader_loop(self, peer: Peer) -> None:
        while True:
            raw = await self._read_frame(peer.reader)
            if not raw:
                break
            if len(raw) > MAX_FRAME_SIZE:
                continue
            if not peer.rate_limiter.allow():
                log.warning(f"Rate limit: {peer.nick}")
                continue
            try:
                frame = parse_frame(raw)
            except ValueError:
                continue
            if not peer.replay_filter.check(frame["nonce_id"], frame["timestamp"]):
                log.warning(f"Replay blocked: {peer.nick}")
                continue
            if frame["type_id"] not in (MessageType.PING, MessageType.PONG):
                if not verify_external(peer.identity_pub, frame["signature"], frame["raw_body"]):
                    log.warning(f"Bad sig: {peer.nick}")
                    continue
            await self._dispatch(peer, frame, raw)

    async def _dispatch(self, peer: Peer, frame: dict, raw: bytes) -> None:
        t = frame["type_id"]
        if t == MessageType.ROOM_JOIN:
            await self._handle_join(peer, frame)
        elif t == MessageType.ROOM_CHAT:
            await self._relay_room(peer, frame)
        elif t == MessageType.ROOM_PM:
            await self._relay_pm(peer, frame)
        elif t == MessageType.KEY_EXCHANGE:
            await self._relay_key_exchange(peer, frame)
        elif t == MessageType.ROOM_LIST:
            await self._handle_room_list(peer, frame)
        elif t == MessageType.USER_LIST:
            await self._send_user_list(peer, frame)
        elif t == MessageType.ROOM_KEY:
            await self._handle_room_key(peer, frame)
        elif t == MessageType.PING:
            pong = build_frame(MessageType.PONG, b"", self._server_identity)
            await peer.queue.put(pong)
        elif t == MessageType.DISCONNECT:
            raise ConnectionResetError("client disconnect")
        elif t == MessageType.FILE_CHUNK:
            await self._relay_file_chunk(peer, frame)

    async def _handle_join(self, peer: Peer, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            room = info["room"][:64]
        except Exception:
            return
        peer.rooms.add(room)
        self._rooms[room].add(peer.nick)
        log.info(f"{peer.nick} joined #{room}")

        notify = encode_json_payload({
            "event":        "join",
            "nick":         peer.nick,
            "room":         room,
            "identity_pub": peer.identity_pub.hex(),
            "session_pub":  peer.session_pub.hex(),
            "fingerprint":  peer.fingerprint,
        })
        notify_frame = build_frame(MessageType.HELLO_ACK, notify, self._server_identity)
        await self._broadcast_room(room, notify_frame, exclude=peer.nick)

        # True zero-knowledge relay - server never stores room keys
        if len(self._rooms[room]) == 1:
            # First member - they will generate and distribute room key
            log.info(f"{peer.nick} is first member of #{room} - will generate room key")
        else:
            # Room exists - request room key from existing member (no storage)
            for nick in self._rooms[room]:
                if nick != peer.nick and nick in self._peers:
                    # Request room key from existing member
                    request_payload = encode_json_payload({
                        "room": room,
                        "requester": peer.nick
                    })
                    request_frame = build_frame(MessageType.ROOM_KEY, request_payload, self._server_identity)
                    await self._peers[nick].queue.put(request_frame)
                    log.info(f"Requested room key for #{room} from existing member")
                    break

        members = [
            self._peers[n].to_info()
            for n in self._rooms[room]
            if n != peer.nick and n in self._peers
        ]
        roster = encode_json_payload({"event": "roster", "room": room, "members": members})
        roster_frame = build_frame(MessageType.USER_LIST, roster, self._server_identity)
        await peer.queue.put(roster_frame)
        log.info(f"Room #{room} joined by {peer.nick} - room key distribution enabled")

    async def _relay_room(self, peer: Peer, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            room = info.get("room", "")
        except Exception:
            return
        if room not in peer.rooms:
            return
        relay_payload = encode_json_payload({
            "from":  peer.nick,
            "room":  room,
            "ct":    info.get("ct", ""),
            "audit": info.get("audit", ""),
        })
        relay_frame = build_frame(MessageType.ROOM_CHAT, relay_payload, self._server_identity)
        await self._broadcast_room(room, relay_frame, exclude=peer.nick)

    async def _relay_pm(self, peer: Peer, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            target_nick = info["to"]
        except Exception:
            return
        if target_nick not in self._peers:
            return
        relay = encode_json_payload({
            "from": peer.nick,
            "to":   target_nick,
            "ct":   info.get("ct", ""),
        })
        relay_frame = build_frame(MessageType.ROOM_PM, relay, self._server_identity)
        await self._peers[target_nick].queue.put(relay_frame)

    async def _relay_key_exchange(self, peer: Peer, frame: dict) -> None:
        try:
            info   = decode_json_payload(frame["payload"])
            target = info["to"]
        except Exception:
            return
        if target in self._peers:
            fwd = build_frame(MessageType.KEY_EXCHANGE, frame["payload"], self._server_identity)
            await self._peers[target].queue.put(fwd)

    async def _relay_file_chunk(self, peer: Peer, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            room = info.get("room", "")
            filename = info.get("filename", "file")
            chunk_id = info.get("chunk_id", 0)
            total = info.get("total", 1)
            ct = info.get("ct", "")
        except Exception:
            return
        
        # Security: Validate file chunk parameters to prevent abuse
        if room not in peer.rooms:
            return
        
        # Limit file size to prevent abuse (max 100MB, 1000 chunks)
        if total > 1000 or chunk_id >= total or chunk_id < 0:
            log.warning(f"Invalid file chunk from {peer.nick}: chunk_id={chunk_id}, total={total}")
            return
        
        # Limit filename length
        if len(filename) > 255:
            log.warning(f"Invalid filename from {peer.nick}: {filename[:50]}...")
            return
        
        # Limit ciphertext size (should be reasonable for 64KB chunks)
        if len(ct) > 100 * 1024:  # 100KB max chunk size
            log.warning(f"Oversized file chunk from {peer.nick}: {len(ct)} bytes")
            return
        
        relay = encode_json_payload({
            "from":     peer.nick,
            "room":     room,
            "filename": filename,
            "chunk_id": chunk_id,
            "total":    total,
            "ct":       ct,
        })
        relay_frame = build_frame(MessageType.FILE_CHUNK, relay, self._server_identity)
        await self._broadcast_room(room, relay_frame, exclude=peer.nick)

    async def _handle_room_key(self, peer: Peer, frame: dict) -> None:
        """Handle room key distribution between peers - true P2P, server never stores keys."""
        try:
            info = decode_json_payload(frame["payload"])
            room = info.get("room", "")
            encrypted_key = info.get("encrypted_key", "")
            requester = info.get("requester", "")
        except Exception:
            return
        
        if not room:
            return
        
        # Server never stores room keys - true zero-knowledge relay
        # Only forward key exchange messages between peers
        
        # Distribute room key to other members in room (no storage)
        if encrypted_key and not requester:
            log.info(f"Forwarding room key for #{room} from {peer.nick}")
            for nick in self._rooms[room]:
                if nick != peer.nick and nick in self._peers:
                    room_key_payload = encode_json_payload({
                        "room": room,
                        "from": peer.nick,
                        "encrypted_key": encrypted_key
                    })
                    room_key_frame = build_frame(MessageType.ROOM_KEY, room_key_payload, self._server_identity)
                    await self._peers[nick].queue.put(room_key_frame)
            return
        
        # Forward room key request to existing members (no storage)
        if requester and room in self._rooms:
            log.info(f"Forwarding room key request for #{room} to existing members")
            for nick in self._rooms[room]:
                if nick != peer.nick and nick != requester and nick in self._peers:
                    request_payload = encode_json_payload({
                        "room": room,
                        "requester": requester
                    })
                    request_frame = build_frame(MessageType.ROOM_KEY, request_payload, self._server_identity)
                    await self._peers[nick].queue.put(request_frame)
            return

    async def _handle_room_list(self, peer: Peer, frame: dict) -> None:
        """Handle room list request from client."""
        try:
            info = decode_json_payload(frame["payload"])
            action = info.get("action", "")
        except Exception:
            action = ""
        
        if action == "list_rooms":
            rooms_data = {}
            for room_name, members in self._rooms.items():
                rooms_data[room_name] = {
                    "member_count": len(members),
                    "members": list(members)
                }
            
            payload = encode_json_payload({"rooms": rooms_data})
            response_frame = build_frame(MessageType.ROOM_LIST, payload, self._server_identity)
            await peer.queue.put(response_frame)

    async def _send_user_list(self, peer: Peer, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            room = info.get("room", "")
        except Exception:
            room = ""
        nicks   = list(self._rooms.get(room, set()))
        members = [self._peers[n].to_info() for n in nicks if n in self._peers]
        payload = encode_json_payload({"room": room, "members": members})
        resp = build_frame(MessageType.USER_LIST, payload, self._server_identity)
        await peer.queue.put(resp)

    async def _broadcast_room(self, room: str, frame: bytes, exclude: str = "") -> None:
        """Enhanced broadcast with adaptive compression and crypto caching"""
        # Apply adaptive compression if enabled
        if PERFORMANCE_OPTIMIZER.optimizations_enabled.get("adaptive_compression", True):
            compressed_frame, was_compressed = ADAPTIVE_COMPRESSOR.compress(frame)
            if was_compressed:
                frame = compressed_frame
                log.debug(f"Compressed frame for room #{room} by {len(frame) - len(compressed_frame)} bytes")
        
        # Check crypto cache for frame verification
        frame_hash = hashlib.sha256(frame).hexdigest()
        cached_result = CRYPTO_CACHE.get(frame_hash) if PERFORMANCE_OPTIMIZER.optimizations_enabled.get("crypto_cache", True) else None
        
        if cached_result is None:
            # Frame not cached, proceed with broadcast
            await BROADCASTER.broadcast_to_room(self._peers, self._rooms.get(room, set()), frame, exclude)
            
            # Cache the result
            if PERFORMANCE_OPTIMIZER.optimizations_enabled.get("crypto_cache", True):
                CRYPTO_CACHE.put(frame_hash, frame)
        else:
            # Use cached result (just log for debugging)
            log.debug(f"Using cached crypto result for frame hash {frame_hash[:16]}...")
            
        # Update connection states
        room_members = self._rooms.get(room, set())
        for nick in room_members:
            if nick != exclude and nick in self._peers:
                peer = self._peers[nick]
                peer.update_activity()
                if peer.connection_state:
                    peer.connection_state.message_count += 1
                    peer.connection_state.bytes_sent += len(frame)

    async def _writer_loop(self, peer: Peer) -> None:
        while True:
            try:
                frame = await asyncio.wait_for(peer.queue.get(), timeout=30.0)
                await self._send_raw(peer.writer, frame)
            except asyncio.TimeoutError:
                ping = build_frame(MessageType.PING, b"", self._server_identity)
                try:
                    await self._send_raw(peer.writer, ping)
                except Exception:
                    break
            except Exception:
                break

    async def _disconnect_peer(self, peer: Peer) -> None:
        log.info(f"Disconnect: {peer.nick}")
        
        # Clean up connection state
        if peer.connection_state:
            connection_stats = CONNECTION_MANAGER.remove_connection(peer.nick)
            if connection_stats:
                log.debug(f"Connection stats for {peer.nick}: {connection_stats.get_stats()}")
        
        self._peers.pop(peer.nick, None)
        for room in peer.rooms:
            self._rooms[room].discard(peer.nick)
            # Clean up empty rooms to prevent memory leak
            if not self._rooms[room]:
                del self._rooms[room]
                log.info(f"Cleaned up empty room: #{room}")
            else:
                notify = encode_json_payload({"event": "leave", "nick": peer.nick, "room": room})
                frame  = build_frame(MessageType.HELLO_ACK, notify, self._server_identity)
                await self._broadcast_room(room, frame)

    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> bytes:
        len_bytes = await reader.readexactly(4)
        total = struct.unpack(">I", len_bytes)[0]
        # Security: Check frame size BEFORE allocating memory
        if total > MAX_FRAME_SIZE:
            raise ValueError(f"Frame too large: {total}")
        body = await reader.readexactly(total)
        return len_bytes + body

    @staticmethod
    async def _send_raw(writer: asyncio.StreamWriter, data: bytes) -> None:
        """Send raw data"""
        writer.write(data)
        await writer.drain()


async def main():
    parser = argparse.ArgumentParser(description="secure-term-chat relay server")
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, default=12345)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--tls", action="store_true", help="Enable TLS encryption")
    parser.add_argument("--pq-mode", action="store_true", help="Enable Post-Quantum hybrid cryptography")
    parser.add_argument("--disable-crypto-cache", action="store_true", help="Disable cryptographic operation caching")
    parser.add_argument("--disable-adaptive-compression", action="store_true", help="Disable adaptive compression")
    parser.add_argument("--disable-advanced-memory", action="store_true", help="Disable advanced memory pool")
    parser.add_argument("--enable-advanced-optimizations", action="store_true", help="Enable all advanced optimizations")
    args = parser.parse_args()
    
    # Configure advanced optimizations based on CLI args
    if args.disable_crypto_cache:
        PERFORMANCE_OPTIMIZER.disable_optimization("crypto_cache")
    if args.disable_adaptive_compression:
        PERFORMANCE_OPTIMIZER.disable_optimization("adaptive_compression")
    if args.disable_advanced_memory:
        PERFORMANCE_OPTIMIZER.disable_optimization("advanced_memory_pool")
    if args.enable_advanced_optimizations:
        log.info("🚀 Advanced optimizations enabled")
        log.info(PERFORMANCE_OPTIMIZER.get_comprehensive_report())

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    srv    = ChatServer(use_tls=args.tls, pq_mode=args.pq_mode)
    
    if args.tls:
        # Use SSL context pool with explicit secure verification
        ssl_context = SSL_POOL.get_context(TLS_CERT_FILE, TLS_KEY_FILE, ssl.CERT_REQUIRED)
        ssl_context.check_hostname = False  # We use fingerprinting instead
        # verify_mode is now set to CERT_REQUIRED by SSL_POOL.get_context()
        
        server = await asyncio.start_server(
            srv.handle_client, args.host, args.port,
            ssl=ssl_context,
            limit=MAX_FRAME_SIZE + 8,
        )
        log.info(f"🔒 TLS enabled - Listening on secure connections")
    else:
        server = await asyncio.start_server(
            srv.handle_client, args.host, args.port,
            limit=MAX_FRAME_SIZE + 8,
        )
        log.info("⚠️  TLS disabled - Plain text connections only")
    
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.info(f"Listening on {addrs}")
    log.info(f"Server FP: {srv._server_identity.fingerprint()}")
    log.info("RAM-only mode: no persistence, no message content logged.")
    log.info("🚀 Performance optimizations enabled: Frame Pooling, SSL Pooling, Compression")
    log.info("⚡ Advanced optimizations: Crypto Cache, Adaptive Compression, Memory Pool, Connection Management")
    
    # Start performance monitoring task
    async def performance_monitor():
        while True:
            await asyncio.sleep(60)  # Report every minute
            log.info(PERF_MONITOR.get_report())
    
    # Start advanced optimizations maintenance task
    async def advanced_maintenance():
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            # Clean up stale connections
            stale_count = CONNECTION_MANAGER.cleanup_stale(timeout=300.0)
            if stale_count > 0:
                log.info(f"Cleaned up {stale_count} stale connections")
            
            # Log advanced performance report
            if args.debug:
                log.debug(PERFORMANCE_OPTIMIZER.get_comprehensive_report())
    
    asyncio.create_task(performance_monitor())
    asyncio.create_task(advanced_maintenance())
    
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Server shutting down.")
