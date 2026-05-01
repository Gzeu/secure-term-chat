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
    decode_json_payload, IdentityKey, verify_external,
    fingerprint_from_bytes, AntiReplayFilter, sanitize_nick,
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
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
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
    def __init__(self, use_tls: bool = False):
        self._peers: Dict[str, Peer] = {}
        self._rooms: Dict[str, Set[str]] = defaultdict(set)
        self._room_keys: Dict[str, str] = {}  # room -> encrypted room_key (hex)
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
            nick = nick + "_" + secrets.token_hex(3)

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
        await self._send_raw(writer, ack_frame)
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

        members = [
            self._peers[n].to_info()
            for n in self._rooms[room]
            if n != peer.nick and n in self._peers
        ]
        roster = encode_json_payload({"event": "roster", "room": room, "members": members})
        roster_frame = build_frame(MessageType.USER_LIST, roster, self._server_identity)
        await peer.queue.put(roster_frame)
        
        # Send room key if it exists
        if room in self._room_keys:
            log.info(f"Sending room key to {peer.nick} for #{room}")
            log.info(f"Sending key value: {self._room_keys[room]}")
            payload = encode_json_payload({
                "room": room,
                "from": "server",
                "encrypted_key": self._room_keys[room],
            })
            key_frame = build_frame(MessageType.ROOM_KEY, payload, self._server_identity)
            await peer.queue.put(key_frame)
        else:
            log.info(f"No room key exists for #{room} - new member {peer.nick} should generate")

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
        except Exception:
            return
        if room not in peer.rooms:
            return
        relay = encode_json_payload({
            "from":     peer.nick,
            "room":     room,
            "filename": info.get("filename", "file"),
            "chunk_id": info.get("chunk_id", 0),
            "total":    info.get("total", 1),
            "ct":       info.get("ct", ""),
        })
        relay_frame = build_frame(MessageType.FILE_CHUNK, relay, self._server_identity)
        await self._broadcast_room(room, relay_frame, exclude=peer.nick)

    async def _handle_room_key(self, peer: Peer, frame: dict) -> None:
        """Handle room key distribution from room creator."""
        try:
            info = decode_json_payload(frame["payload"])
            room = info["room"]
            encrypted_key = info["encrypted_key"]  # hex string
        except Exception:
            return
        
        if room not in peer.rooms:
            log.warning(f"Room key from non-member {peer.nick} for #{room}")
            return
        
        if room not in self._room_keys:
            # First time: store the room key
            self._room_keys[room] = encrypted_key
            log.info(f"Room key stored for #{room} by {peer.nick}")
            log.info(f"Stored key value: {encrypted_key}")
            
            # Broadcast to all current members (including sender for confirmation)
            payload = encode_json_payload({
                "room": room,
                "from": peer.nick,
                "encrypted_key": encrypted_key,
            })
            key_frame = build_frame(MessageType.ROOM_KEY, payload, self._server_identity)
            await self._broadcast_room(room, key_frame)
        else:
            # Room key already exists, ignore or update
            log.info(f"Room key already exists for #{room}, ignoring from {peer.nick}")

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
        for nick in list(self._rooms.get(room, set())):
            if nick == exclude or nick not in self._peers:
                continue
            try:
                self._peers[nick].queue.put_nowait(frame)
            except asyncio.QueueFull:
                log.warning(f"Queue full for {nick}")

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
        self._peers.pop(peer.nick, None)
        for room in peer.rooms:
            self._rooms[room].discard(peer.nick)
            notify = encode_json_payload({"event": "leave", "nick": peer.nick, "room": room})
            frame  = build_frame(MessageType.HELLO_ACK, notify, self._server_identity)
            await self._broadcast_room(room, frame)

    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> bytes:
        len_bytes = await reader.readexactly(4)
        total = struct.unpack(">I", len_bytes)[0]
        if total > MAX_FRAME_SIZE:
            raise ValueError(f"Frame too large: {total}")
        body = await reader.readexactly(total)
        return len_bytes + body

    @staticmethod
    async def _send_raw(writer: asyncio.StreamWriter, data: bytes) -> None:
        writer.write(data)
        await writer.drain()


async def main():
    parser = argparse.ArgumentParser(description="secure-term-chat relay server")
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, default=12345)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--tls", action="store_true", help="Enable TLS encryption")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    srv    = ChatServer(use_tls=args.tls)
    
    if args.tls:
        # Create SSL context for TLS server
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE  # Clients verify via fingerprinting
        
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
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Server shutting down.")
