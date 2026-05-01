#!/usr/bin/env python3
# server.py — Discovery & Relay Server for secure-term-chat
# Handles: room management, peer discovery, relay of encrypted blobs.
# Does NOT decrypt anything — operates on opaque ciphertext.
# pip install cryptography

from __future__ import annotations
import asyncio
import argparse
import json
import logging
import secrets
import struct
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from utils import (
    MessageType, parse_frame, build_frame, encode_json_payload,
    decode_json_payload, IdentityKey, verify_external,
    fingerprint_from_bytes, AntiReplayFilter,
)

# ──────────────────────────────────────────────
# Logging (no message content logged — privacy)
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("server")

# ──────────────────────────────────────────────
# Rate Limiting
# ──────────────────────────────────────────────
RATE_WINDOW     = 5.0   # seconds
RATE_MAX_MSGS   = 30    # max messages per window
MAX_QUEUE_SIZE  = 512
MAX_FRAME_SIZE  = 2 * 1024 * 1024  # 2 MB


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


# ──────────────────────────────────────────────
# Client Peer representation
# ──────────────────────────────────────────────
@dataclass
class Peer:
    nick: str
    identity_pub: bytes        # Ed25519 raw public key
    session_pub: bytes         # X25519 raw public key (ephemeral)
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
            "nick": self.nick,
            "identity_pub": self.identity_pub.hex(),
            "session_pub":  self.session_pub.hex(),
            "fingerprint":  self.fingerprint,
        }


# ──────────────────────────────────────────────
# Server State
# ──────────────────────────────────────────────
class ChatServer:
    def __init__(self):
        self._peers: Dict[str, Peer] = {}   # nick -> Peer
        self._rooms: Dict[str, Set[str]] = defaultdict(set)  # room -> {nicks}
        self._server_identity = IdentityKey.generate()
        log.info(f"Server fingerprint: {self._server_identity.fingerprint()}")

    # ── Connection Handling ────────────────────
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername", ("?", 0))
        addr_str = f"{addr[0]}:{addr[1]}"
        log.info(f"New connection from {addr_str}")
        peer: Optional[Peer] = None

        try:
            peer = await self._do_handshake(reader, writer, addr_str)
            if peer is None:
                return
            asyncio.ensure_future(self._writer_loop(peer))
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
        """Expect HELLO frame, register peer."""
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
            log.warning(f"Expected HELLO, got {frame['type_id']} from {addr_str}")
            return None

        try:
            hello = decode_json_payload(frame["payload"])
            nick         = hello["nick"][:32]  # truncate
            identity_pub = bytes.fromhex(hello["identity_pub"])
            session_pub  = bytes.fromhex(hello["session_pub"])
        except (KeyError, ValueError) as e:
            log.warning(f"Bad HELLO payload: {e}")
            return None

        # Verify signature on HELLO
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
        log.info(f"Peer registered: {nick} | fp={peer.fingerprint}")

        # Send HELLO_ACK with server fingerprint and room list
        ack_payload = encode_json_payload({
            "server_fp":    self._server_identity.fingerprint(),
            "server_id_pub": self._server_identity.public_bytes().hex(),
            "rooms":        list(self._rooms.keys()),
            "your_nick":    nick,
        })
        ack_frame = build_frame(MessageType.HELLO_ACK, ack_payload, self._server_identity)
        await self._send_raw(writer, ack_frame)
        return peer

    # ── Read Loop ─────────────────────────────
    async def _reader_loop(self, peer: Peer) -> None:
        while True:
            raw = await self._read_frame(peer.reader)
            if not raw:
                break
            if len(raw) > MAX_FRAME_SIZE:
                log.warning(f"Oversized frame from {peer.nick}, dropping")
                continue
            if not peer.rate_limiter.allow():
                log.warning(f"Rate limit hit for {peer.nick}")
                continue

            try:
                frame = parse_frame(raw)
            except ValueError:
                continue

            # Anti-replay check
            if not peer.replay_filter.check(frame["nonce_id"], frame["timestamp"]):
                log.warning(f"Replay/stale frame from {peer.nick}")
                continue

            # Verify signature (for authenticated frames)
            if frame["type_id"] not in (MessageType.PING, MessageType.PONG):
                if not verify_external(peer.identity_pub, frame["signature"], frame["raw_body"]):
                    log.warning(f"Bad sig from {peer.nick}")
                    continue

            await self._dispatch(peer, frame, raw)

    async def _dispatch(self, peer: Peer, frame: dict, raw: bytes) -> None:
        t = frame["type_id"]
        if t == MessageType.ROOM_JOIN:
            await self._handle_join(peer, frame)
        elif t == MessageType.ROOM_CHAT:
            await self._relay_room(peer, frame, raw)
        elif t == MessageType.ROOM_PM:
            await self._relay_pm(peer, frame)
        elif t == MessageType.KEY_EXCHANGE:
            await self._relay_key_exchange(peer, frame)
        elif t == MessageType.ROOM_LIST:
            await self._send_room_list(peer)
        elif t == MessageType.USER_LIST:
            await self._send_user_list(peer, frame)
        elif t == MessageType.PING:
            pong = build_frame(MessageType.PONG, b"", self._server_identity)
            await peer.queue.put(pong)
        elif t == MessageType.DISCONNECT:
            raise ConnectionResetError("client disconnect")
        elif t == MessageType.FILE_CHUNK:
            await self._relay_file_chunk(peer, frame, raw)

    # ── Room Handling ─────────────────────────
    async def _handle_join(self, peer: Peer, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            room = info["room"][:64]
        except Exception:
            return

        peer.rooms.add(room)
        self._rooms[room].add(peer.nick)
        log.info(f"{peer.nick} joined room #{room}")

        # Notify others in room
        notify = encode_json_payload({
            "event": "join",
            "nick": peer.nick,
            "room": room,
            "identity_pub": peer.identity_pub.hex(),
            "session_pub":  peer.session_pub.hex(),
            "fingerprint":  peer.fingerprint,
        })
        notify_frame = build_frame(MessageType.HELLO_ACK, notify, self._server_identity)
        await self._broadcast_room(room, notify_frame, exclude=peer.nick)

        # Send current room members to joiner
        members = [
            self._peers[n].to_info()
            for n in self._rooms[room]
            if n != peer.nick and n in self._peers
        ]
        roster = encode_json_payload({"event": "roster", "room": room, "members": members})
        roster_frame = build_frame(MessageType.USER_LIST, roster, self._server_identity)
        await peer.queue.put(roster_frame)

    async def _relay_room(self, peer: Peer, frame: dict, raw_frame: bytes) -> None:
        """Relay encrypted blob to all members of a room. Server sees only ciphertext."""
        try:
            info = decode_json_payload(frame["payload"])
            room = info.get("room", "")
            # The actual message is in info["ct"] — we never touch it
        except Exception:
            return
        if room not in peer.rooms:
            return
        # Re-sign with server key for relay authenticity
        relay_payload = encode_json_payload({
            "from":  peer.nick,
            "room":  room,
            "ct":    info.get("ct", ""),   # opaque ciphertext
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
        target = self._peers[target_nick]
        relay = encode_json_payload({
            "from": peer.nick,
            "to":   target_nick,
            "ct":   info.get("ct", ""),
        })
        relay_frame = build_frame(MessageType.ROOM_PM, relay, self._server_identity)
        await target.queue.put(relay_frame)

    async def _relay_key_exchange(self, peer: Peer, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            target = info["to"]
        except Exception:
            return
        if target in self._peers:
            fwd = build_frame(MessageType.KEY_EXCHANGE, frame["payload"], self._server_identity)
            await self._peers[target].queue.put(fwd)

    async def _relay_file_chunk(self, peer: Peer, frame: dict, raw: bytes) -> None:
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
            "filename": info.get("filename", "unknown"),
            "chunk_id": info.get("chunk_id", 0),
            "total":    info.get("total", 1),
            "ct":       info.get("ct", ""),
        })
        relay_frame = build_frame(MessageType.FILE_CHUNK, relay, self._server_identity)
        await self._broadcast_room(room, relay_frame, exclude=peer.nick)

    async def _send_room_list(self, peer: Peer) -> None:
        payload = encode_json_payload({
            "rooms": [
                {"name": r, "count": len(members)}
                for r, members in self._rooms.items()
            ]
        })
        frame = build_frame(MessageType.ROOM_LIST, payload, self._server_identity)
        await peer.queue.put(frame)

    async def _send_user_list(self, peer: Peer, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            room = info.get("room", "")
        except Exception:
            room = ""
        nicks = list(self._rooms.get(room, set()))
        members = [self._peers[n].to_info() for n in nicks if n in self._peers]
        payload = encode_json_payload({"room": room, "members": members})
        resp = build_frame(MessageType.USER_LIST, payload, self._server_identity)
        await peer.queue.put(resp)

    # ── Broadcast ────────────────────────────
    async def _broadcast_room(self, room: str, frame: bytes, exclude: str = "") -> None:
        for nick in list(self._rooms.get(room, set())):
            if nick == exclude or nick not in self._peers:
                continue
            try:
                self._peers[nick].queue.put_nowait(frame)
            except asyncio.QueueFull:
                log.warning(f"Queue full for {nick}, dropping message")

    # ── Writer Loop ───────────────────────────
    async def _writer_loop(self, peer: Peer) -> None:
        while True:
            try:
                frame = await asyncio.wait_for(peer.queue.get(), timeout=30.0)
                await self._send_raw(peer.writer, frame)
            except asyncio.TimeoutError:
                # Send ping to keep alive
                ping = build_frame(MessageType.PING, b"", self._server_identity)
                await self._send_raw(peer.writer, ping)
            except Exception:
                break

    # ── Disconnect ────────────────────────────
    async def _disconnect_peer(self, peer: Peer) -> None:
        log.info(f"Peer disconnected: {peer.nick}")
        self._peers.pop(peer.nick, None)
        for room in peer.rooms:
            self._rooms[room].discard(peer.nick)
            notify = encode_json_payload({
                "event": "leave",
                "nick": peer.nick,
                "room": room,
            })
            frame = build_frame(MessageType.HELLO_ACK, notify, self._server_identity)
            await self._broadcast_room(room, frame)

    # ── IO Helpers ────────────────────────────
    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> bytes:
        """Read a length-prefixed frame."""
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


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser(description="secure-term-chat relay server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=12345, help="Bind port")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    srv = ChatServer()
    server = await asyncio.start_server(
        srv.handle_client,
        args.host,
        args.port,
        limit=MAX_FRAME_SIZE + 8,
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.info(f"secure-term-chat server listening on {addrs}")
    log.info("Server fingerprint: " + srv._server_identity.fingerprint())
    log.info("RAM-only mode: no persistence, no logs of message content.")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Server shutting down.")
