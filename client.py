#!/usr/bin/env python3
# client.py — Encrypted Terminal Chat Client
# pip install cryptography textual

from __future__ import annotations
import asyncio
import argparse
import struct
import sys
import time
import secrets
from pathlib import Path
from typing import Dict, Optional, List
from collections import deque

from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, RichLog, Static
from textual.containers import Horizontal, Vertical
from textual import work

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
)

MAX_FRAME_SIZE = 2 * 1024 * 1024
RECONNECT_DELAY = 5.0   # seconds between reconnect attempts
RECONNECT_MAX   = 5     # max attempts


# ──────────────────────────────────────────────────
# TOFU Store (RAM-only)
# ──────────────────────────────────────────────────
class TOFUStore:
    def __init__(self):
        self._store: Dict[str, str] = {}

    def check_or_trust(self, nick: str, identity_pub_hex: str) -> tuple[bool, bool]:
        fp = fingerprint_from_bytes(bytes.fromhex(identity_pub_hex))
        if nick not in self._store:
            self._store[nick] = fp
            return True, True
        return self._store[nick] == fp, False

    def get(self, nick: str) -> Optional[str]:
        return self._store.get(nick)

    def all(self) -> dict:
        return dict(self._store)


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
    def __init__(self, host: str, port: int, nick: str, room: str):
        self.host = host
        self.port = port
        self.nick = nick
        self.room = room

        self.identity = IdentityKey.generate()
        self.session  = SessionKey.generate()
        self.tofu     = TOFUStore()
        self.peers: Dict[str, PeerSession] = {}
        self.replay   = AntiReplayFilter()
        self.files    = FileReassembler()  # FIX: file reassembly

        self._room_key: Optional[bytearray] = None

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected   = False
        self._msg_queue: asyncio.Queue = asyncio.Queue()
        self._server_fp: Optional[str] = None
        self._offline_queue: deque = deque(maxlen=256)
        self._reconnect_attempts = 0

    @property
    def fingerprint(self) -> str:
        return self.identity.fingerprint()

    # ── Connect ──────────────────────────────────────
    async def connect(self) -> bool:
        try:
            self._reader, self._writer = await asyncio.open_connection(
                self.host, self.port, limit=MAX_FRAME_SIZE + 8,
            )
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
        # FIX: room key from cryptographically random secret, NOT public key
        room_seed = secrets.token_bytes(32)
        self._room_key, _ = derive_room_key(room_seed, room.encode())
        await self._msg_queue.put({"type": "system", "msg": f"Joined #{room}"})

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
        except ValueError:
            return
        t = frame["type_id"]
        if t == MessageType.ROOM_CHAT:
            await self._on_room_chat(frame)
        elif t == MessageType.ROOM_PM:
            await self._on_pm(frame)
        elif t == MessageType.HELLO_ACK:
            await self._on_event(frame)
        elif t == MessageType.USER_LIST:
            await self._on_user_list(frame)
        elif t == MessageType.KEY_EXCHANGE:
            await self._on_key_exchange(frame)
        elif t == MessageType.FILE_CHUNK:
            await self._on_file_chunk(frame)
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
        elif event == "leave":
            nick = sanitize_nick(info.get("nick", "?"))
            await self._msg_queue.put({"type": "event", "msg": f"{nick} left #{info.get('room','?')}"})
            if nick in self.peers:
                self.peers[nick].destroy()
                del self.peers[nick]

    async def _on_user_list(self, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
        except Exception:
            return
        if info.get("event") in ("roster", "join"):
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

    async def _on_file_chunk(self, frame: dict) -> None:
        """FIX: proper multi-chunk reassembly."""
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
        complete = self.files.add_chunk(sender, filename, chunk_id, total, pt)
        if complete is not None:
            out_path = Path(filename)
            out_path.write_bytes(complete)
            await self._msg_queue.put({
                "type": "system",
                "msg":  f"✓ File received from {sender}: {filename} ({len(complete):,} bytes)"
            })
        else:
            await self._msg_queue.put({
                "type": "system",
                "msg":  f"File chunk {chunk_id+1}/{total} from {sender}: {filename}"
            })

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
    """

    def __init__(self, net: ChatNetworkClient):
        super().__init__()
        self.net = net

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="main-col"):
                yield RichLog(id="chat-log", markup=True, highlight=True)
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
        self._start_network()
        self.set_interval(0.1, self._poll_messages)

    @work(exclusive=False, thread=False)
    async def _start_network(self) -> None:
        # FIX: wrap in try/except to surface errors in UI instead of silently swallowing
        try:
            ok = await self.net.connect()
            if ok:
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
        elif t == "error":
            log.write(Text.from_markup(f"[dim]{ts}[/] [bold red]✗ {msg['msg']}[/]"))

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
            log.write(Text.from_markup(
                "[bold cyan]Commands:[/]\n"
                "  [yellow]/join #room[/]         — Join a room\n"
                "  [yellow]/pm @user message[/]   — Send private message (E2EE ratchet)\n"
                "  [yellow]/keys[/]               — Show all fingerprints (TOFU)\n"
                "  [yellow]/verify @user[/]       — Show peer fingerprint for OOB check\n"
                "  [yellow]/filesend path[/]      — Send encrypted file to room\n"
                "  [yellow]/users[/]              — List room users\n"
                "  [yellow]/quit[/]               — Exit & wipe keys"
            ))
        elif cmd == "/join" and len(parts) >= 2:
            asyncio.create_task(self.net.join_room(parts[1].lstrip("#")))
        elif cmd == "/pm" and len(parts) >= 3:
            target = parts[1].lstrip("@")
            asyncio.create_task(self.net.send_pm(target, " ".join(parts[2:])))
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

    async def on_unmount(self) -> None:
        await self.net.disconnect()


# ──────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="secure-term-chat — E2EE encrypted terminal chat",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python client.py localhost:12345 --nick Alice --room default
  python client.py 192.168.1.10:12345 --nick Bob --room crypto
"""
    )
    parser.add_argument("server", help="host:port")
    parser.add_argument("--nick", required=True)
    parser.add_argument("--room", default="default")
    args = parser.parse_args()
    try:
        host, port_str = args.server.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        print(f"Invalid address: {args.server}")
        sys.exit(1)
    ChatApp(ChatNetworkClient(host, port, args.nick, args.room)).run()


if __name__ == "__main__":
    main()
