#!/usr/bin/env python3
# client.py — Encrypted Terminal Chat Client (Textual TUI)
# pip install cryptography pynacl textual

from __future__ import annotations
import asyncio
import argparse
import json
import os
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
    InvalidTag,
)

MAX_FRAME_SIZE = 2 * 1024 * 1024


# ──────────────────────────────────────────────
# TOFU Store (RAM-only)
# ──────────────────────────────────────────────
class TOFUStore:
    """Trust On First Use — in-memory fingerprint registry."""

    def __init__(self):
        self._store: Dict[str, str] = {}  # nick -> fingerprint

    def check_or_trust(self, nick: str, identity_pub_hex: str) -> tuple[bool, bool]:
        """
        Returns (trusted: bool, new: bool).
        trusted=True if fp matches or was just added.
        """
        fp = fingerprint_from_bytes(bytes.fromhex(identity_pub_hex))
        if nick not in self._store:
            self._store[nick] = fp
            return True, True   # new entry
        return self._store[nick] == fp, False

    def get(self, nick: str) -> Optional[str]:
        return self._store.get(nick)

    def all(self) -> dict:
        return dict(self._store)


# ──────────────────────────────────────────────
# Peer Session (E2EE state per peer)
# ──────────────────────────────────────────────
class PeerSession:
    def __init__(self, nick: str, identity_pub_hex: str, session_pub_hex: str):
        self.nick = nick
        self.identity_pub = bytes.fromhex(identity_pub_hex)
        self.session_pub  = bytes.fromhex(session_pub_hex)
        self.fingerprint  = fingerprint_from_bytes(self.identity_pub)
        self._enc_key: Optional[bytes] = None
        self._ratchet_send: Optional[SymmetricRatchet] = None
        self._ratchet_recv: Optional[SymmetricRatchet] = None

    def derive_keys(self, our_session: SessionKey, salt: bytes | None = None):
        """Perform ECDH and derive session encryption key + ratchets."""
        shared = our_session.exchange(self.session_pub)
        enc_key, used_salt = derive_session_key(shared, salt)
        self._enc_key = enc_key
        self._ratchet_send = SymmetricRatchet(enc_key)
        self._ratchet_recv = SymmetricRatchet(enc_key)

    def encrypt_pm(self, plaintext: bytes) -> str:
        if self._ratchet_send is None:
            raise RuntimeError("Keys not derived")
        return self._ratchet_send.encrypt(plaintext).hex()

    def decrypt_pm(self, ct_hex: str) -> bytes:
        if self._ratchet_recv is None:
            raise RuntimeError("Keys not derived")
        return self._ratchet_recv.decrypt(bytes.fromhex(ct_hex))

    def destroy(self):
        if self._ratchet_send:
            self._ratchet_send.destroy()
        if self._ratchet_recv:
            self._ratchet_recv.destroy()


# ──────────────────────────────────────────────
# Network Client
# ──────────────────────────────────────────────
class ChatNetworkClient:
    def __init__(self, host: str, port: int, nick: str, room: str):
        self.host = host
        self.port = port
        self.nick = nick
        self.room = room

        self.identity    = IdentityKey.generate()
        self.session     = SessionKey.generate()
        self.tofu        = TOFUStore()
        self.peers: Dict[str, PeerSession] = {}
        self.replay      = AntiReplayFilter()

        # Room ratchet (group forward secrecy)
        self._room_ratchet: Optional[SymmetricRatchet] = None
        self._room_key: Optional[bytes] = None

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected  = False
        self._msg_queue: asyncio.Queue = asyncio.Queue()
        self._server_fp: Optional[str] = None

        # Offline queue for when disconnected
        self._offline_queue: deque = deque(maxlen=256)

    @property
    def fingerprint(self) -> str:
        return self.identity.fingerprint()

    # ── Connect ───────────────────────────────
    async def connect(self) -> bool:
        try:
            self._reader, self._writer = await asyncio.open_connection(
                self.host, self.port,
                limit=MAX_FRAME_SIZE + 8,
            )
            self._connected = True
        except Exception as e:
            await self._msg_queue.put({"type": "error", "msg": f"Connection failed: {e}"})
            return False

        # Send HELLO
        hello = encode_json_payload({
            "nick":         self.nick,
            "identity_pub": self.identity.public_bytes().hex(),
            "session_pub":  self.session.public_bytes().hex(),
        })
        frame = build_frame(MessageType.HELLO, hello, self.identity)
        await self._send(frame)

        # Receive HELLO_ACK
        try:
            raw = await asyncio.wait_for(self._read_frame(), timeout=15.0)
            f = parse_frame(raw)
            if f["type_id"] == MessageType.HELLO_ACK:
                info = decode_json_payload(f["payload"])
                self._server_fp = info.get("server_fp", "?")
                self.nick = info.get("your_nick", self.nick)  # server may rename on conflict
                await self._msg_queue.put({"type": "system", "msg": f"Connected! Server FP: {self._server_fp}"})
                await self._msg_queue.put({"type": "system", "msg": f"Your nick: {self.nick} | Your FP: {self.fingerprint}"})
        except asyncio.TimeoutError:
            await self._msg_queue.put({"type": "error", "msg": "Handshake timeout"})
            return False

        # Join room
        await self.join_room(self.room)
        return True

    async def join_room(self, room: str) -> None:
        self.room = room
        payload = encode_json_payload({"room": room})
        frame = build_frame(MessageType.ROOM_JOIN, payload, self.identity)
        await self._send(frame)
        # Derive room key from session key + room name (HKDF)
        shared_seed = self.session.public_bytes()  # deterministic from our session
        self._room_key, _ = derive_room_key(shared_seed, room.encode())
        self._room_ratchet = SymmetricRatchet(self._room_key)
        await self._msg_queue.put({"type": "system", "msg": f"Joined room #{room}"})

    # ── Send message ─────────────────────────
    async def send_room_message(self, text: str) -> None:
        if not self._connected or self._room_ratchet is None:
            self._offline_queue.append(("room", text))
            return
        plaintext = text.encode()
        ct = self._room_ratchet.encrypt(plaintext)
        ct_hex = ct.hex()
        audit = message_hash(ct)
        payload = encode_json_payload({
            "room":  self.room,
            "ct":    ct_hex,
            "audit": audit,
        })
        frame = build_frame(MessageType.ROOM_CHAT, payload, self.identity)
        await self._send(frame)

    async def send_pm(self, target: str, text: str) -> None:
        if target not in self.peers:
            await self._msg_queue.put({"type": "error", "msg": f"Unknown peer: {target}. Use /keys to see peers."})
            return
        peer = self.peers[target]
        ct_hex = peer.encrypt_pm(text.encode())
        payload = encode_json_payload({"to": target, "ct": ct_hex})
        frame = build_frame(MessageType.ROOM_PM, payload, self.identity)
        await self._send(frame)

    async def send_file(self, room: str, filepath: str) -> None:
        if self._room_key is None:
            return
        p = Path(filepath)
        if not p.exists():
            await self._msg_queue.put({"type": "error", "msg": f"File not found: {filepath}"})
            return
        chunks = list(encrypt_file_stream(self._room_key, filepath))
        total = len(chunks)
        for i, ct in enumerate(chunks):
            payload = encode_json_payload({
                "room":     room,
                "filename": p.name,
                "chunk_id": i,
                "total":    total,
                "ct":       ct.hex(),
            })
            frame = build_frame(MessageType.FILE_CHUNK, payload, self.identity)
            await self._send(frame)
            await asyncio.sleep(0.01)  # throttle
        await self._msg_queue.put({"type": "system", "msg": f"File sent: {p.name} ({total} chunks)"})

    # ── Receive Loop ─────────────────────────
    async def receive_loop(self) -> None:
        while self._connected:
            try:
                raw = await self._read_frame()
                await self._handle_frame(raw)
            except asyncio.IncompleteReadError:
                break
            except Exception as e:
                await self._msg_queue.put({"type": "error", "msg": f"Receive error: {e}"})
                break
        self._connected = False
        await self._msg_queue.put({"type": "system", "msg": "Disconnected from server."})

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
            pong = build_frame(MessageType.PONG, b"", self.identity)
            await self._send(pong)
        elif t == MessageType.ERROR:
            info = decode_json_payload(frame["payload"])
            await self._msg_queue.put({"type": "error", "msg": info.get("msg", "Server error")})

    async def _on_room_chat(self, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            sender = info["from"]
            ct_hex = info["ct"]
            audit  = info.get("audit", "")
        except Exception:
            return

        if sender not in self.peers or self._room_ratchet is None:
            # We don't have a ratchet for this sender in group; use room ratchet
            if self._room_ratchet is None:
                return
            try:
                # Note: group chat uses shared room key ratchet
                # In full Double Ratchet, each sender has own chain; here we use room ratchet
                pt = self.decrypt_room_message(ct_hex)
            except Exception:
                await self._msg_queue.put({"type": "error", "msg": f"[{sender}] Decrypt failed"})
                return
        else:
            try:
                pt = self.decrypt_room_message(ct_hex)
            except Exception:
                await self._msg_queue.put({"type": "error", "msg": f"[{sender}] Decrypt failed"})
                return

        await self._msg_queue.put({
            "type": "chat",
            "from": sender,
            "msg":  pt.decode(errors="replace"),
            "audit": audit,
            "room": info.get("room", self.room),
        })

    def decrypt_room_message(self, ct_hex: str) -> bytes:
        """Decrypt a room message using the room key (non-ratcheted for group simplicity)."""
        if self._room_key is None:
            raise RuntimeError("No room key")
        return decrypt_message(self._room_key, bytes.fromhex(ct_hex))

    async def _on_pm(self, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            sender = info["from"]
            ct_hex = info["ct"]
        except Exception:
            return
        if sender not in self.peers:
            await self._msg_queue.put({"type": "pm", "from": sender, "msg": "[encrypted — no session key]"})
            return
        try:
            pt = self.peers[sender].decrypt_pm(ct_hex)
            await self._msg_queue.put({"type": "pm", "from": sender, "msg": pt.decode(errors="replace")})
        except Exception as e:
            await self._msg_queue.put({"type": "error", "msg": f"PM decrypt failed from {sender}: {e}"})

    async def _on_event(self, frame: dict) -> None:
        """Handle join/leave events from server."""
        try:
            info = decode_json_payload(frame["payload"])
        except Exception:
            return
        event = info.get("event", "")
        if event == "join":
            nick = info["nick"]
            id_pub = info["identity_pub"]
            sess_pub = info["session_pub"]
            fp = info["fingerprint"]
            trusted, new = self.tofu.check_or_trust(nick, id_pub)
            status = "NEW" if new else ("OK" if trusted else "⚠ MISMATCH")
            await self._msg_queue.put({
                "type": "event",
                "msg":  f"{nick} joined #{info.get('room','?')} | FP [{status}]: {fp}",
                "trust": status,
            })
            # Register peer session
            if nick not in self.peers:
                peer_sess = PeerSession(nick, id_pub, sess_pub)
                peer_sess.derive_keys(self.session)
                self.peers[nick] = peer_sess
        elif event == "leave":
            nick = info.get("nick", "?")
            await self._msg_queue.put({"type": "event", "msg": f"{nick} left #{info.get('room','?')}"})
            if nick in self.peers:
                self.peers[nick].destroy()
                del self.peers[nick]
        elif event == "roster":
            for member in info.get("members", []):
                nick = member["nick"]
                id_pub = member["identity_pub"]
                sess_pub = member["session_pub"]
                trusted, new = self.tofu.check_or_trust(nick, id_pub)
                status = "NEW" if new else ("OK" if trusted else "⚠ MISMATCH")
                await self._msg_queue.put({
                    "type": "event",
                    "msg":  f"  {nick} | FP [{status}]: {member['fingerprint']}",
                    "trust": status,
                })
                if nick not in self.peers:
                    peer_sess = PeerSession(nick, id_pub, sess_pub)
                    peer_sess.derive_keys(self.session)
                    self.peers[nick] = peer_sess

    async def _on_user_list(self, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
        except Exception:
            return
        if info.get("event") == "roster":
            await self._on_event(frame)
            return
        members = info.get("members", [])
        lines = [f"Users in #{info.get('room', self.room)}:"]
        for m in members:
            fp = m.get("fingerprint", "?")
            lines.append(f"  {m['nick']} | FP: {fp}")
        await self._msg_queue.put({"type": "system", "msg": "\n".join(lines)})

    async def _on_key_exchange(self, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            from_nick = info.get("from", "?")
            sess_pub  = info.get("session_pub", "")
        except Exception:
            return
        if from_nick in self.peers:
            self.peers[from_nick].session_pub = bytes.fromhex(sess_pub)
            self.peers[from_nick].derive_keys(self.session)
            await self._msg_queue.put({"type": "system", "msg": f"Key refreshed for {from_nick}"})

    async def _on_file_chunk(self, frame: dict) -> None:
        try:
            info = decode_json_payload(frame["payload"])
            sender   = info["from"]
            filename = info.get("filename", "received_file")
            chunk_id = info["chunk_id"]
            total    = info["total"]
            ct_hex   = info["ct"]
        except Exception:
            return
        if self._room_key is None:
            return
        # Simple single-chunk display; full streaming would buffer
        try:
            pt = decrypt_message(self._room_key, bytes.fromhex(ct_hex))
            # Save to CWD with chunk suffix for multi-chunk files
            out_path = f"{filename}.part{chunk_id}" if total > 1 else filename
            Path(out_path).write_bytes(pt)
            await self._msg_queue.put({
                "type": "system",
                "msg":  f"File chunk {chunk_id+1}/{total} from {sender}: {out_path}"
            })
        except Exception as e:
            await self._msg_queue.put({"type": "error", "msg": f"File decrypt error: {e}"})

    # ── IO ────────────────────────────────────
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
        frame = build_frame(MessageType.DISCONNECT, b"", self.identity)
        try:
            await self._send(frame)
        except Exception:
            pass
        # Wipe keys
        self.identity.destroy()
        self.session.destroy()
        for ps in self.peers.values():
            ps.destroy()
        if self._writer:
            self._writer.close()


# ──────────────────────────────────────────────
# Textual TUI Application
# ──────────────────────────────────────────────
COLOR_SYSTEM  = "bold cyan"
COLOR_CHAT    = "white"
COLOR_PM      = "bold magenta"
COLOR_EVENT   = "bold yellow"
COLOR_ERROR   = "bold red"
COLOR_FP_OK   = "bold green"
COLOR_FP_WARN = "bold red"


class ChatApp(App):
    CSS = """
    Screen {
        background: #0d1117;
    }
    #chat-log {
        border: solid #30363d;
        height: 1fr;
        padding: 0 1;
    }
    #side-panel {
        width: 28;
        border: solid #30363d;
        padding: 0 1;
    }
    #status-bar {
        height: 3;
        border: solid #30363d;
        padding: 0 1;
        color: #8b949e;
    }
    #input-box {
        dock: bottom;
        height: 3;
        border: solid #58a6ff;
    }
    """

    def __init__(self, net: ChatNetworkClient):
        super().__init__()
        self.net = net
        self._users: List[str] = []

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
                f"[cyan]Your Nick:[/] {self.net.nick}\n"
                f"[cyan]Room:[/] #{self.net.room}\n"
                f"[cyan]Fingerprint:[/] [green]{self.net.fingerprint}[/]\n"
                f"[dim]Type /help for commands[/]"
            )
        )
        self._start_network()
        self.set_interval(0.1, self._poll_messages)

    @work(exclusive=False, thread=False)
    async def _start_network(self) -> None:
        ok = await self.net.connect()
        if ok:
            await self.net.receive_loop()

    def _poll_messages(self) -> None:
        while not self.net._msg_queue.empty():
            try:
                msg = self.net._msg_queue.get_nowait()
                self._render_message(msg)
            except Exception:
                pass

    def _render_message(self, msg: dict) -> None:
        log = self.query_one("#chat-log", RichLog)
        t = msg["type"]
        ts = time.strftime("%H:%M:%S")

        if t == "chat":
            sender = msg["from"]
            text   = msg["msg"]
            audit  = msg.get("audit", "")
            audit_tag = f" [dim]#{audit[:8]}[/]" if audit else ""
            log.write(Text.from_markup(
                f"[dim]{ts}[/] [bold white]{sender}[/]: {text}{audit_tag}"
            ))
        elif t == "pm":
            log.write(Text.from_markup(
                f"[dim]{ts}[/] [bold magenta]PM from {msg['from']}:[/] {msg['msg']}"
            ))
        elif t == "system":
            log.write(Text.from_markup(
                f"[dim]{ts}[/] [bold cyan]● {msg['msg']}[/]"
            ))
        elif t == "event":
            trust = msg.get("trust", "")
            color = "green" if trust in ("OK", "NEW") else "red"
            log.write(Text.from_markup(
                f"[dim]{ts}[/] [bold {color}]▶ {msg['msg']}[/]"
            ))
        elif t == "error":
            log.write(Text.from_markup(
                f"[dim]{ts}[/] [bold red]✗ ERROR: {msg['msg']}[/]"
            ))

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        self.query_one("#input-box", Input).value = ""

        if text.startswith("/"):
            await self._handle_command(text)
        else:
            asyncio.ensure_future(self.net.send_room_message(text))
            # Echo own message
            log = self.query_one("#chat-log", RichLog)
            ts = time.strftime("%H:%M:%S")
            log.write(Text.from_markup(
                f"[dim]{ts}[/] [bold green]{self.net.nick}[/] [dim](you)[/]: {text}"
            ))

    async def _handle_command(self, text: str) -> None:
        parts = text.split()
        cmd = parts[0].lower()
        log = self.query_one("#chat-log", RichLog)

        if cmd == "/help":
            log.write(Text.from_markup(
                "[bold cyan]Commands:[/]\n"
                "  [yellow]/join #room[/]         — Join a room\n"
                "  [yellow]/pm @user message[/]   — Send private message\n"
                "  [yellow]/keys[/]               — Show fingerprints\n"
                "  [yellow]/verify @user[/]       — Verify peer fingerprint\n"
                "  [yellow]/filesend path[/]      — Send file to current room\n"
                "  [yellow]/users[/]              — List room users\n"
                "  [yellow]/quit[/]               — Exit"
            ))
        elif cmd == "/join" and len(parts) >= 2:
            room = parts[1].lstrip("#")
            asyncio.ensure_future(self.net.join_room(room))
        elif cmd == "/pm" and len(parts) >= 3:
            target = parts[1].lstrip("@")
            msg = " ".join(parts[2:])
            asyncio.ensure_future(self.net.send_pm(target, msg))
        elif cmd == "/keys":
            lines = ["[bold cyan]Known fingerprints:[/]"]
            lines.append(f"  [green]you:[/] {self.net.fingerprint}")
            for nick, fp in self.net.tofu.all().items():
                lines.append(f"  {nick}: [yellow]{fp}[/]")
            log.write(Text.from_markup("\n".join(lines)))
        elif cmd == "/verify" and len(parts) >= 2:
            target = parts[1].lstrip("@")
            fp = self.net.tofu.get(target)
            if fp:
                log.write(Text.from_markup(
                    f"[bold cyan]Fingerprint for {target}:[/] [bold green]{fp}[/]\n"
                    f"Verify out-of-band (call/Signal) to confirm identity."
                ))
            else:
                log.write(Text.from_markup(f"[red]No fingerprint found for {target}[/]"))
        elif cmd == "/filesend" and len(parts) >= 2:
            filepath = parts[1]
            asyncio.ensure_future(self.net.send_file(self.net.room, filepath))
        elif cmd == "/users":
            payload = encode_json_payload({"room": self.net.room})
            frame = build_frame(MessageType.USER_LIST, payload, self.net.identity)
            asyncio.ensure_future(self.net._send(frame))
        elif cmd == "/quit":
            asyncio.ensure_future(self.net.disconnect())
            self.exit()
        else:
            log.write(Text.from_markup(f"[red]Unknown command: {cmd}. Type /help.[/]"))

    async def on_unmount(self) -> None:
        await self.net.disconnect()


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
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
    parser.add_argument("server", help="host:port of the relay server")
    parser.add_argument("--nick", required=True, help="Your display nickname")
    parser.add_argument("--room", default="default", help="Room to join (default: 'default')")
    args = parser.parse_args()

    try:
        host, port_str = args.server.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        print(f"Invalid server address: {args.server}. Use host:port format.")
        sys.exit(1)

    net = ChatNetworkClient(host, port, args.nick, args.room)
    app = ChatApp(net)
    app.run()


if __name__ == "__main__":
    main()
