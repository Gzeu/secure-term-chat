#!/usr/bin/env python3
"""
Modern Terminal UI for secure-term-chat
Professional, feature-rich, and visually impressive interface
"""

import asyncio
import time
from typing import Optional, List, Dict, Union
from enum import Enum
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, RichLog, Input, Button,
    Label, Switch, Checkbox, Select,
    TabPane, TabbedContent,
)
from textual.reactive import reactive
from textual.binding import Binding
from textual.screen import ModalScreen
from rich.text import Text
from rich.table import Table
from rich.rule import Rule

# Import existing client
from client import ChatNetworkClient
from encrypted_keystore import EncryptedKeystore, create_keystore, load_keystore, verify_keystore_password
from p2p_manager import P2PManager, P2PState, create_p2p_manager, is_p2p_available
from performance_monitor import MetricsCollector, AlertManager, create_metrics_collector, create_alert_manager
from room_manager import RoomManager, RoomType, create_room_manager
from file_transfer import FileTransferManager, create_file_transfer_manager
from user_manager import UserManager, create_user_manager
from audit_compliance import AuditManager, AuditEventType, SeverityLevel, create_audit_manager


class UIState(Enum):
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class ChatMessage:
    """Enhanced message with rich formatting"""

    def __init__(self, sender: str, content: str, msg_type: str = "chat",
                 timestamp: float = None, room: str = "", metadata: dict = None):
        self.sender = sender
        self.content = content
        self.type = msg_type
        self.timestamp = timestamp or time.time()
        self.room = room
        self.metadata = metadata or {}

    def to_rich_text(self) -> Text:
        time_str = time.strftime("%H:%M", time.localtime(self.timestamp))
        configs = {
            "chat": {
                "prefix": f"[dim #4d5566]{time_str}[/] ",
                "sender": f"[bold {'#79c0ff' if self.sender == 'You' else '#e6edf3'}]{self.sender}[/] ",
                "content": f"[#cdd9e5]{self.content}[/]",
            },
            "pm": {
                "prefix": f"[dim #4d5566]{time_str}[/] ",
                "sender": "[bold #f0883e]💬 PM[/] ",
                "content": f"[#f0883e]{self.sender}: {self.content}[/]",
            },
            "system": {
                "prefix": f"[dim #4d5566]{time_str}[/] ",
                "sender": "[#8b949e]",
                "content": f"[#8b949e]{self.content}[/]",
            },
            "error": {
                "prefix": f"[dim #4d5566]{time_str}[/] ",
                "sender": "[bold #f85149]✗ [/]",
                "content": f"[#f85149]{self.content}[/]",
            },
            "success": {
                "prefix": f"[dim #4d5566]{time_str}[/] ",
                "sender": "[bold #3fb950]✓ [/]",
                "content": f"[#3fb950]{self.content}[/]",
            },
            "warning": {
                "prefix": f"[dim #4d5566]{time_str}[/] ",
                "sender": "[bold #d29922]⚠ [/]",
                "content": f"[#d29922]{self.content}[/]",
            },
            "event": {
                "prefix": f"[dim #4d5566]{time_str}[/] ",
                "sender": "[dim #6e7681]─ [/]",
                "content": f"[dim #6e7681]{self.content}[/]",
            },
        }
        cfg = configs.get(self.type, configs["system"])
        return Text.assemble(cfg["prefix"], cfg["sender"], cfg["content"])


# ─── Modals ───────────────────────────────────────────────────────────────────

class PasswordSetupModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        with Container(id="modal-box"):
            yield Static("🔐  Setup Keystore Password", classes="modal-title")
            yield Static("Protect your identity keys with a strong password.", classes="modal-subtitle")
            yield Label("Password", classes="field-label")
            yield Input(placeholder="Enter strong password…", password=True, id="password-input")
            yield Label("Confirm Password", classes="field-label")
            yield Input(placeholder="Repeat password…", password=True, id="confirm-password-input")
            yield Label("Key Derivation Function", classes="field-label")
            yield Select(
                [("Argon2  (Recommended)", "argon2"), ("bcrypt", "bcrypt"), ("PBKDF2", "pbkdf2")],
                value="argon2", id="kdf-select",
            )
            with Horizontal(classes="modal-actions"):
                yield Button("Setup", variant="primary", id="setup-btn")
                yield Button("Cancel", id="cancel-btn", classes="btn-ghost")


class PasswordModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        with Container(id="modal-box"):
            yield Static("🔐  Unlock Keystore", classes="modal-title")
            yield Static("Enter your keystore password to unlock identity keys.", classes="modal-subtitle")
            yield Label("Password", classes="field-label")
            yield Input(placeholder="Enter password…", password=True, id="password-input")
            with Horizontal(classes="modal-actions"):
                yield Button("Unlock", variant="primary", id="unlock-btn")
                yield Button("Cancel", id="cancel-btn", classes="btn-ghost")


class ConnectionModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        with Container(id="modal-box"):
            yield Static("🔗  Connect to Server", classes="modal-title")
            yield Label("Server Address", classes="field-label")
            yield Input(placeholder="localhost:12345", id="server-input")
            yield Label("Nickname", classes="field-label")
            yield Input(placeholder="YourNickname", id="nick-input")
            yield Label("Room", classes="field-label")
            yield Input(placeholder="#general", id="room-input")
            yield Label("Security", classes="field-label")
            with Horizontal(classes="checkbox-row"):
                yield Checkbox("Use TLS", value=True, id="tls-checkbox")
                yield Checkbox("Advanced Security", value=False, id="advanced-checkbox")
            with Horizontal(classes="modal-actions"):
                yield Button("Connect", variant="primary", id="connect-btn")
                yield Button("Cancel", id="cancel-btn", classes="btn-ghost")


class SettingsModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        with Container(id="modal-box", classes="modal-wide"):
            yield Static("⚙️  Settings", classes="modal-title")
            with TabbedContent():
                with TabPane("Appearance", id="appearance-tab"):
                    yield Label("Theme", classes="field-label")
                    yield Select(
                        [("Dark (GitHub)", "dark"), ("Light", "light"), ("Auto", "auto")],
                        value="dark", id="theme-select",
                    )
                    yield Label("Timestamps", classes="field-label")
                    yield Switch(value=True, id="timestamps-switch")
                    yield Label("Animations", classes="field-label")
                    yield Switch(value=True, id="animations-switch")
                with TabPane("Security", id="security-tab"):
                    yield Label("End-to-End Encryption", classes="field-label")
                    yield Switch(value=True, id="encryption-switch")
                    yield Label("Forward Secrecy", classes="field-label")
                    yield Switch(value=True, id="forward-secrecy-switch")
                    yield Label("P2P Mode", classes="field-label")
                    yield Switch(value=False, id="p2p-switch")
                    yield Label("Ephemeral Messages", classes="field-label")
                    yield Switch(value=False, id="ephemeral-switch")
                    yield Label("Default TTL (hours)", classes="field-label")
                    yield Input(placeholder="24", id="ttl-input")
                with TabPane("Notifications", id="notifications-tab"):
                    yield Label("Message Notifications", classes="field-label")
                    yield Switch(value=True, id="message-notifications")
                    yield Label("User Join / Leave", classes="field-label")
                    yield Switch(value=True, id="user-notifications")
                    yield Label("Sound Alerts", classes="field-label")
                    yield Switch(value=False, id="sound-alerts")
                with TabPane("Advanced", id="advanced-tab"):
                    yield Label("Debug Mode", classes="field-label")
                    yield Switch(value=False, id="debug-switch")
                    yield Label("Performance Monitoring", classes="field-label")
                    yield Switch(value=True, id="monitoring-switch")
                    yield Label("Auto-reconnect", classes="field-label")
                    yield Switch(value=True, id="auto-reconnect-switch")
                    yield Label("Max File Size (MB)", classes="field-label")
                    yield Input(placeholder="10", id="max-file-size")
            with Horizontal(classes="modal-actions"):
                yield Button("Save", variant="primary", id="save-settings")
                yield Button("Reset", id="reset-settings", classes="btn-ghost")
                yield Button("Cancel", id="cancel-settings", classes="btn-ghost")


# ─── Widgets ──────────────────────────────────────────────────────────────────

class StatusBar(Static):
    """Compact status bar rendered as Rich markup."""

    state = reactive(UIState.DISCONNECTED)
    server_info = reactive("")
    user_info = reactive("")
    room_info = reactive("")
    message_count = reactive(0)
    p2p_status = reactive(P2PState.DISCONNECTED)
    p2p_peers = reactive(0)

    def __init__(self):
        super().__init__()
        self.start_time = time.time()

    def render(self) -> str:
        state_map = {
            UIState.CONNECTING:   ("● Connecting",   "#d29922"),
            UIState.CONNECTED:    ("● Connected",    "#3fb950"),
            UIState.DISCONNECTED: ("● Disconnected", "#4d5566"),
            UIState.ERROR:        ("● Error",        "#f85149"),
        }
        p2p_map = {
            P2PState.CONNECTING:   ("P2P…",    "#d29922"),
            P2PState.CONNECTED:    ("P2P ON",  "#3fb950"),
            P2PState.DISCONNECTED: ("P2P OFF", "#4d5566"),
            P2PState.FAILED:       ("P2P ERR", "#f85149"),
            P2PState.FALLBACK:     ("Relay",   "#d29922"),
        }
        s_text, s_color = state_map.get(self.state, ("● Unknown", "#4d5566"))
        p_text, p_color = p2p_map.get(self.p2p_status, ("P2P ?", "#4d5566"))

        uptime = int(time.time() - self.start_time)
        up_str = f"{uptime // 60:02d}:{uptime % 60:02d}"

        parts = [f"[bold {s_color}]{s_text}[/]"]
        if self.server_info:
            parts.append(f"[#8b949e] {self.server_info}[/]")
        if self.user_info:
            parts.append(f"[#79c0ff] {self.user_info}[/]")
        if self.room_info:
            parts.append(f"[#e6edf3] #{self.room_info.lstrip('#')}[/]")
        parts.append(f"[{p_color}] {p_text}{'  ' + str(self.p2p_peers) if self.p2p_peers else ''}[/]")
        if self.message_count:
            parts.append(f"[#4d5566] {self.message_count} msgs[/]")
        parts.append(f"[dim #4d5566] {up_str}[/]")

        return "  ".join(parts)


class UserListPanel(Static):
    """User list rendered as a compact Rich table."""

    def __init__(self):
        super().__init__()
        self.users: Dict[str, Dict] = {}

    def add_user(self, nick: str, fingerprint: str, status: str = "online"):
        self.users[nick] = {
            "nick": nick,
            "fingerprint": fingerprint,
            "status": status,
            "last_seen": time.time(),
        }
        self.refresh()

    def remove_user(self, nick: str):
        if nick in self.users:
            del self.users[nick]
            self.refresh()

    def update_user_status(self, nick: str, status: str):
        if nick in self.users:
            self.users[nick]["status"] = status
            self.users[nick]["last_seen"] = time.time()
            self.refresh()

    def render(self) -> Union[str, Table]:
        if not self.users:
            return "[dim #4d5566]  no users online[/]"

        table = Table(show_header=True, box=None, padding=(0, 1), expand=True)
        table.add_column("", width=1, no_wrap=True)
        table.add_column("Nick", style="#e6edf3", no_wrap=True)
        table.add_column("FP", style="#4d5566", no_wrap=True)
        table.add_column("Seen", style="#4d5566", no_wrap=True, justify="right")

        status_dot = {"online": "[#3fb950]●[/]", "away": "[#d29922]●[/]",
                      "busy": "[#f85149]●[/]", "offline": "[#4d5566]●[/]"}

        for nick, info in sorted(self.users.items(),
                                 key=lambda u: (u[1]["status"] != "online", u[0].lower())):
            dot = status_dot.get(info["status"], "?")
            fp = info["fingerprint"][:6] + "…" if len(info["fingerprint"]) > 6 else info["fingerprint"]
            age = int(time.time() - info["last_seen"])
            seen = "now" if age < 60 else (f"{age // 60}m" if age < 3600 else f"{age // 3600}h")
            table.add_row(dot, nick, fp, seen)

        return table


class ChatPanel(RichLog):
    """Chat area backed by RichLog for proper scrolling & rich rendering."""

    def __init__(self):
        super().__init__(highlight=False, markup=True, wrap=True, id="chat-log")
        self.max_messages = 2000

    def add_message(self, message: ChatMessage):
        self.write(message.to_rich_text())

    def clear_messages(self):
        self.clear()


# ─── Main App ─────────────────────────────────────────────────────────────────

class ModernChatApp(App):
    """secure-term-chat — GitHub-dark terminal UI"""

    TITLE = "secure-term-chat"
    SUB_TITLE = "end-to-end encrypted"

    CSS = """
    /* ── Base ── */
    Screen {
        background: #0d1117;
    }

    /* ── Layout ── */
    #main-layout {
        layout: horizontal;
        height: 1fr;
    }

    /* ── Left: chat + input ── */
    #chat-column {
        layout: vertical;
        width: 1fr;
        height: 100%;
    }

    #room-header {
        height: 1;
        background: #161b22;
        padding: 0 1;
        color: #8b949e;
        border-bottom: solid #21262d;
    }

    #chat-log {
        height: 1fr;
        background: #0d1117;
        padding: 0 1;
        border: none;
        scrollbar-color: #21262d #0d1117;
        scrollbar-background: #0d1117;
        scrollbar-corner-color: #0d1117;
    }

    #input-bar {
        height: 3;
        layout: horizontal;
        background: #161b22;
        border-top: solid #21262d;
        padding: 0 1;
        align: left middle;
    }

    #message-input {
        width: 1fr;
        background: #0d1117;
        border: solid #21262d;
        color: #cdd9e5;
        height: 1;
    }
    #message-input:focus {
        border: solid #388bfd;
        background: #0d1117;
    }

    #send-btn {
        width: 8;
        min-width: 8;
        height: 1;
        margin-left: 1;
        background: #238636;
        color: #ffffff;
        border: none;
    }
    #send-btn:hover {
        background: #2ea043;
    }

    /* ── Right: sidebar ── */
    #sidebar {
        width: 24;
        layout: vertical;
        background: #161b22;
        border-left: solid #21262d;
    }

    #sidebar-users-header {
        height: 1;
        background: #21262d;
        padding: 0 1;
        color: #8b949e;
    }

    #user-list {
        height: 1fr;
        padding: 1 1;
        overflow-y: auto;
        scrollbar-color: #21262d #161b22;
        scrollbar-background: #161b22;
    }

    #sidebar-status-header {
        height: 1;
        background: #21262d;
        padding: 0 1;
        color: #8b949e;
    }

    #status-bar {
        height: auto;
        padding: 1 1;
        background: #161b22;
        layout: vertical;
    }

    /* ── Header / Footer ── */
    Header {
        background: #161b22;
        color: #e6edf3;
        border-bottom: solid #21262d;
        text-style: bold;
    }
    Footer {
        background: #0d1117;
        color: #4d5566;
        border-top: solid #21262d;
    }

    /* ── Modals ── */
    ModalScreen {
        align: center middle;
        background: rgba(0,0,0,0.6);
    }

    #modal-box {
        background: #161b22;
        border: solid #30363d;
        border-title-color: #388bfd;
        padding: 2 3;
        width: 60;
        height: auto;
        max-height: 80vh;
    }
    #modal-box.modal-wide {
        width: 80;
    }

    .modal-title {
        text-align: center;
        text-style: bold;
        color: #e6edf3;
        margin-bottom: 0;
    }
    .modal-subtitle {
        text-align: center;
        color: #8b949e;
        margin-bottom: 1;
    }

    .field-label {
        color: #8b949e;
        margin: 1 0 0 0;
    }

    Input {
        background: #0d1117;
        border: solid #30363d;
        color: #cdd9e5;
        margin-bottom: 0;
    }
    Input:focus {
        border: solid #388bfd;
    }
    Select {
        background: #0d1117;
        border: solid #30363d;
        color: #cdd9e5;
        margin-bottom: 0;
    }

    .checkbox-row {
        height: 3;
        margin: 1 0;
    }

    .modal-actions {
        margin-top: 2;
        height: 3;
        align: right middle;
    }

    Button {
        margin-left: 1;
    }
    Button.btn-ghost {
        background: #21262d;
        color: #cdd9e5;
        border: solid #30363d;
    }
    Button.btn-ghost:hover {
        background: #30363d;
    }

    /* ── Utility ── */
    .hidden { display: none; }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit"),
        Binding("ctrl+s", "settings", "Settings"),
        Binding("ctrl+n", "connect", "Connect"),
        Binding("ctrl+l", "clear", "Clear"),
        Binding("ctrl+h", "help", "Help"),
        Binding("ctrl+r", "room_list", "Rooms"),
        Binding("ctrl+u", "user_list", "Users"),
        Binding("f1", "toggle_side_panel", "Panel"),
        Binding("escape", "dismiss_modal", "Close"),
    ]

    def __init__(self):
        super().__init__()
        self.net: Optional[ChatNetworkClient] = None
        self.keystore: Optional[EncryptedKeystore] = None
        self.keystore_password: Optional[str] = None
        self.keystore_dir = Path.home() / ".secure-term-chat"
        self.p2p_manager: Optional[P2PManager] = None
        self.p2p_enabled = is_p2p_available()
        self.metrics_collector: Optional[MetricsCollector] = None
        self.alert_manager: Optional[AlertManager] = None
        self.performance_enabled = True
        self.room_manager: Optional[RoomManager] = None
        self.room_management_enabled = True
        self.file_transfer_manager: Optional[FileTransferManager] = None
        self.file_transfer_enabled = True
        self.user_manager: Optional[UserManager] = None
        self.user_management_enabled = True
        self.audit_manager: Optional[AuditManager] = None
        self.audit_compliance_enabled = True
        self.chat_panel = ChatPanel()
        self.user_list = UserListPanel()
        self.status_bar = StatusBar()
        self.side_panel_visible = True
        # FIX: track connecting state to prevent update_status() from overwriting it
        self._connecting = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-layout"):
            # Chat column
            with Vertical(id="chat-column"):
                yield Static(" #general", id="room-header")
                yield self.chat_panel
                with Horizontal(id="input-bar"):
                    yield Input(placeholder="Message…  /help for commands", id="message-input")
                    yield Button("Send", variant="primary", id="send-btn")
            # Sidebar
            with Vertical(id="sidebar"):
                yield Static(" Users", id="sidebar-users-header")
                yield self.user_list
                yield Static(" Status", id="sidebar-status-header")
                with Vertical(id="status-bar"):
                    yield self.status_bar
        yield Footer()

    def on_mount(self) -> None:
        boot_ok: List[str] = []
        boot_err: List[str] = []

        def _init(label: str, fn):
            try:
                fn()
                boot_ok.append(label)
            except Exception as e:
                boot_err.append(f"{label}: {e}")

        _init("rooms", self._initialize_room_management_silent)
        _init("file-transfer", self._initialize_file_transfer_silent)
        _init("user-mgmt", self._initialize_user_management_silent)
        _init("audit", self._initialize_audit_compliance_silent)
        _init("monitoring", self._initialize_performance_monitoring_silent)

        # Single grouped boot message
        if boot_ok:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"Subsystems ready: {', '.join(boot_ok)}",
                "success",
            ))
        for err in boot_err:
            self.chat_panel.add_message(ChatMessage("System", f"Init error — {err}", "error"))

        self.chat_panel.add_message(ChatMessage(
            "System",
            "Welcome to secure-term-chat!  Ctrl+N to connect · Ctrl+H for help.",
            "success",
        ))

        self._check_keystore_status()

        # FIX: use call_after_refresh so focus lands after any modal is pushed
        self.call_after_refresh(self._focus_input)

        self.set_interval(1.0, self.update_status)
        self.set_interval(5.0, self.update_ui)
        self.set_interval(10.0, self.update_performance_metrics)

    def _focus_input(self) -> None:
        try:
            self.set_focus(self.query_one("#message-input", Input))
        except Exception:
            pass

    # ── Silent initializers (no individual chat messages) ─────────────────────

    def _initialize_room_management_silent(self) -> None:
        if self.room_management_enabled:
            self.room_manager = create_room_manager()

    def _initialize_file_transfer_silent(self) -> None:
        if self.file_transfer_enabled:
            self.file_transfer_manager = create_file_transfer_manager()

    def _initialize_user_management_silent(self) -> None:
        if self.user_management_enabled:
            self.user_manager = create_user_manager()

    def _initialize_audit_compliance_silent(self) -> None:
        if self.audit_compliance_enabled:
            self.audit_manager = create_audit_manager()

    def _initialize_performance_monitoring_silent(self) -> None:
        if self.performance_enabled:
            self.metrics_collector = create_metrics_collector(interval=1.0)
            self.alert_manager = create_alert_manager()
            self._setup_performance_alerts()
            asyncio.create_task(self.metrics_collector.start_collection())

    # ── Keystore ──────────────────────────────────────────────────────────────

    def _check_keystore_status(self) -> None:
        keystore_path = self.keystore_dir / "secure_keystore.json"
        if keystore_path.exists():
            self.chat_panel.add_message(ChatMessage("System", "Keystore detected — enter password to unlock.", "system"))
            self.push_screen(PasswordModal())
        else:
            self.chat_panel.add_message(ChatMessage("System", "No keystore found — set up a password to protect your identity.", "system"))
            self.push_screen(PasswordSetupModal())

    async def setup_keystore(self, password: str, confirm_password: str, kdf: str) -> bool:
        try:
            if password != confirm_password:
                self.chat_panel.add_message(ChatMessage("System", "Passwords do not match.", "error"))
                return False
            if len(password) < 8:
                self.chat_panel.add_message(ChatMessage("System", "Password must be at least 8 characters.", "error"))
                return False
            self.keystore = create_keystore(self.keystore_dir, password, kdf)
            self.keystore_password = password
            self.chat_panel.add_message(ChatMessage("System", f"Keystore created with {kdf.upper()} key derivation.", "success"))
            return True
        except Exception as e:
            self.chat_panel.add_message(ChatMessage("System", f"Error creating keystore: {e}", "error"))
            return False

    async def unlock_keystore(self, password: str) -> bool:
        try:
            if not verify_keystore_password(self.keystore_dir, password):
                self.chat_panel.add_message(ChatMessage("System", "Invalid password.", "error"))
                return False
            self.keystore = load_keystore(self.keystore_dir, password)
            self.keystore_password = password
            self.chat_panel.add_message(ChatMessage("System", "Keystore unlocked.", "success"))
            return True
        except Exception as e:
            self.chat_panel.add_message(ChatMessage("System", f"Error unlocking keystore: {e}", "error"))
            return False

    # ── Performance ───────────────────────────────────────────────────────────

    def _setup_performance_alerts(self) -> None:
        if self.alert_manager:
            def handle_alert(alert_data):
                alert = alert_data["alert"]
                lvl = alert.level.value
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    f"{lvl.upper()}: {alert.message} ({alert_data['metric_value']:.1f})",
                    "error" if lvl in ("critical", "emergency") else "warning",
                ))
            self.alert_manager.add_alert_handler(handle_alert)

    def update_performance_metrics(self) -> None:
        if not self.metrics_collector or not self.alert_manager:
            return
        try:
            self.metrics_collector.get_current_metrics()
            if self.p2p_manager:
                self.metrics_collector.update_p2p_connections(len(self.p2p_manager.get_connected_peers()))
        except Exception as e:
            self.chat_panel.add_message(ChatMessage("System", f"Metrics update error: {e}", "error"))

    # ── Feature panels ────────────────────────────────────────────────────────

    async def open_room_management(self) -> None:
        try:
            if self.room_manager:
                from room_manager import RoomSettings
                user_id = getattr(self.net, "nickname", "user") if self.net else "user"
                settings = RoomSettings(max_members=50, allow_guests=True, enable_file_sharing=True, max_file_size_mb=10)
                room = await self.room_manager.create_room(
                    name=f"Room by {user_id}",
                    description="A test room from modern UI",
                    room_type=RoomType.PUBLIC,
                    owner_id=user_id,
                    settings=settings,
                )
                if room:
                    self.chat_panel.add_message(ChatMessage("System", f"Created room: {room.name}  (ID: {room.room_id[:8]}…)", "success"))
                    success = await self.room_manager.join_room(room.room_id, user_id)
                    if success:
                        self.chat_panel.add_message(ChatMessage("System", f"Joined room: {room.name}", "success"))
                        self.room_manager.update_room_analytics(room.room_id, message_count=1, user_id=user_id)
                else:
                    self.chat_panel.add_message(ChatMessage("System", "Failed to create room.", "error"))
            else:
                self.chat_panel.add_message(ChatMessage("System", "Room management not available.", "error"))
        except Exception as e:
            self.chat_panel.add_message(ChatMessage("System", f"Room management error: {e}", "error"))

    async def open_file_transfer(self) -> None:
        try:
            if self.file_transfer_manager:
                from file_transfer import CompressionType, EncryptionType
                test_data = (
                    b"Test file for secure-term-chat file transfer.\n"
                    b"Demonstrates security, compression, and encryption.\n"
                    b"Created at: " + str(time.ctime()).encode()
                )
                test_filename = f"test_{int(time.time())}.txt"
                success, file_id, message = await self.file_transfer_manager.upload_file(
                    test_filename, test_data,
                    getattr(self.net, "room", "test_room") if self.net else "test_room",
                    getattr(self.net, "nickname", "test_user") if self.net else "test_user",
                    compression_type=CompressionType.GZIP,
                    encryption_type=EncryptionType.AES256_GCM,
                )
                if success:
                    self.chat_panel.add_message(ChatMessage("System", f"Uploaded: {test_filename}  ({len(test_data)} B)  →  {file_id[:8]}…", "success"))
                    file_info = self.file_transfer_manager.get_file_info(file_id)
                    if file_info:
                        ratio = f"{(1 - file_info.file_size / len(test_data)):.1%}" if file_info.is_compressed else "N/A"
                        self.chat_panel.add_message(ChatMessage("System", f"Compression: {file_info.compression_type.value}  ({ratio} reduction)", "system"))
                        self.chat_panel.add_message(ChatMessage("System", f"Encryption: {file_info.encryption_type.value}", "system"))
                        dl_ok, dl_data, dl_err = await self.file_transfer_manager.download_file(
                            file_id,
                            getattr(self.net, "nickname", "test_user") if self.net else "test_user",
                        )
                        if dl_ok:
                            ok = "✓ integrity verified" if dl_data == test_data else "✗ integrity mismatch"
                            self.chat_panel.add_message(ChatMessage("System", f"Downloaded {len(dl_data)} B — {ok}", "success" if dl_data == test_data else "error"))
                        else:
                            self.chat_panel.add_message(ChatMessage("System", f"Download failed: {dl_err}", "error"))
                else:
                    self.chat_panel.add_message(ChatMessage("System", f"Upload failed: {message}", "error"))
            else:
                self.chat_panel.add_message(ChatMessage("System", "File transfer not available.", "error"))
        except Exception as e:
            self.chat_panel.add_message(ChatMessage("System", f"File transfer error: {e}", "error"))

    async def open_user_management(self) -> None:
        try:
            if self.user_manager:
                from user_manager import UserRole
                success1, user1_id = await self.user_manager.create_user(
                    "alice_admin", "alice@example.com", "secure123456",
                    "Alice Admin", "Administrator", role=UserRole.ADMIN,
                )
                success2, user2_id = await self.user_manager.create_user(
                    "bob_moderator", "bob@example.com", "secure123456",
                    "Bob Mod", "Moderator", role=UserRole.MODERATOR,
                )
                success3, user3_id = await self.user_manager.create_user(
                    "charlie_member", "charlie@example.com", "secure123456",
                    "Charlie", "Member", role=UserRole.MEMBER,
                )
                if success1 and user1_id:
                    self.chat_panel.add_message(ChatMessage("System", f"Created admin: alice_admin ({user1_id[:8]}…)", "success"))
                    ui = self.user_manager.get_user_by_id(user1_id)
                    if ui:
                        self.chat_panel.add_message(ChatMessage("System", f"Role: {ui.role.value}  ·  {len(ui.permissions)} permissions  ·  {ui.status.value}", "system"))
                    auth_ok, session_id = await self.user_manager.authenticate_user("alice_admin", "secure123456")
                    self.chat_panel.add_message(ChatMessage("System",
                        f"Auth: {'OK  · session ' + session_id[:8] + '…' if auth_ok else 'FAILED'}", "success" if auth_ok else "error"))
                if success2 and user2_id:
                    self.chat_panel.add_message(ChatMessage("System", f"Created moderator: bob_moderator ({user2_id[:8]}…)", "success"))
                if success3 and user3_id:
                    self.chat_panel.add_message(ChatMessage("System", f"Created member: charlie_member ({user3_id[:8]}…)", "success"))
                stats = self.user_manager.get_global_statistics()
                self.chat_panel.add_message(ChatMessage("System", f"Global: {stats['total_users']} users, {stats['active_users']} active", "system"))
            else:
                self.chat_panel.add_message(ChatMessage("System", "User management not available.", "error"))
        except Exception as e:
            self.chat_panel.add_message(ChatMessage("System", f"User management error: {e}", "error"))

    async def open_audit_compliance(self) -> None:
        try:
            if self.audit_manager:
                uid = getattr(self.net, "nickname", "system_user") if self.net else "system_user"
                event_id = await self.audit_manager.log_event(
                    AuditEventType.SYSTEM_CONFIG, uid,
                    "Audit system access", target_resource="audit_compliance_ui",
                    severity=SeverityLevel.INFO,
                )
                if event_id:
                    stats = self.audit_manager.get_audit_statistics()
                    self.chat_panel.add_message(ChatMessage("System",
                        f"Audit OK  ({event_id[:8]}…)  ·  {stats['total_events']} events", "success"))
                    from audit_compliance import ComplianceFramework
                    gdpr = self.audit_manager.get_compliance_summary(ComplianceFramework.GDPR)
                    self.chat_panel.add_message(ChatMessage("System", f"GDPR compliance: {gdpr['compliance_rate']:.1f}%", "system"))
                    end_t = time.time()
                    report_id = await self.audit_manager.generate_compliance_report(
                        ComplianceFramework.GDPR, end_t - 7 * 86400, end_t
                    )
                    if report_id:
                        r = self.audit_manager.reports.get(report_id)
                        self.chat_panel.add_message(ChatMessage("System",
                            f"GDPR report {report_id[:8]}…  ·  {r.violations_count} violations  ·  {r.status.value}",
                            "warning" if r and r.violations_count else "success"))
                else:
                    self.chat_panel.add_message(ChatMessage("System", "Audit access failed.", "error"))
            else:
                self.chat_panel.add_message(ChatMessage("System", "Audit not available.", "error"))
        except Exception as e:
            self.chat_panel.add_message(ChatMessage("System", f"Audit error: {e}", "error"))

    # ── P2P callbacks ─────────────────────────────────────────────────────────

    def _on_p2p_peer_connected(self, peer_id: str):
        # FIX: set CONNECTED state when a peer actually connects
        self.status_bar.p2p_peers = len(self.p2p_manager.get_connected_peers())
        self.status_bar.p2p_status = P2PState.CONNECTED
        self.status_bar.refresh()
        self.chat_panel.add_message(ChatMessage("System", f"P2P peer connected: {peer_id}", "success"))

    def _on_p2p_peer_disconnected(self, peer_id: str):
        self.chat_panel.add_message(ChatMessage("System", f"P2P disconnected: {peer_id}", "warning"))
        peers = len(self.p2p_manager.get_connected_peers()) if self.p2p_manager else 0
        self.status_bar.p2p_peers = peers
        # FIX: downgrade to CONNECTING (not failed) if we still have the manager running
        if peers == 0 and self.p2p_manager:
            self.status_bar.p2p_status = P2PState.CONNECTING
        self.status_bar.refresh()

    def _on_p2p_message_received(self, peer_id: str, message: str):
        self.chat_panel.add_message(ChatMessage(peer_id, message, "pm"))

    # ── Input handling ────────────────────────────────────────────────────────

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "message-input":
            await self.send_message()

    async def send_message(self) -> None:
        input_box = self.query_one("#message-input", Input)
        text = input_box.value.strip()
        if not text:
            return
        if not self.net or not self.net._connected:
            self.chat_panel.add_message(ChatMessage("System", "Not connected.  Ctrl+N to connect.", "error"))
            input_box.value = ""
            return
        try:
            if text.startswith("/"):
                await self.handle_command(text)
            else:
                await self.net.send_room_message(text)
                self.chat_panel.add_message(ChatMessage("You", text, "chat", room=self.net.room))
                self.status_bar.message_count += 1
                if self.metrics_collector:
                    self.metrics_collector.increment_message_counter(is_p2p=False)
                if self.p2p_manager and self.p2p_manager.state == P2PState.CONNECTED:
                    p2p_sent = await self.p2p_manager.broadcast_message(text)
                    if p2p_sent and self.metrics_collector:
                        for _ in range(p2p_sent):
                            self.metrics_collector.increment_message_counter(is_p2p=True)
            input_box.value = ""
        except Exception as e:
            self.chat_panel.add_message(ChatMessage("System", f"Send error: {e}", "error"))

    async def handle_command(self, command: str) -> None:
        parts = command[1:].split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:] if len(parts) > 1 else []
        if cmd == "help":
            self.show_help()
        elif cmd == "clear":
            self.chat_panel.clear_messages()
        elif cmd in ("quit", "exit"):
            await self.disconnect()
            self.exit()
        elif cmd == "connect":
            self.push_screen(ConnectionModal())
        elif cmd == "disconnect":
            await self.disconnect()
        elif cmd == "settings":
            self.push_screen(SettingsModal())
        elif cmd == "rooms":
            await self.show_room_list()
        elif cmd == "users":
            await self.show_user_list()
        elif cmd == "nick" and args:
            await self.change_nick(args[0])
        elif cmd == "join" and args:
            await self.join_room(args[0])
        elif cmd in ("part", "leave"):
            await self.leave_room()
        elif cmd == "me" and args:
            # /me action
            action_text = " ".join(args)
            nick = getattr(self.net, "nickname", "You") if self.net else "You"
            self.chat_panel.add_message(ChatMessage("System", f"* {nick} {action_text}", "event"))
        else:
            self.chat_panel.add_message(ChatMessage("System", f"Unknown command: {command}  (try /help)", "error"))

    def show_help(self) -> None:
        lines = [
            "[bold #e6edf3]Commands[/]",
            "[#4d5566]/connect  /disconnect  /quit[/]",
            "[#4d5566]/nick <name>  /join <room>  /part[/]",
            "[#4d5566]/me <action>  /rooms  /users[/]",
            "[#4d5566]/settings  /clear  /help[/]",
            "",
            "[bold #e6edf3]Shortcuts[/]",
            "[#4d5566]Ctrl+N  Connect       Ctrl+S  Settings[/]",
            "[#4d5566]Ctrl+L  Clear         Ctrl+H  Help[/]",
            "[#4d5566]Ctrl+R  Rooms         Ctrl+U  Users[/]",
            "[#4d5566]F1  Toggle sidebar    Esc  Close modal[/]",
        ]
        self.chat_panel.add_message(ChatMessage("System", "\n".join(lines), "system"))

    # ── Password handlers ─────────────────────────────────────────────────────

    async def handle_password_setup(self) -> None:
        try:
            pwd = self.query_one("#password-input", Input).value.strip()
            cpwd = self.query_one("#confirm-password-input", Input).value.strip()
            kdf = self.query_one("#kdf-select", Select).value
            if await self.setup_keystore(pwd, cpwd, kdf):
                self.pop_screen()
                self.push_screen(ConnectionModal())
        except Exception as e:
            self.chat_panel.add_message(ChatMessage("System", f"Password setup error: {e}", "error"))

    async def handle_password_unlock(self) -> None:
        try:
            pwd = self.query_one("#password-input", Input).value.strip()
            if await self.unlock_keystore(pwd):
                self.pop_screen()
                self.push_screen(ConnectionModal())
        except Exception as e:
            self.chat_panel.add_message(ChatMessage("System", f"Password unlock error: {e}", "error"))

    # ── Button handler ────────────────────────────────────────────────────────

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "send-btn":
            await self.send_message()
        elif bid == "connect-btn":
            await self.handle_connect()
        elif bid in ("cancel-btn", "cancel-settings"):
            self.pop_screen()
        elif bid == "save-settings":
            await self.save_settings()
        elif bid == "reset-settings":
            await self.reset_settings()
        elif bid == "setup-btn":
            await self.handle_password_setup()
        elif bid == "unlock-btn":
            await self.handle_password_unlock()

    async def handle_connect(self) -> None:
        try:
            server = self.query_one("#server-input", Input).value.strip()
            nick = self.query_one("#nick-input", Input).value.strip()
            room = self.query_one("#room-input", Input).value.strip()
            use_tls = self.query_one("#tls-checkbox", Checkbox).value
            if not all([server, nick, room]):
                self.chat_panel.add_message(ChatMessage("System", "Please fill in all fields.", "error"))
                return
            if not self.keystore:
                self.chat_panel.add_message(ChatMessage("System", "Keystore not unlocked.", "error"))
                return
            if self.net and self.net._connected:
                await self.disconnect()
            self.net = ChatNetworkClient(server, nick, room, use_tls)
            # FIX: set _connecting guard so update_status() doesn't overwrite CONNECTING state
            self._connecting = True
            self.status_bar.state = UIState.CONNECTING
            self.status_bar.server_info = server
            self.status_bar.user_info = nick
            self.status_bar.room_info = room
            self.status_bar.refresh()
            self.chat_panel.add_message(ChatMessage("System", f"Connecting to {server}…", "system"))
            success = await self.net.connect()
            self._connecting = False
            if success:
                self.status_bar.state = UIState.CONNECTED
                self.status_bar.refresh()
                self.query_one("#room-header", Static).update(f" #{room.lstrip('#')}")
                self.chat_panel.add_message(ChatMessage("System", f"Connected to {server} as {nick} in #{room.lstrip('#')}", "success"))
                try:
                    if self.net.identity:
                        if self.keystore.store_identity_key(self.net.identity, f"{nick}@{server}"):
                            self.chat_panel.add_message(ChatMessage("System", "Identity key stored.", "success"))
                except Exception:
                    pass
                self.user_list.add_user(nick, getattr(self.net, "fingerprint", ""), "online")
                if self.p2p_enabled:
                    await self._initialize_p2p(nick, room)
                # FIX: use queue-based message loop
                asyncio.create_task(self.handle_messages())
                self.pop_screen()
                # Return focus to input after modal closes
                self.call_after_refresh(self._focus_input)
            else:
                self._connecting = False
                self.status_bar.state = UIState.ERROR
                self.status_bar.refresh()
                self.chat_panel.add_message(ChatMessage("System", "Failed to connect.", "error"))
        except Exception as e:
            self._connecting = False
            self.status_bar.state = UIState.ERROR
            self.status_bar.refresh()
            self.chat_panel.add_message(ChatMessage("System", f"Connection error: {e}", "error"))

    async def _initialize_p2p(self, nick: str, room: str) -> None:
        try:
            self.p2p_manager = create_p2p_manager(nick, room)
            self.p2p_manager.on_peer_connected = self._on_p2p_peer_connected
            self.p2p_manager.on_peer_disconnected = self._on_p2p_peer_disconnected
            self.p2p_manager.on_message_received = self._on_p2p_message_received
            self.status_bar.p2p_status = P2PState.CONNECTING
            self.status_bar.refresh()
            await self.p2p_manager.start()
            # FIX: if start() succeeds without peers yet, state stays CONNECTING until
            # _on_p2p_peer_connected fires. That is correct — no premature CONNECTED here.
        except Exception as e:
            self.status_bar.p2p_status = P2PState.FAILED
            self.status_bar.refresh()
            self.chat_panel.add_message(ChatMessage("System", f"P2P init failed: {e}", "warning"))

    async def handle_messages(self) -> None:
        """FIX: use await queue.get() instead of polling .empty() + .get_nowait()"""
        try:
            queue = self.net._msg_queue
            while self.net and self.net._connected:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=1.0)
                    await self.process_message(msg)
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    self.chat_panel.add_message(ChatMessage("System", f"Message loop error: {e}", "error"))
                    break
        except Exception:
            pass

    async def process_message(self, msg: dict) -> None:
        mt = msg.get("type", "unknown")
        if mt == "chat":
            sender = msg.get("from", "Unknown")
            self.chat_panel.add_message(ChatMessage(sender, msg.get("msg", ""), "chat", room=msg.get("room", "")))
            if sender != "You" and sender not in self.user_list.users:
                self.user_list.add_user(sender, "unknown", "online")
        elif mt == "pm":
            self.chat_panel.add_message(ChatMessage(msg.get("from", "Unknown"), msg.get("msg", ""), "pm"))
        elif mt == "system":
            self.chat_panel.add_message(ChatMessage("System", msg.get("msg", ""), "system"))
        elif mt == "event":
            ev = msg.get("msg", "")
            self.chat_panel.add_message(ChatMessage("System", ev, "event", metadata=msg))
            parts = ev.split()
            if "joined" in ev.lower() and len(parts) >= 3:
                self.user_list.add_user(parts[2].rstrip("!"), "unknown", "online")
            elif "left" in ev.lower() and len(parts) >= 2:
                self.user_list.remove_user(parts[1])
        elif mt == "error":
            self.chat_panel.add_message(ChatMessage("System", msg.get("msg", ""), "error"))
        elif mt == "user_list":
            # Handle server-sent user list updates
            users = msg.get("users", [])
            for u in users:
                nick = u if isinstance(u, str) else u.get("nick", "")
                fp = "" if isinstance(u, str) else u.get("fingerprint", "")
                if nick and nick not in self.user_list.users:
                    self.user_list.add_user(nick, fp, "online")

    async def disconnect(self) -> None:
        self._connecting = False
        if self.net:
            await self.net.disconnect()
            self.status_bar.state = UIState.DISCONNECTED
            self.status_bar.server_info = ""
            self.status_bar.user_info = ""
            self.status_bar.room_info = ""
            self.status_bar.refresh()
            self.chat_panel.add_message(ChatMessage("System", "Disconnected.", "system"))
            # Reset room header
            try:
                self.query_one("#room-header", Static).update(" #general")
            except Exception:
                pass
        if self.p2p_manager:
            await self.p2p_manager.stop()
            self.p2p_manager = None
            self.status_bar.p2p_status = P2PState.DISCONNECTED
            self.status_bar.p2p_peers = 0
            self.status_bar.refresh()
        if self.metrics_collector:
            self.metrics_collector.stop_collection()
            self.metrics_collector = None
        self.alert_manager = None
        self.user_list.users.clear()
        self.user_list.refresh()

    def update_status(self) -> None:
        # FIX: don't overwrite CONNECTING or ERROR states set by handle_connect()
        if self._connecting:
            return
        if self.status_bar.state in (UIState.CONNECTING, UIState.ERROR):
            return
        connected = bool(self.net and self.net._connected)
        new_state = UIState.CONNECTED if connected else UIState.DISCONNECTED
        if self.status_bar.state != new_state:
            self.status_bar.state = new_state
            self.status_bar.refresh()

    def update_ui(self) -> None:
        # Refresh user list "last seen" timestamps periodically
        if self.user_list.users:
            self.user_list.refresh()

    async def save_settings(self) -> None:
        self.chat_panel.add_message(ChatMessage("System", "Settings saved.", "success"))
        self.pop_screen()

    async def reset_settings(self) -> None:
        self.chat_panel.add_message(ChatMessage("System", "Settings reset to defaults.", "system"))

    async def show_room_list(self) -> None:
        if self.net and self.net._connected:
            await self.net.request_room_list()
        else:
            self.chat_panel.add_message(ChatMessage("System", "Not connected.", "error"))

    async def show_user_list(self) -> None:
        """FIX: actually display the current user list from sidebar."""
        if not self.user_list.users:
            self.chat_panel.add_message(ChatMessage("System", "No users in room yet.", "system"))
            return
        lines = ["[bold #e6edf3]Users in room[/]"]
        status_dot = {"online": "●", "away": "◑", "busy": "○", "offline": "○"}
        for nick, info in sorted(self.user_list.users.items(), key=lambda u: u[0].lower()):
            dot = status_dot.get(info["status"], "●")
            age = int(time.time() - info["last_seen"])
            seen = "now" if age < 60 else (f"{age // 60}m ago" if age < 3600 else f"{age // 3600}h ago")
            lines.append(f"[#4d5566]{dot}[/] [#e6edf3]{nick}[/] [dim #4d5566]— {seen}[/]")
        self.chat_panel.add_message(ChatMessage("System", "\n".join(lines), "system"))

    async def change_nick(self, new_nick: str) -> None:
        if self.net and self.net._connected:
            try:
                old_nick = getattr(self.net, "nickname", "")
                # Send nick change command if the client supports it
                if hasattr(self.net, "change_nickname"):
                    await self.net.change_nickname(new_nick)
                else:
                    await self.net.send_command(f"NICK {new_nick}")
                # Update local state
                if old_nick and old_nick in self.user_list.users:
                    info = self.user_list.users.pop(old_nick)
                    info["nick"] = new_nick
                    self.user_list.users[new_nick] = info
                    self.user_list.refresh()
                self.status_bar.user_info = new_nick
                self.status_bar.refresh()
                self.chat_panel.add_message(ChatMessage("System", f"Nick changed: {old_nick} → {new_nick}", "success"))
            except Exception as e:
                self.chat_panel.add_message(ChatMessage("System", f"Nick change failed: {e}", "error"))
        else:
            self.chat_panel.add_message(ChatMessage("System", "Not connected.", "error"))

    async def join_room(self, room_name: str) -> None:
        if self.net and self.net._connected:
            try:
                clean = room_name.lstrip("#")
                if hasattr(self.net, "join_room"):
                    await self.net.join_room(clean)
                else:
                    await self.net.send_command(f"JOIN #{clean}")
                self.status_bar.room_info = clean
                self.status_bar.refresh()
                self.query_one("#room-header", Static).update(f" #{clean}")
                # Clear user list for new room
                self.user_list.users.clear()
                self.user_list.refresh()
                self.chat_panel.add_message(ChatMessage("System", f"Joined #{clean}", "success"))
            except Exception as e:
                self.chat_panel.add_message(ChatMessage("System", f"Join failed: {e}", "error"))
        else:
            self.chat_panel.add_message(ChatMessage("System", "Not connected.", "error"))

    async def leave_room(self) -> None:
        if self.net and self.net._connected:
            try:
                room = getattr(self.net, "room", "")
                if hasattr(self.net, "leave_room"):
                    await self.net.leave_room()
                else:
                    await self.net.send_command("PART")
                self.user_list.users.clear()
                self.user_list.refresh()
                self.status_bar.room_info = ""
                self.status_bar.refresh()
                self.query_one("#room-header", Static).update(" (no room)")
                self.chat_panel.add_message(ChatMessage("System", f"Left #{room.lstrip('#')}", "system"))
            except Exception as e:
                self.chat_panel.add_message(ChatMessage("System", f"Leave failed: {e}", "error"))
        else:
            self.chat_panel.add_message(ChatMessage("System", "Not connected.", "error"))

    # ── Actions ───────────────────────────────────────────────────────────────

    def action_settings(self) -> None:
        self.push_screen(SettingsModal())

    def action_connect(self) -> None:
        self.push_screen(ConnectionModal())

    def action_clear(self) -> None:
        self.chat_panel.clear_messages()

    def action_help(self) -> None:
        self.show_help()

    def action_room_list(self) -> None:
        asyncio.create_task(self.show_room_list())

    def action_user_list(self) -> None:
        asyncio.create_task(self.show_user_list())

    def action_toggle_side_panel(self) -> None:
        sidebar = self.query_one("#sidebar")
        sidebar.display = not sidebar.display
        self.side_panel_visible = sidebar.display

    def action_dismiss_modal(self) -> None:
        if len(self.screen_stack) > 1:
            self.pop_screen()


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ModernChatApp().run()
