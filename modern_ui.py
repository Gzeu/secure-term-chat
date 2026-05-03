#!/usr/bin/env python3
"""
Modern Terminal UI for secure-term-chat
Professional, feature-rich, and visually impressive interface
"""

import asyncio
import time
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, RichLog, Input, Button, 
    ProgressBar, Label, Switch, Checkbox, Select,
    Tabs, TabPane, TabbedContent, Placeholder
)
from textual.reactive import reactive
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.message import Message
from textual import work
from typing import Union
from rich.text import Text
from rich.markup import escape
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

# Import existing client
from client import ChatNetworkClient
from encrypted_keystore import EncryptedKeystore, create_keystore, load_keystore, verify_keystore_password
from p2p_manager import P2PManager, P2PState, PeerInfo, create_p2p_manager, is_p2p_available
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
        """Convert message to rich text with enhanced formatting"""
        time_str = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        
        # Enhanced color scheme
        if self.type == "chat":
            prefix = f"[dim #6e7681]{time_str}[/] "
            sender_color = "#58a6ff" if self.sender == "You" else "#c9d1d9"
            sender_text = f"[bold {sender_color}]{self.sender}[/]: "
            content_text = f"[#c9d1d9]{self.content}[/]"
        elif self.type == "pm":
            prefix = f"[dim #6e7681]{time_str}[/] "
            sender_text = f"[bold #f0f6fc]💬 PM ← {self.sender}[/]: "
            content_text = f"[#c9d1d9]{self.content}[/]"
        elif self.type == "system":
            prefix = f"[dim #6e7681]{time_str}[/] "
            sender_text = "[bold #58a6ff]ℹ️ [/]"
            content_text = f"[#8b949e]{self.content}[/]"
        elif self.type == "error":
            prefix = f"[dim #6e7681]{time_str}[/] "
            sender_text = "[bold #f85149]❌ [/]"
            content_text = f"[#f85149]{self.content}[/]"
        elif self.type == "success":
            prefix = f"[dim #6e7681]{time_str}[/] "
            sender_text = "[bold #56d364]✅ [/]"
            content_text = f"[#56d364]{self.content}[/]"
        elif self.type == "event":
            color = "#56d364" if self.metadata.get("trust") in ("OK", "NEW") else "#f85149"
            prefix = f"[dim #6e7681]{time_str}[/] "
            sender_text = f"[bold {color}]▶ [/]"
            content_text = f"[#c9d1d9]{self.content}[/]"
        else:
            prefix = f"[dim #6e7681]{time_str}[/] "
            sender_text = f"[bold #79c0ff]{self.type}[/]: "
            content_text = f"[#c9d1d9]{self.content}[/]"
        
        return Text.assemble(prefix, sender_text, content_text)

class PasswordSetupModal(ModalScreen):
    """Password setup modal for keystore"""
    
    BINDINGS = [("escape", "dismiss", "Close")]
    
    def compose(self) -> ComposeResult:
        with Container(id="password-modal"):
            yield Static("🔐 Setup Keystore Password", classes="modal-title")
            
            with Vertical(classes="form-container"):
                yield Static("🔒 Protect your identity keys with a strong password", classes="form-help")
                
                yield Label("🔑 Password:", classes="form-label")
                yield Input(placeholder="Enter strong password...", password=True, id="password-input", classes="form-input")
                
                yield Label("🔄 Confirm Password:", classes="form-label")
                yield Input(placeholder="Confirm password...", password=True, id="confirm-password-input", classes="form-input")
                
                yield Label("🛡️ Key Derivation:", classes="form-label")
                yield Select(
                    [("🔥 Argon2 (Recommended)", "argon2"), ("🔧 bcrypt", "bcrypt"), ("🔓 PBKDF2", "pbkdf2")],
                    value="argon2",
                    id="kdf-select",
                    classes="form-select"
                )
                
                with Horizontal(classes="button-container"):
                    yield Button("🚀 Setup", variant="primary", id="setup-btn", classes="btn-primary")
                    yield Button("❌ Cancel", id="cancel-btn", classes="btn-secondary")

class PasswordModal(ModalScreen):
    """Password entry modal for keystore unlock"""
    
    BINDINGS = [("escape", "dismiss", "Close")]
    
    def compose(self) -> ComposeResult:
        with Container(id="password-modal"):
            yield Static("🔐 Unlock Keystore", classes="modal-title")
            
            with Vertical(classes="form-container"):
                yield Static("🔒 Enter your keystore password to unlock identity keys", classes="form-help")
                
                yield Label("🔑 Password:", classes="form-label")
                yield Input(placeholder="Enter password...", password=True, id="password-input", classes="form-input")
                
                with Horizontal(classes="button-container"):
                    yield Button("🔓 Unlock", variant="primary", id="unlock-btn", classes="btn-primary")
                    yield Button("❌ Cancel", id="cancel-btn", classes="btn-secondary")

class ConnectionModal(ModalScreen):
    """Beautiful connection modal"""
    
    BINDINGS = [("escape", "dismiss", "Close")]
    
    def compose(self) -> ComposeResult:
        with Container(id="connection-modal"):
            yield Static("🔗 Connect to Server", classes="modal-title")
            
            with Vertical(classes="form-container"):
                yield Label("🌐 Server Address:", classes="form-label")
                yield Input(placeholder="localhost:12345", id="server-input", classes="form-input")
                
                yield Label("👤 Nickname:", classes="form-label")
                yield Input(placeholder="YourNickname", id="nick-input", classes="form-input")
                
                yield Label("🏠 Room:", classes="form-label")
                yield Input(placeholder="#crypto", id="room-input", classes="form-input")
                
                yield Label("🔒 Security Options:", classes="form-label")
                with Horizontal(classes="security-options"):
                    yield Checkbox("Use TLS", value=True, id="tls-checkbox", classes="form-checkbox")
                    yield Checkbox("Advanced Security", value=False, id="advanced-checkbox", classes="form-checkbox")
                
                with Horizontal(classes="button-container"):
                    yield Button("🚀 Connect", variant="primary", id="connect-btn", classes="btn-primary")
                    yield Button("❌ Cancel", id="cancel-btn", classes="btn-secondary")

class SettingsModal(ModalScreen):
    """Comprehensive settings modal"""
    
    BINDINGS = [("escape", "dismiss", "Close")]
    
    def compose(self) -> ComposeResult:
        with Container(id="settings-modal"):
            yield Static("⚙️ Settings", classes="modal-title")
            
            with TabbedContent(classes="settings-tabs"):
                with TabPane("🎨 Appearance", id="appearance-tab"):
                    with Vertical(classes="tab-content"):
                        yield Label("🎨 Theme:", classes="form-label")
                        yield Select(
                            [("🌙 Dark", "dark"), ("☀️ Light", "light"), ("🔄 Auto", "auto")],
                            value="dark",
                            id="theme-select",
                            classes="form-select"
                        )
                        
                        yield Label("📏 Font Size:", classes="form-label")
                        yield Select(
                            [("📱 Small", "small"), ("🖥️ Medium", "medium"), ("📺 Large", "large")],
                            value="medium",
                            id="font-size-select",
                            classes="form-select"
                        )
                        
                        yield Label("✨ Animations:", classes="form-label")
                        yield Switch(value=True, id="animations-switch", classes="form-switch")
                        
                        yield Label("🕐 Show Timestamps:", classes="form-label")
                        yield Switch(value=True, id="timestamps-switch", classes="form-switch")
                
                with TabPane("🔒 Security", id="security-tab"):
                    with Vertical(classes="tab-content"):
                        yield Label("🔐 End-to-End Encryption:", classes="form-label")
                        yield Switch(value=True, id="encryption-switch", classes="form-switch")
                        
                        yield Label("🔄 Forward Secrecy:", classes="form-label")
                        yield Switch(value=True, id="forward-secrecy-switch", classes="form-switch")
                        
                        yield Label("🌐 P2P Mode:", classes="form-label")
                        yield Switch(value=False, id="p2p-switch", classes="form-switch")
                        
                        yield Label("💨 Ephemeral Messages:", classes="form-label")
                        yield Switch(value=False, id="ephemeral-switch", classes="form-switch")
                        
                        yield Label("⏰ Default TTL (hours):", classes="form-label")
                        yield Input(placeholder="24", id="ttl-input", classes="form-input")
                
                with TabPane("🔔 Notifications", id="notifications-tab"):
                    with Vertical(classes="tab-content"):
                        yield Label("💬 Message Notifications:", classes="form-label")
                        yield Switch(value=True, id="message-notifications", classes="form-switch")
                        
                        yield Label("👥 User Join/Leave:", classes="form-label")
                        yield Switch(value=True, id="user-notifications", classes="form-switch")
                        
                        yield Label("🔊 Sound Alerts:", classes="form-label")
                        yield Switch(value=False, id="sound-alerts", classes="form-switch")
                        
                        yield Label("📱 Desktop Notifications:", classes="form-label")
                        yield Switch(value=False, id="desktop-notifications", classes="form-switch")
                
                with TabPane("⚡ Advanced", id="advanced-tab"):
                    with Vertical(classes="tab-content"):
                        yield Label("🐛 Debug Mode:", classes="form-label")
                        yield Switch(value=False, id="debug-switch", classes="form-switch")
                        
                        yield Label("📊 Performance Monitoring:", classes="form-label")
                        yield Switch(value=True, id="monitoring-switch", classes="form-switch")
                        
                        yield Label("🔄 Auto-reconnect:", classes="form-label")
                        yield Switch(value=True, id="auto-reconnect-switch", classes="form-switch")
                        
                        yield Label("📁 Max File Size (MB):", classes="form-label")
                        yield Input(placeholder="10", id="max-file-size", classes="form-input")
            
            with Horizontal(classes="button-container"):
                yield Button("💾 Save", variant="primary", id="save-settings", classes="btn-primary")
                yield Button("🔄 Reset", id="reset-settings", classes="btn-secondary")
                yield Button("❌ Cancel", id="cancel-settings", classes="btn-secondary")

class StatusBar(Static):
    """Enhanced status bar with real-time information"""
    
    state = reactive(UIState.DISCONNECTED)
    server_info = reactive("")
    user_info = reactive("")
    room_info = reactive("")
    connection_time = reactive(0)
    message_count = reactive(0)
    p2p_status = reactive(P2PState.DISCONNECTED)
    p2p_peers = reactive(0)
    
    def __init__(self):
        super().__init__()
        self.start_time = time.time()
        self.message_count = 0
    
    def render(self) -> Union[str, Table, Text]:
        """Render enhanced status bar"""
        state_config = {
            UIState.CONNECTING: ("🔄 Connecting", "#ff79c6"),
            UIState.CONNECTED: ("🟢 Connected", "#56d364"), 
            UIState.DISCONNECTED: ("⚫ Disconnected", "#6e7681"),
            UIState.ERROR: ("❌ Error", "#f85149")
        }
        
        status_text, color = state_config.get(self.state, ("❓ Unknown", "#6e7681"))
        
        # Create status table
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("", style=color, width=12)
        table.add_column("", style="#c9d1d9", width=18)
        table.add_column("", style="#8b949e", width=12)
        table.add_column("", style="#8b949e", width=12)
        table.add_column("", style="#8b949e", width=12)
        table.add_column("", style="#8b949e", width=12)
        
        uptime = int(time.time() - self.start_time)
        uptime_str = f"{uptime//60:02d}:{uptime%60:02d}"
        
        # P2P status
        p2p_config = {
            P2PState.CONNECTING: ("🔄 P2P", "#ff79c6"),
            P2PState.CONNECTED: ("🟢 P2P", "#56d364"),
            P2PState.DISCONNECTED: ("⚫ P2P", "#6e7681"),
            P2PState.FAILED: ("❌ P2P", "#f85149"),
            P2PState.FALLBACK: ("🔄 Relay", "#ff79c6")
        }
        p2p_text, p2p_color = p2p_config.get(self.p2p_status, ("❓ P2P", "#6e7681"))
        
        table.add_row(
            f"[bold]{status_text}[/]",
            f"🌐 {self.server_info}" if self.server_info else "",
            f"👤 {self.user_info}" if self.user_info else "",
            f"[{p2p_color}]{p2p_text} ({self.p2p_peers})[/]" if self.p2p_peers > 0 else f"[{p2p_color}]{p2p_text}[/]",
            f"📨 {self.message_count}" if self.message_count > 0 else "",
            f"⏱️ {uptime_str}"
        )
        
        return table

class UserListPanel(Static):
    """Enhanced user list with status indicators"""
    
    def __init__(self):
        super().__init__()
        self.users: Dict[str, Dict] = {}
    
    def add_user(self, nick: str, fingerprint: str, status: str = "online"):
        """Add or update user"""
        self.users[nick] = {
            "nick": nick,
            "fingerprint": fingerprint,
            "status": status,
            "last_seen": time.time()
        }
        self.refresh()
    
    def remove_user(self, nick: str):
        """Remove user"""
        if nick in self.users:
            del self.users[nick]
            self.refresh()
    
    def render(self) -> Union[str, Table, Text]:
        """Render enhanced user list"""
        if not self.users:
            return "[dim #6e7681]No users online[/]"
        
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Status", width=2)
        table.add_column("Nick", style="#c9d1d9", width=15)
        table.add_column("Fingerprint", style="#6e7681", width=10)
        table.add_column("Last Seen", style="#6e7681", width=8)
        
        # Sort users by status and nick
        sorted_users = sorted(
            self.users.items(),
            key=lambda u: (u[1]["status"] != "online", u[0].lower())
        )
        
        for nick, user_info in sorted_users:
            status_icons = {
                "online": "🟢",
                "away": "🟡", 
                "busy": "🔴",
                "offline": "⚫"
            }
            
            status_icon = status_icons.get(user_info["status"], "❓")
            
            # Truncate fingerprint
            fp_short = user_info["fingerprint"][:8] + "..."
            
            # Format last seen
            last_seen = int(time.time() - user_info["last_seen"])
            if last_seen < 60:
                last_seen_str = "now"
            elif last_seen < 3600:
                last_seen_str = f"{last_seen//60}m"
            else:
                last_seen_str = f"{last_seen//3600}h"
            
            table.add_row(status_icon, nick, fp_short, last_seen_str)
        
        return table

class ChatPanel(Static):
    """Enhanced chat panel with rich formatting"""
    
    def __init__(self):
        super().__init__()
        self.messages: List[ChatMessage] = []
        self.max_messages = 1000
    
    def add_message(self, message: ChatMessage):
        """Add a message to the chat"""
        self.messages.append(message)
        
        # Keep only the last max_messages
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]
        
        self.refresh()
    
    def clear_messages(self):
        """Clear all messages"""
        self.messages = []
        self.refresh()
    
    def render(self) -> Union[str, Table, Text]:
        """Render enhanced chat panel"""
        if not self.messages:
            welcome_text = """
[bold #58a6ff]🌟 Welcome to secure-term-chat! 🌟[/]

[dim #6e7681]End-to-end encrypted terminal chat with advanced security features.[/]

[dim #6e7681]Commands:[/]
[dim #6e7681]• /help - Show all commands[/]
[dim #6e7681]• /connect - Connect to server[/]
[dim #6e7681]• /settings - Open settings[/]
[dim #6e7681]• /clear - Clear chat[/]

[dim #6e7681]Press Ctrl+S for settings or Ctrl+N to connect.[/]
            """.strip()
            
            return welcome_text
        
        # Create rich text for all messages
        message_lines = []
        for message in self.messages:
            message_lines.append(message.to_rich_text())
        
        return "\n".join(str(line) for line in message_lines)

class ModernChatApp(App):
    """Modern terminal chat application with enhanced UI"""
    
    CSS = """
    /* Modern Dark Theme */
    Screen {
        background: #0d1117;
        text-style: none;
    }
    
    /* Modal Styles */
    #connection-modal, #settings-modal, #password-modal {
        background: #161b22;
        border: solid #30363d;
        padding: 2;
        margin: 2;
        width: 80;
        height: 30;
    }
    
    .modal-title {
        text-align: center;
        text-style: bold;
        color: #58a6ff;
        margin: 1 0;
    }
    
    .form-container {
        padding: 1;
    }
    
    .form-label {
        color: #f0f6fc;
        margin: 1 0 0 0;
        text-style: bold;
    }
    
    .form-help {
        color: #8b949e;
        margin: 0 0 1 0;
        text-style: italic;
    }
    
    .form-input, .form-select {
        width: 100%;
        margin: 0 0 1 0;
        border: solid #30363d;
        background: #0d1117;
        color: #c9d1d9;
    }
    
    .form-input:focus, .form-select:focus {
        border: solid #58a6ff;
        background: #0d1117;
    }
    
    .form-checkbox, .form-switch {
        margin: 0 0 1 0;
    }
    
    .security-options {
        margin: 1 0;
    }
    
    .button-container {
        height: 3;
        dock: bottom;
        padding: 1 0;
    }
    
    .btn-primary {
        background: #238636;
        color: white;
        border: solid #2ea043;
    }
    
    .btn-primary:hover {
        background: #2ea043;
        border: solid #3fb950;
    }
    
    .btn-secondary {
        background: #21262d;
        color: #c9d1d9;
        border: solid #30363d;
    }
    
    .btn-secondary:hover {
        background: #30363d;
        border: solid #6e7681;
    }
    
    /* Header and Footer */
    Header {
        background: #161b22;
        text-align: center;
        color: #c9d1d9;
        text-style: bold;
    }
    
    Footer {
        background: #161b22;
        color: #8b949e;
    }
    
    /* Main Layout */
    #main-container {
        layout: grid;
        grid-size: 3 1;
        grid-columns: 1fr 25% 1fr;
        padding: 1;
        height: 100%;
    }
    
    /* Chat Area */
    #chat-area {
        layout: vertical;
        height: 100%;
    }
    
    #chat-panel {
        height: 1fr;
        border: solid #30363d;
        background: #0d1117;
        padding: 1;
    }
    
    #input-container {
        height: 4;
        border: solid #30363d;
        padding: 1;
        background: #161b22;
        margin-top: 1;
    }
    
    #message-input {
        width: 100%;
        border: solid #30363d;
        background: #0d1117;
        color: #c9d1d9;
        margin-bottom: 1;
    }
    
    #message-input:focus {
        border: solid #58a6ff;
        background: #0d1117;
    }
    
    /* Side Panel */
    #side-panel {
        layout: vertical;
        height: 100%;
        border-left: solid #30363d;
        padding: 1;
        margin-left: 1;
    }
    
    #user-list {
        height: 1fr;
        border: solid #30363d;
        background: #161b22;
        padding: 1;
        margin-bottom: 1;
    }
    
    #status-bar {
        height: 8;
        border: solid #30363d;
        background: #161b22;
        padding: 1;
    }
    
    /* Tab Styles */
    .settings-tabs {
        height: 1fr;
    }
    
    .tab-content {
        padding: 1;
    }
    
    /* Utility Classes */
    .center {
        text-align: center;
    }
    
    .bold {
        text-style: bold;
    }
    
    .dim {
        color: #6e7681;
    }
    
    .success {
        color: #56d364;
    }
    
    .error {
        color: #f85149;
    }
    
    .warning {
        color: #ff79c6;
    }
    
    .info {
        color: #58a6ff;
    }
    """
    
    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit"),
        Binding("ctrl+s", "settings", "Settings"),
        Binding("ctrl+n", "connect", "Connect"),
        Binding("ctrl+l", "clear", "Clear"),
        Binding("ctrl+h", "help", "Help"),
        Binding("ctrl+r", "room_list", "Rooms"),
        Binding("ctrl+u", "user_list", "Users"),
        Binding("f1", "toggle_side_panel", "Toggle Panel"),
        Binding("f2", "toggle_status", "Toggle Status"),
        Binding("escape", "dismiss_modal", "Close Modal"),
        Binding("enter", "send_message", "Send Message"),
    ]
    
    def __init__(self):
        super().__init__()
        self.net: Optional[ChatNetworkClient] = None
        self.keystore: Optional[EncryptedKeystore] = None
        self.keystore_password: Optional[str] = None
        self.keystore_dir = Path.home() / ".secure-term-chat"
        self.p2p_manager: Optional[P2PManager] = None
        self.p2p_enabled = is_p2p_available()
        
        # Performance monitoring
        self.metrics_collector: Optional[MetricsCollector] = None
        self.alert_manager: Optional[AlertManager] = None
        self.performance_enabled = True
        
        # Room management
        self.room_manager: Optional[RoomManager] = None
        self.room_management_enabled = True
        
        # File transfer
        self.file_transfer_manager: Optional[FileTransferManager] = None
        self.file_transfer_enabled = True
        
        # User management
        self.user_manager: Optional[UserManager] = None
        self.user_management_enabled = True
        
        # Audit and compliance
        self.audit_manager: Optional[AuditManager] = None
        self.audit_compliance_enabled = True
        
        self.chat_panel = ChatPanel()
        self.user_list = UserListPanel()
        self.status_bar = StatusBar()
        self.side_panel_visible = True
        self.status_visible = True
    
    def compose(self) -> ComposeResult:
        """Compose the modern application layout"""
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            # Chat Area (left)
            with Vertical(id="chat-area"):
                yield self.chat_panel
                with Horizontal(id="input-container"):
                    yield Input(
                        placeholder="Type a message or /command...",
                        id="message-input"
                    )
                    yield Button("📤 Send", variant="primary", id="send-btn")
            
            # Side Panel (right)
            with Vertical(id="side-panel"):
                yield self.user_list
                yield self.status_bar
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the application"""
        # Initialize room management
        self._initialize_room_management()
        
        # Initialize file transfer
        self._initialize_file_transfer()
        
        # Initialize user management
        self._initialize_user_management()
        
        # Initialize audit and compliance
        self._initialize_audit_compliance()
        
        # Initialize performance monitoring
        self._initialize_performance_monitoring()
        
        # Check keystore status
        self._check_keystore_status()
        
        # Focus the input box (if available)
        try:
            input_box = self.query_one("#message-input", Input)
            self.set_focus(input_box)
        except:
            # Input box not available yet, will focus later
            pass
        
        # Set up periodic tasks
        self.set_interval(1.0, self.update_status)
        self.set_interval(5.0, self.update_ui)
        self.set_interval(10.0, self.update_performance_metrics)
        
        # Show welcome message
        self.chat_panel.add_message(ChatMessage(
            "System",
            "🌟 Welcome to secure-term-chat! Press Ctrl+N to connect or Ctrl+S for settings.",
            "success"
        ))
    
    def _check_keystore_status(self) -> None:
        """Check keystore status and show appropriate modal"""
        keystore_path = self.keystore_dir / "secure_keystore.json"
        
        if keystore_path.exists():
            # Keystore exists, need password
            self.chat_panel.add_message(ChatMessage(
                "System",
                "🔒 Keystore detected. Please enter password to unlock.",
                "system"
            ))
            self.push_screen(PasswordModal())
        else:
            # No keystore, need setup
            self.chat_panel.add_message(ChatMessage(
                "System",
                "🔐 No keystore found. Please setup password for identity protection.",
                "system"
            ))
            self.push_screen(PasswordSetupModal())
    
    async def setup_keystore(self, password: str, confirm_password: str, kdf: str) -> bool:
        """Setup new keystore"""
        try:
            if password != confirm_password:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "❌ Passwords do not match",
                    "error"
                ))
                return False
            
            if len(password) < 8:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "❌ Password must be at least 8 characters long",
                    "error"
                ))
                return False
            
            # Create keystore
            self.keystore = create_keystore(self.keystore_dir, password, kdf)
            self.keystore_password = password
            
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"✅ Keystore created with {kdf.upper()} key derivation",
                "success"
            ))
            
            return True
            
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error creating keystore: {e}",
                "error"
            ))
            return False
    
    async def unlock_keystore(self, password: str) -> bool:
        """Unlock existing keystore"""
        try:
            # Verify password
            if not verify_keystore_password(self.keystore_dir, password):
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "❌ Invalid password",
                    "error"
                ))
                return False
            
            # Load keystore
            self.keystore = load_keystore(self.keystore_dir, password)
            self.keystore_password = password
            
            self.chat_panel.add_message(ChatMessage(
                "System",
                "✅ Keystore unlocked successfully",
                "success"
            ))
            
            return True
            
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error unlocking keystore: {e}",
                "error"
            ))
            return False
    
    def _initialize_room_management(self) -> None:
        """Initialize room management components"""
        try:
            if self.room_management_enabled:
                self.room_manager = create_room_manager()
                
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "🏠 Room management initialized",
                    "success"
                ))
            else:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "🏠 Room management disabled",
                    "warning"
                ))
                
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error initializing room management: {e}",
                "error"
            ))
    
    def _initialize_file_transfer(self) -> None:
        """Initialize file transfer components"""
        try:
            if self.file_transfer_enabled:
                self.file_transfer_manager = create_file_transfer_manager()
                
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "📁 File transfer system initialized",
                    "success"
                ))
            else:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "📁 File transfer disabled",
                    "warning"
                ))
                
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error initializing file transfer: {e}",
                "error"
            ))
    
    def _initialize_user_management(self) -> None:
        """Initialize user management components"""
        try:
            if self.user_management_enabled:
                self.user_manager = create_user_manager()
                
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "👥 User management system initialized",
                    "success"
                ))
            else:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "👥 User management disabled",
                    "warning"
                ))
                
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error initializing user management: {e}",
                "error"
            ))
    
    def _initialize_audit_compliance(self) -> None:
        """Initialize audit and compliance components"""
        try:
            if self.audit_compliance_enabled:
                self.audit_manager = create_audit_manager()
                
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "📋 Audit and compliance system initialized",
                    "success"
                ))
            else:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "📋 Audit and compliance disabled",
                    "warning"
                ))
                
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error initializing audit and compliance: {e}",
                "error"
            ))
    
    def _initialize_performance_monitoring(self) -> None:
        """Initialize performance monitoring components"""
        try:
            if self.performance_enabled:
                self.metrics_collector = create_metrics_collector(interval=1.0)
                self.alert_manager = create_alert_manager()
                
                # Setup alert handlers
                self._setup_performance_alerts()
                
                # Start metrics collection
                asyncio.create_task(self.metrics_collector.start_collection())
                
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "📊 Performance monitoring started",
                    "success"
                ))
            else:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "📊 Performance monitoring disabled",
                    "warning"
                ))
                
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error initializing performance monitoring: {e}",
                "error"
            ))
    
    def _setup_performance_alerts(self) -> None:
        """Setup performance alert handlers"""
        if self.alert_manager:
            def handle_alert(alert_data):
                alert = alert_data["alert"]
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    f"🚨 {alert.level.value.upper()}: {alert.message} ({alert_data['metric_value']:.1f})",
                    "error" if alert.level.value in ["critical", "emergency"] else "warning"
                ))
            
            self.alert_manager.add_alert_handler(handle_alert)
    
    def update_performance_metrics(self) -> None:
        """Update performance metrics"""
        if not self.metrics_collector or not self.alert_manager:
            return
        
        try:
            # Get current metrics
            current_metrics = self.metrics_collector.get_current_metrics()
            
            # Update P2P metrics if available
            if self.p2p_manager:
                p2p_connections = len(self.p2p_manager.get_connected_peers())
                self.metrics_collector.update_p2p_connections(p2p_connections)
                
        except Exception as e:
            self.status_bar.p2p_status = P2PState.FAILED
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ P2P initialization failed: {e}",
                "error"
            ))
    
    async def open_room_management(self) -> None:
        """Open room management interface"""
        try:
            if self.room_manager:
                # Get user ID
                user_id = getattr(self.net, 'nickname', 'user') if self.net else 'user'
                
                # Create a test room to demonstrate functionality
                from room_manager import RoomSettings
                settings = RoomSettings(
                    max_members=50,
                    allow_guests=True,
                    enable_file_sharing=True,
                    max_file_size_mb=10
                )
                
                room = await self.room_manager.create_room(
                    name=f"Test Room by {user_id}",
                    description="A test room created from modern UI",
                    room_type=RoomType.PUBLIC,
                    owner_id=user_id,
                    settings=settings
                )
                
                if room:
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        f"🏠 Created test room: {room.name} (ID: {room.room_id})",
                        "success"
                    ))
                    
                    # Join the room
                    success = await self.room_manager.join_room(room.room_id, user_id)
                    if success:
                        self.chat_panel.add_message(ChatMessage(
                            "System",
                            f"👥 Joined room: {room.name}",
                            "success"
                        ))
                        
                        # Update room analytics
                        self.room_manager.update_room_analytics(room.room_id, message_count=1, user_id=user_id)
                        
                        # Show room info
                        analytics = self.room_manager.get_room_analytics(room.room_id)
                        if analytics:
                            self.chat_panel.add_message(ChatMessage(
                                "System",
                                f"📊 Room stats: {analytics.total_messages} messages, {analytics.active_users} users",
                                "system"
                            ))
                else:
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        "❌ Failed to create test room",
                        "error"
                    ))
            else:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "❌ Room management not available",
                    "error"
                ))
                
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error opening room management: {e}",
                "error"
            ))
    
    async def open_file_transfer(self) -> None:
        """Open file transfer interface"""
        try:
            if self.file_transfer_manager:
                # Add missing imports
                from file_transfer import CompressionType, EncryptionType
                
                # Create a test file to demonstrate functionality
                test_data = b"This is a test file for the enhanced file transfer system.\n" \
                               b"It demonstrates security, compression, and encryption features.\n" \
                               b"Created at: " + str(time.ctime()).encode()
                
                test_filename = f"test_file_{int(time.time())}.txt"
                
                # Upload test file
                success, file_id, message = await self.file_transfer_manager.upload_file(
                    test_filename,
                    test_data,
                    self.net.room if self.net else "test_room",
                    getattr(self.net, "nickname", "test_user") if self.net else "test_user",
                    compression_type=CompressionType.GZIP,
                    encryption_type=EncryptionType.AES256_GCM
                )
                
                if success:
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        f"📁 Uploaded test file: {test_filename} ({len(test_data)} bytes) -> {file_id[:8]}...",
                        "success"
                    ))
                    
                    # Get file info
                    file_info = self.file_transfer_manager.get_file_info(file_id)
                    if file_info:
                        self.chat_panel.add_message(ChatMessage(
                            "System",
                            f"📊 File info: {file_info.filename} ({file_info.file_size} bytes)",
                            "system"
                        ))
                        
                        # Show compression and encryption info
                        compression_ratio = "N/A"
                        if file_info.is_compressed:
                            compression_ratio = f"{(1 - file_info.file_size / len(test_data)):.1%}"
                        
                        self.chat_panel.add_message(ChatMessage(
                            "System",
                            f"🗜️ Compression: {file_info.compression_type.value} ({compression_ratio} reduction)",
                            "system"
                        ))
                        
                        self.chat_panel.add_message(
                            "System",
                            f"🔐 Encryption: {file_info.encryption_type.value}",
                            "system"
                        )
                        
                        # Show chunk info
                        self.chat_panel.add_message(
                            "System",
                            f"📦 Chunks: {file_info.chunk_count} ({self.file_transfer_manager.chunk_size} bytes each)",
                            "system"
                        )
                        
                        # Test download
                        download_success, downloaded_data, error = await self.file_transfer_manager.download_file(
                            file_id,
                            getattr(self.net, "nickname", "test_user") if self.net else "test_user"
                        )
                        
                        if download_success:
                            self.chat_panel.add_message(
                                "System",
                                f"✅ Downloaded and verified file: {len(downloaded_data)} bytes",
                                "success"
                            )
                            
                            # Verify integrity
                            if downloaded_data == test_data:
                                self.chat_panel.add_message(
                                    "System",
                                    "✅ File integrity verified",
                                    "success"
                                )
                            else:
                                self.chat_panel.add_message(
                                    "System",
                                    "❌ File integrity check failed",
                                    "error"
                                )
                        else:
                            self.chat_panel.add_message(
                                "System",
                                f"❌ Download failed: {error}",
                                "error"
                            )
                else:
                    self.chat_panel.add_message(
                        "System",
                        f"❌ Failed to upload test file: {message}",
                        "error"
                    )
            else:
                self.chat_panel.add_message(
                    "System",
                    "❌ File transfer not available",
                    "error"
                )
            
        except Exception as e:
            self.chat_panel.add_message(
                "System",
                f"❌ Error opening file transfer: {e}",
                "error"
            )
    
    async def open_user_management(self) -> None:
        """Open user management interface"""
        try:
            if self.user_manager:
                # Create test users to demonstrate functionality
                from user_manager import UserRole
                
                # Create test users
                success1, user1_id = await self.user_manager.create_user(
                    "alice_admin", "alice@example.com", "secure123456", 
                    "Alice Admin", "System administrator with full access",
                    role=UserRole.ADMIN
                )
                
                success2, user2_id = await self.user_manager.create_user(
                    "bob_moderator", "bob@example.com", "secure123456",
                    "Bob Moderator", "Room moderator with limited admin access",
                    role=UserRole.MODERATOR
                )
                
                success3, user3_id = await self.user_manager.create_user(
                    "charlie_member", "charlie@example.com", "secure123456",
                    "Charlie Member", "Regular user with basic permissions",
                    role=UserRole.MEMBER
                )
                
                if success1 and user1_id:
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        f"👥 Created admin user: alice_admin ({user1_id[:8]}...)",
                        "success"
                    ))
                    
                    # Get user info
                    user_info = self.user_manager.get_user_by_id(user1_id)
                    if user_info:
                        self.chat_panel.add_message(ChatMessage(
                            "System",
                            f"📊 User info: {user_info.username} ({user_info.role.value})",
                            "system"
                        ))
                        
                        # Show role and permissions
                        self.chat_panel.add_message(ChatMessage(
                            "System",
                            f"🔐 Role: {user_info.role.value} with {len(user_info.permissions)} permissions",
                            "system"
                        ))
                        
                        self.chat_panel.add_message(
                            "System",
                            f"📝 Status: {user_info.status.value}",
                            "system"
                        )
                        
                        # Test authentication
                        auth_success, session_id = await self.user_manager.authenticate_user("alice_admin", "secure123456")
                        if auth_success:
                            self.chat_panel.add_message(
                                "System",
                                f"✅ Authentication successful: {session_id[:8]}...",
                                "success"
                            )
                        else:
                            self.chat_panel.add_message(
                                "System",
                                f"❌ Authentication failed",
                                "error"
                            )
            
                if success2 and user2_id:
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        f"👥 Created moderator user: bob_moderator ({user2_id[:8]}...)",
                        "success"
                    ))
            
                if success3 and user3_id:
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        f"👥 Created member user: charlie_member ({user3_id[:8]}...)",
                        "success"
                    ))
            
                # Show global statistics
                stats = self.user_manager.get_global_statistics()
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    f"📊 Global stats: {stats['total_users']} users, {stats['active_users']} active",
                    "system"
                ))
            
                # Test user management operations
                if user2_id:
                    # Promote moderator to admin
                    promote_success = self.user_manager.promote_user(user2_id, UserRole.ADMIN)
                    if promote_success:
                        self.chat_panel.add_message(
                            "System",
                            f"📈 Promoted bob_moderator to admin",
                            "success"
                        )
            
                # Test session management
                if user1_id:
                    sessions = self.user_manager.session_manager.get_user_sessions(user1_id)
                    self.chat_panel.add_message(
                        "System",
                        f"🔐 Active sessions for alice_admin: {len(sessions)}",
                        "system"
                    )
        
        except Exception as e:
            self.chat_panel.add_message(
                "System",
                f"❌ Error opening user management: {e}",
                "error"
            )
    
    async def open_audit_compliance(self) -> None:
        """Open audit and compliance interface"""
        try:
            if self.audit_manager:
                # Log audit system access
                event_id = await self.audit_manager.log_event(
                    AuditEventType.SYSTEM_CONFIG,
                    getattr(self.net, "nickname", "system_user") if self.net else "system_user",
                    "Audit system access",
                    target_resource="audit_compliance_ui",
                    severity=SeverityLevel.INFO
                )
                
                if event_id:
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        f"📋 Audit system accessed: {event_id[:8]}...",
                        "success"
                    ))
                    
                    # Show audit statistics
                    stats = self.audit_manager.get_audit_statistics()
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        f"📊 Audit stats: {stats['total_events']} events, {stats['compliance_rules']['enabled']} rules",
                        "system"
                    ))
                    
                    # Show compliance summary
                    from audit_compliance import ComplianceFramework
                    gdpr_summary = self.audit_manager.get_compliance_summary(ComplianceFramework.GDPR)
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        f"🔒 GDPR compliance: {gdpr_summary['compliance_rate']:.1f}% compliant",
                        "system"
                    ))
                    
                    # Test compliance report generation
                    end_time = time.time()
                    start_time = end_time - (7 * 24 * 3600)  # Last 7 days
                    
                    report_id = await self.audit_manager.generate_compliance_report(
                        ComplianceFramework.GDPR,
                        start_time,
                        end_time
                    )
                    
                    if report_id:
                        self.chat_panel.add_message(ChatMessage(
                            "System",
                            f"📊 Generated GDPR report: {report_id[:8]}...",
                            "success"
                        ))
                        
                        # Get report details
                        report = self.audit_manager.reports.get(report_id)
                        if report:
                            self.chat_panel.add_message(ChatMessage(
                                "System",
                                f"📈 Compliance status: {report.status.value}",
                                "system"
                            ))
                            
                            self.chat_panel.add_message(ChatMessage(
                                "System",
                                f"⚠️ Violations: {report.violations_count}",
                                "warning" if report.violations_count > 0 else "success"
                            ))
                    else:
                        self.chat_panel.add_message(ChatMessage(
                            "System",
                            "❌ Failed to generate compliance report",
                            "error"
                        ))
                else:
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        "❌ Failed to access audit system",
                        "error"
                    ))
            else:
                self.chat_panel.add_message(
                    "System",
                    "❌ Audit and compliance not available",
                    "error"
                )
                
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error opening audit and compliance: {e}",
                "error"
            ))

    def _on_p2p_peer_connected(self, peer_id: str):
        self.status_bar.p2p_peers = len(self.p2p_manager.get_connected_peers())

# ... (rest of the code remains the same)
    def _on_p2p_peer_disconnected(self, peer_id: str):
        """Handle P2P peer disconnection"""
        self.chat_panel.add_message(ChatMessage(
            "System",
            f"🌐 P2P disconnected from {peer_id}",
            "warning"
        ))
        self.status_bar.p2p_peers = len(self.p2p_manager.get_connected_peers())

    def _on_p2p_message_received(self, peer_id: str, message: str):
        """Handle P2P message received"""
        self.chat_panel.add_message(ChatMessage(
            peer_id,
            message,
            "p2p"
        ))
    
    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle input submission"""
        if event.input.id == "message-input":
            await self.send_message()
    
    async def send_message(self) -> None:
        """Send a message"""
        input_box = self.query_one("#message-input", Input)
        message_text = input_box.value.strip()
        
        if not message_text:
            return
        
        if not self.net or not self.net._connected:
            self.chat_panel.add_message(ChatMessage(
                "System",
                "❌ Not connected to server. Press Ctrl+N to connect.",
                "error"
            ))
            input_box.value = ""
            return
        
        try:
            if message_text.startswith("/"):
                # Handle commands
                await self.handle_command(message_text)
            else:
                # Send regular message
                await self.net.send_room_message(message_text)
                self.chat_panel.add_message(ChatMessage(
                    "You",
                    message_text,
                    "chat",
                    room=self.net.room
                ))
                self.status_bar.message_count += 1
                
                # Track message for performance monitoring
                if self.metrics_collector:
                    self.metrics_collector.increment_message_counter(is_p2p=False)
                
                # Also send via P2P if available
                if self.p2p_manager and self.p2p_manager.state == P2PState.CONNECTED:
                    p2p_sent = await self.p2p_manager.broadcast_message(message_text)
                    if p2p_sent > 0:
                        # Track P2P messages
                        if self.metrics_collector:
                            for _ in range(p2p_sent):
                                self.metrics_collector.increment_message_counter(is_p2p=True)
                        
                        self.chat_panel.add_message(ChatMessage(
                            "System",
                            f"🌐 Sent via P2P to {p2p_sent} peers",
                            "system"
                        ))
            
            input_box.value = ""
            
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error sending message: {e}",
                "error"
            ))
    
    async def handle_command(self, command: str) -> None:
        """Handle slash commands"""
        parts = command[1:].split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:] if len(parts) > 1 else []
        
        if cmd == "help":
            self.show_help()
        elif cmd == "clear":
            self.chat_panel.clear_messages()
            self.chat_panel.add_message(ChatMessage(
                "System",
                "✅ Chat history cleared",
                "success"
            ))
        elif cmd == "quit" or cmd == "exit":
            await self.disconnect()
            self.exit()
        elif cmd == "connect":
            self.push_screen(ConnectionModal())
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
        elif cmd == "part" or cmd == "leave":
            await self.leave_room()
        else:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Unknown command: {command}",
                "error"
            ))
    
    def show_help(self) -> None:
        """Show comprehensive help"""
        help_text = """
[bold #58a6ff]🌟 secure-term-chat Commands 🌟[/]

[dim #6e7681]─────────────────────────────────────────[/]

[bold #c9d1d9]Connection Commands:[/]
[dim #6e7681]/connect      - Connect to server[/]
[dim #6e7681]/disconnect   - Disconnect from server[/]
[dim #6e7681]/quit         - Exit application[/]

[bold #c9d1d9]Chat Commands:[/]
[dim #6e7681]/help         - Show this help[/]
[dim #6e7681]/clear        - Clear chat history[/]
[dim #6e7681]/nick <name>  - Change nickname[/]
[dim #6e7681]/join <room>  - Join room[/]
[dim #6e7681]/part         - Leave current room[/]

[bold #c9d1d9]Information Commands:[/]
[dim #6e7681]/rooms        - List available rooms[/]
[dim #6e7681]/users        - List online users[/]
[dim #6e7681]/status       - Show connection status[/]

[bold #c9d1d9]Settings Commands:[/]
[dim #6e7681]/settings     - Open settings menu[/]
[dim #6e7681]/config       - Show current configuration[/]

[dim #6e7681]─────────────────────────────────────────[/]

[bold #c9d1d9]Keyboard Shortcuts:[/]
[dim #6e7681]Ctrl+S         - Settings menu[/]
[dim #6e7681]Ctrl+N         - New connection[/]
[dim #6e7681]Ctrl+L         - Clear chat[/]
[dim #6e7681]Ctrl+H         - Show help[/]
[dim #6e7681]Ctrl+R         - Room list[/]
[dim #6e7681]Ctrl+U         - User list[/]
[dim #6e7681]F1             - Toggle side panel[/]
[dim #6e7681]F2             - Toggle status bar[/]
[dim #6e7681]Escape         - Close modal[/]
[dim #6e7681]Enter          - Send message[/]

[dim #6e7681]─────────────────────────────────────────[/]

[bold #58a6ff]Features:[/]
[dim #6e7681]✅ End-to-end encryption[/]
[dim #6e7681]✅ Forward secrecy[/]
[dim #6e7681]✅ TLS connections[/]
[dim #6e7681]✅ Modern terminal UI[/]
[dim #6e7681]✅ Real-time status[/]
[dim #6e7681]✅ Enhanced security[/]
        """.strip()
        
        self.chat_panel.add_message(ChatMessage(
            "System",
            help_text,
            "system"
        ))
    
    async def handle_password_setup(self) -> None:
        """Handle password setup"""
        try:
            password = self.query_one("#password-input", Input).value.strip()
            confirm_password = self.query_one("#confirm-password-input", Input).value.strip()
            kdf = self.query_one("#kdf-select", Select).value
            
            success = await self.setup_keystore(password, confirm_password, kdf)
            
            if success:
                self.pop_screen()
                # Show connection modal
                self.push_screen(ConnectionModal())
            else:
                # Keep modal open for retry
                pass
                
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error in password setup: {e}",
                "error"
            ))
    
    async def handle_password_unlock(self) -> None:
        """Handle password unlock"""
        try:
            password = self.query_one("#password-input", Input).value.strip()
            
            success = await self.unlock_keystore(password)
            
            if success:
                self.pop_screen()
                # Show connection modal
                self.push_screen(ConnectionModal())
            else:
                # Keep modal open for retry
                pass
                
        except Exception as e:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Error in password unlock: {e}",
                "error"
            ))
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "send-btn":
            await self.send_message()
        elif event.button.id == "connect-btn":
            await self.handle_connect()
        elif event.button.id == "cancel-btn":
            self.pop_screen()
        elif event.button.id == "save-settings":
            await self.save_settings()
        elif event.button.id == "room-management-btn":
            await self.open_room_management()
        elif event.button.id == "file-transfer-btn":
            await self.open_file_transfer()
        elif event.button.id == "user-management-btn":
            await self.open_user_management()
        elif event.button.id == "audit-compliance-btn":
            await self.open_audit_compliance()
        elif event.button.id == "reset-settings":
            await self.reset_settings()
        elif event.button.id == "cancel-settings":
            self.pop_screen()
        elif event.button.id == "setup-btn":
            await self.handle_password_setup()
        elif event.button.id == "unlock-btn":
            await self.handle_password_unlock()
    
    async def handle_connect(self) -> None:
        """Handle connection from modal"""
        try:
            server = self.query_one("#server-input", Input).value.strip()
            nick = self.query_one("#nick-input", Input).value.strip()
            room = self.query_one("#room-input", Input).value.strip()
            use_tls = self.query_one("#tls-checkbox", Checkbox).value
            
            if not server or not nick or not room:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "❌ Please fill in all connection details",
                    "error"
                ))
                return
            
            # Check keystore status
            if not self.keystore:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "❌ Keystore not available. Please setup password first.",
                    "error"
                ))
                return
            
            # Disconnect existing connection
            if self.net and self.net._connected:
                await self.disconnect()
            
            # Create new client
            self.net = ChatNetworkClient(server, nick, room, use_tls)
            
            # Update status
            self.status_bar.state = UIState.CONNECTING
            self.status_bar.server_info = server
            self.status_bar.user_info = nick
            self.status_bar.room_info = room
            
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"🔄 Connecting to {server}...",
                "system"
            ))
            
            # Connect
            success = await self.net.connect()
            
            if success:
                self.status_bar.state = UIState.CONNECTED
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    f"✅ Connected to {server} as {nick} in {room}",
                    "success"
                ))
                
                # Store identity in keystore
                try:
                    identity_key = self.net.identity
                    if identity_key:
                        keystore_success = self.keystore.store_identity_key(identity_key, f"{nick}@{server}")
                        if keystore_success:
                            self.chat_panel.add_message(ChatMessage(
                                "System",
                                "🔐 Identity key stored in encrypted keystore",
                                "success"
                            ))
                except Exception as e:
                    self.chat_panel.add_message(ChatMessage(
                        "System",
                        f"⚠️ Warning: Could not store identity key: {e}",
                        "warning"
                    ))
                
                # Add current user to user list
                self.user_list.add_user(nick, self.net.fingerprint, "online")
                
                # Initialize P2P if available
                if self.p2p_enabled:
                    await self._initialize_p2p(nick, room)
                
                # Start message handling
                asyncio.create_task(self.handle_messages())
                
                self.pop_screen()
            else:
                self.status_bar.state = UIState.ERROR
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    "❌ Failed to connect to server",
                    "error"
                ))
        
        except Exception as e:
            self.status_bar.state = UIState.ERROR
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"❌ Connection error: {e}",
                "error"
            ))
    
    async def handle_messages(self) -> None:
        """Handle incoming messages"""
        while self.net and self.net._connected:
            try:
                if not self.net._msg_queue.empty():
                    msg = self.net._msg_queue.get_nowait()
                    await self.process_message(msg)
                else:
                    await asyncio.sleep(0.1)
            except Exception as e:
                self.chat_panel.add_message(ChatMessage(
                    "System",
                    f"❌ Message handling error: {e}",
                    "error"
                ))
                break
    
    async def process_message(self, msg: dict) -> None:
        """Process incoming message"""
        msg_type = msg.get("type", "unknown")
        
        if msg_type == "chat":
            sender = msg.get("from", "Unknown")
            content = msg.get("msg", "")
            
            self.chat_panel.add_message(ChatMessage(
                sender,
                content,
                "chat",
                room=msg.get("room", "")
            ))
            
            # Add user to list if not present
            if sender != "You" and sender not in self.user_list.users:
                self.user_list.add_user(sender, "unknown", "online")
                
        elif msg_type == "pm":
            self.chat_panel.add_message(ChatMessage(
                msg.get("from", "Unknown"),
                msg.get("msg", ""),
                "pm"
            ))
        elif msg_type == "system":
            self.chat_panel.add_message(ChatMessage(
                "System",
                msg.get("msg", ""),
                "system"
            ))
        elif msg_type == "event":
            event_msg = msg.get("msg", "")
            self.chat_panel.add_message(ChatMessage(
                "System",
                event_msg,
                "event",
                metadata=msg
            ))
            
            # Handle user join/leave events
            if "joined" in event_msg.lower():
                # Extract nick from event message
                parts = event_msg.split()
                if len(parts) >= 3:
                    nick = parts[2].rstrip("!")
                    self.user_list.add_user(nick, "unknown", "online")
            elif "left" in event_msg.lower():
                # Extract nick from event message
                parts = event_msg.split()
                if len(parts) >= 2:
                    nick = parts[1]
                    self.user_list.remove_user(nick)
                    
        elif msg_type == "error":
            self.chat_panel.add_message(ChatMessage(
                "System",
                msg.get("msg", ""),
                "error"
            ))
    
    async def disconnect(self) -> None:
        """Disconnect from server"""
        if self.net:
            await self.net.disconnect()
            self.status_bar.state = UIState.DISCONNECTED
            self.chat_panel.add_message(ChatMessage(
                "System",
                "👋 Disconnected from server",
                "system"
            ))
        
        # Stop P2P manager
        if self.p2p_manager:
            await self.p2p_manager.stop()
            self.p2p_manager = None
            self.status_bar.p2p_status = P2PState.DISCONNECTED
            self.status_bar.p2p_peers = 0
        
        # Stop performance monitoring
        if self.metrics_collector:
            self.metrics_collector.stop_collection()
            self.metrics_collector = None
        
        if self.alert_manager:
            self.alert_manager = None
        
        # Clear user list (always)
        self.user_list.users.clear()
        self.user_list.refresh()
    
    def update_status(self) -> None:
        """Update status panel"""
        if self.net and self.net._connected:
            self.status_bar.state = UIState.CONNECTED
        else:
            self.status_bar.state = UIState.DISCONNECTED
    
    def update_ui(self) -> None:
        """Update UI elements"""
        # This would update various UI elements
        pass
    
    async def save_settings(self) -> None:
        """Save settings"""
        self.chat_panel.add_message(ChatMessage(
            "System",
            "✅ Settings saved successfully",
            "success"
        ))
        self.pop_screen()
    
    async def reset_settings(self) -> None:
        """Reset settings to defaults"""
        self.chat_panel.add_message(ChatMessage(
            "System",
            "🔄 Settings reset to defaults",
            "system"
        ))
    
    async def show_room_list(self) -> None:
        """Show room list"""
        if self.net and self.net._connected:
            await self.net.request_room_list()
        else:
            self.chat_panel.add_message(ChatMessage(
                "System",
                "❌ Not connected to server",
                "error"
            ))
    
    async def show_user_list(self) -> None:
        """Show user list"""
        if self.net and self.net._connected:
            # Request user list
            pass
        else:
            self.chat_panel.add_message(ChatMessage(
                "System",
                "❌ Not connected to server",
                "error"
            ))
    
    async def change_nick(self, new_nick: str) -> None:
        """Change nickname"""
        if self.net and self.net._connected:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"🔄 Changing nickname to {new_nick}...",
                "system"
            ))
            # Implement nickname change
        else:
            self.chat_panel.add_message(ChatMessage(
                "System",
                "❌ Not connected to server",
                "error"
            ))
    
    async def join_room(self, room_name: str) -> None:
        """Join a room"""
        if self.net and self.net._connected:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"🏠 Joining room {room_name}...",
                "system"
            ))
            # Implement room join
        else:
            self.chat_panel.add_message(ChatMessage(
                "System",
                "❌ Not connected to server",
                "error"
            ))
    
    async def leave_room(self) -> None:
        """Leave current room"""
        if self.net and self.net._connected:
            self.chat_panel.add_message(ChatMessage(
                "System",
                f"👋 Leaving room {self.net.room}...",
                "system"
            ))
            # Implement room leave
        else:
            self.chat_panel.add_message(ChatMessage(
                "System",
                "❌ Not connected to server",
                "error"
            ))
    
    # Actions
    def action_settings(self) -> None:
        """Show settings modal"""
        self.push_screen(SettingsModal())
    
    def action_connect(self) -> None:
        """Show connection modal"""
        self.push_screen(ConnectionModal())
    
    def action_clear(self) -> None:
        """Clear chat"""
        self.chat_panel.clear_messages()
    
    def action_help(self) -> None:
        """Show help"""
        self.show_help()
    
    def action_room_list(self) -> None:
        """Show room list"""
        asyncio.create_task(self.show_room_list())
    
    def action_user_list(self) -> None:
        """Show user list"""
        asyncio.create_task(self.show_user_list())
    
    def action_send_message(self) -> None:
        """Send message action"""
        asyncio.create_task(self.send_message())
    
    def action_toggle_side_panel(self) -> None:
        """Toggle side panel visibility"""
        side_panel = self.query_one("#side-panel")
        if self.side_panel_visible:
            side_panel.display = False
        else:
            side_panel.display = True
        self.side_panel_visible = not self.side_panel_visible
    
    def action_toggle_status(self) -> None:
        """Toggle status panel visibility"""
        status_bar = self.query_one("#status-bar")
        status_bar.display = not status_bar.display
        self.status_visible = status_bar.display

    def action_dismiss_modal(self) -> None:
        """Dismiss any modal"""
        if self.screen_stack:
            self.pop_screen()

# Main entry point
if __name__ == "__main__":
    app = ModernChatApp()
    app.run()