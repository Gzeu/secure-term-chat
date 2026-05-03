#!/usr/bin/env python3
"""
Enhanced Terminal UI for secure-term-chat
Modern, professional, and feature-rich interface
"""

import asyncio
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum

from textual.app import App, ComposeResult
from textual.containers import (
    Horizontal, Vertical, Container, ScrollableContainer,
    Center, Middle, Grid
)
from textual.widgets import (
    Header, Footer, Static, RichLog, Input, Button, 
    ProgressBar, ListView, ListItem, Label, Switch,
    DataTable, Tabs, TabPane, TabbedContent, Tree,
    Panel, Placeholder, Checkbox, Select
)
from textual.reactive import reactive
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.message import Message
from textual import work
from rich.text import Text
from rich.markup import escape
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.columns import Columns
from rich.console import Console

# Import existing client
from client import ChatNetworkClient

class UIState(Enum):
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"

class Message:
    def __init__(self, sender: str, content: str, msg_type: str = "chat", 
                 timestamp: float = None, room: str = "", metadata: dict = None):
        self.sender = sender
        self.content = content
        self.type = msg_type
        self.timestamp = timestamp or time.time()
        self.room = room
        self.metadata = metadata or {}
    
    def to_rich_text(self) -> Text:
        """Convert message to rich text for display"""
        time_str = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        
        if self.type == "chat":
            prefix = f"[dim #8b949e]{time_str}[/] "
            sender_text = f"[bold #e2e8f0]{self.sender}[/]: "
            content_text = self.content
        elif self.type == "pm":
            prefix = f"[dim #8b949e]{time_str}[/] "
            sender_text = f"[bold #ff79c6]💬 PM ← {self.sender}[/]: "
            content_text = self.content
        elif self.type == "system":
            prefix = f"[dim #8b949e]{time_str}[/] "
            sender_text = "[bold #58a6ff]ℹ️ [/]"
            content_text = self.content
        elif self.type == "error":
            prefix = f"[dim #8b949e]{time_str}[/] "
            sender_text = "[bold #f85149]❌ [/]"
            content_text = self.content
        elif self.type == "event":
            color = "#56d364" if self.metadata.get("trust") in ("OK", "NEW") else "#f85149"
            prefix = f"[dim #8b949e]{time_str}[/] "
            sender_text = f"[bold {color}]▶ [/]"
            content_text = self.content
        else:
            prefix = f"[dim #8b949e]{time_str}[/] "
            sender_text = f"[bold #79c0ff]{self.type}[/]: "
            content_text = self.content
        
        return Text.assemble(prefix, sender_text, content_text)

class RoomInfo:
    def __init__(self, name: str, member_count: int = 0, is_private: bool = False, 
                 is_ephemeral: bool = False, ttl: int = 0):
        self.name = name
        self.member_count = member_count
        self.is_private = is_private
        self.is_ephemeral = is_ephemeral
        self.ttl = ttl
        self.unread_count = 0
        self.last_activity = time.time()

class UserInfo:
    def __init__(self, nick: str, fingerprint: str, status: str = "online", 
                 room: str = "", is_typing: bool = False):
        self.nick = nick
        self.fingerprint = fingerprint
        self.status = status  # online, away, busy, offline
        self.room = room
        self.is_typing = is_typing
        self.last_seen = time.time()

class ConnectionModal(ModalScreen):
    """Modal for connection settings"""
    
    BINDINGS = [("escape", "dismiss", "Close")]
    
    def compose(self) -> ComposeResult:
        with Container(id="connection-modal"):
            yield Static("🔗 Connection Settings", classes="modal-title")
            
            with Vertical():
                yield Label("Server Address:")
                yield Input(placeholder="localhost:12345", id="server-input")
                
                yield Label("Nickname:")
                yield Input(placeholder="YourNickname", id="nick-input")
                
                yield Label("Room:")
                yield Input(placeholder="#crypto", id="room-input")
                
                yield Label("Security:")
                with Horizontal():
                    yield Checkbox("Use TLS", value=True, id="tls-checkbox")
                    yield Checkbox("Advanced Security", value=False, id="advanced-checkbox")
                
                with Horizontal(id="connection-buttons"):
                    yield Button("Connect", variant="primary", id="connect-btn")
                    yield Button("Cancel", id="cancel-btn")

class SettingsModal(ModalScreen):
    """Modal for application settings"""
    
    BINDINGS = [("escape", "dismiss", "Close")]
    
    def compose(self) -> ComposeResult:
        with Container(id="settings-modal"):
            yield Static("⚙️ Settings", classes="modal-title")
            
            with TabbedContent():
                with TabPane("Appearance", id="appearance-tab"):
                    with Vertical():
                        yield Label("Theme:")
                        yield Select(
                            [("Dark", "dark"), ("Light", "light"), ("Auto", "auto")],
                            value="dark",
                            id="theme-select"
                        )
                        
                        yield Label("Font Size:")
                        yield Select(
                            [("Small", "small"), ("Medium", "medium"), ("Large", "large")],
                            value="medium",
                            id="font-size-select"
                        )
                        
                        yield Label("Animations:")
                        yield Switch(value=True, id="animations-switch")
                        
                        yield Label("Show Timestamps:")
                        yield Switch(value=True, id="timestamps-switch")
                
                with TabPane("Security", id="security-tab"):
                    with Vertical():
                        yield Label("Encryption:")
                        yield Switch(value=True, id="encryption-switch")
                        
                        yield Label("Forward Secrecy:")
                        yield Switch(value=True, id="forward-secrecy-switch")
                        
                        yield Label("P2P Mode:")
                        yield Switch(value=False, id="p2p-switch")
                        
                        yield Label("Ephemeral Messages:")
                        yield Switch(value=False, id="ephemeral-switch")
                        
                        yield Label("Default TTL (hours):")
                        yield Input(placeholder="24", id="ttl-input")
                
                with TabPane("Notifications", id="notifications-tab"):
                    with Vertical():
                        yield Label("Message Notifications:")
                        yield Switch(value=True, id="message-notifications")
                        
                        yield Label("User Join/Leave:")
                        yield Switch(value=True, id="user-notifications")
                        
                        yield Label("Sound Alerts:")
                        yield Switch(value=False, id="sound-alerts")
                        
                        yield Label("Desktop Notifications:")
                        yield Switch(value=False, id="desktop-notifications")
                
                with TabPane("Advanced", id="advanced-tab"):
                    with Vertical():
                        yield Label("Debug Mode:")
                        yield Switch(value=False, id="debug-switch")
                        
                        yield Label("Performance Monitoring:")
                        yield Switch(value=True, id="monitoring-switch")
                        
                        yield Label("Auto-reconnect:")
                        yield Switch(value=True, id="auto-reconnect-switch")
                        
                        yield Label("Max File Size (MB):")
                        yield Input(placeholder="10", id="max-file-size")
            
            with Horizontal(id="settings-buttons"):
                yield Button("Save", variant="primary", id="save-settings")
                yield Button("Reset", id="reset-settings")
                yield Button("Cancel", id="cancel-settings")

class RoomInfoPanel(Static):
    """Panel showing room information"""
    
    def __init__(self, room_info: RoomInfo):
        super().__init__()
        self.room_info = room_info
    
    def render(self) -> RichLog:
        """Render room information"""
        table = Table(show_header=False, box=None, padding=0)
        table.add_column("Property", style="bold #58a6ff")
        table.add_column("Value")
        
        table.add_row("Room:", f"[bold]{self.room_info.name}[/]")
        table.add_row("Members:", f"[#79c0ff]{self.room_info.member_count}[/]")
        
        if self.room_info.is_private:
            table.add_row("Type:", "[#ff79c6]🔒 Private[/]")
        
        if self.room_info.is_ephemeral:
            ttl_hours = self.room_info.ttl // 3600
            table.add_row("TTL:", f"[#f85149]⏰ {ttl_hours}h[/]")
        
        return Panel(table, title="🏠 Room Info")

class UserListPanel(Static):
    """Panel showing online users"""
    
    def __init__(self):
        super().__init__()
        self.users: Dict[str, UserInfo] = {}
    
    def add_user(self, user: UserInfo):
        """Add or update user"""
        self.users[user.nick] = user
        self.refresh()
    
    def remove_user(self, nick: str):
        """Remove user"""
        if nick in self.users:
            del self.users[nick]
            self.refresh()
    
    def render(self) -> RichLog:
        """Render user list"""
        if not self.users:
            return Panel("[dim #8b949e]No users online[/]", title="👥 Users")
        
        table = Table(show_header=False, box=None, padding=0)
        table.add_column("Status", width=2)
        table.add_column("Nick", style="bold #e2e8f0")
        table.add_column("Fingerprint", style="dim #8b949e")
        
        # Sort users by status and nick
        sorted_users = sorted(
            self.users.values(),
            key=lambda u: (u.status != "online", u.nick.lower())
        )
        
        for user in sorted_users:
            status_icon = {
                "online": "🟢",
                "away": "🟡", 
                "busy": "🔴",
                "offline": "⚫"
            }.get(user.status, "❓")
            
            nick_text = user.nick
            if user.is_typing:
                nick_text += " [dim](typing...)[/]"
            
            fp_short = user.fingerprint[:8] + "..."
            
            table.add_row(status_icon, nick_text, fp_short)
        
        return Panel(table, title=f"👥 Users ({len(self.users)})")

class MessageList(Static):
    """Enhanced message display with rich formatting"""
    
    def __init__(self):
        super().__init__()
        self.messages: List[Message] = []
        self.max_messages = 1000
    
    def add_message(self, message: Message):
        """Add a message to the list"""
        self.messages.append(message)
        
        # Keep only the last max_messages
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]
        
        self.refresh()
    
    def clear_messages(self):
        """Clear all messages"""
        self.messages = []
        self.refresh()
    
    def render(self) -> RichLog:
        """Render messages"""
        if not self.messages:
            return Panel(
                "[dim #8b949e]No messages yet. Start a conversation![/]",
                title="💬 Chat"
            )
        
        # Create rich text for all messages
        message_lines = []
        for message in self.messages:
            message_lines.append(message.to_rich_text())
        
        return Panel(
            "\n".join(str(line) for line in message_lines),
            title="💬 Chat",
            border_style="#3a3f5c"
        )

class StatusPanel(Static):
    """Status and connection information panel"""
    
    state = reactive(UIState.DISCONNECTED)
    server_info = reactive("")
    user_info = reactive("")
    
    def render(self) -> RichLog:
        """Render status panel"""
        state_colors = {
            UIState.CONNECTING: "#ff79c6",
            UIState.CONNECTED: "#56d364", 
            UIState.DISCONNECTED: "#8b949e",
            UIState.ERROR: "#f85149"
        }
        
        state_icons = {
            UIState.CONNECTING: "🔄",
            UIState.CONNECTED: "🟢",
            UIState.DISCONNECTED: "⚫",
            UIState.ERROR: "❌"
        }
        
        color = state_colors.get(self.state, "#8b949e")
        icon = state_icons.get(self.state, "❓")
        
        status_text = f"[bold {color}]{icon} {self.state.value.title()}[/]"
        
        table = Table(show_header=False, box=None, padding=0)
        table.add_row("Status:", status_text)
        
        if self.server_info:
            table.add_row("Server:", f"[#79c0ff]{self.server_info}[/]")
        
        if self.user_info:
            table.add_row("User:", f"[#e2e8f0]{self.user_info}[/]")
        
        return Panel(table, title="📊 Status")

class EnhancedChatApp(App):
    """Enhanced terminal chat application"""
    
    CSS = """
    /* Main Application Styles */
    Screen {
        background: #0d1117;
        text-style: normal;
    }
    
    /* Modal Styles */
    #connection-modal, #settings-modal {
        background: #161b22;
        border: solid #30363d;
        padding: 2;
        margin: 2;
        width: 60;
        height: 25;
    }
    
    .modal-title {
        text-align: center;
        text-style: bold;
        color: #58a6ff;
        margin: 1 0;
    }
    
    #connection-buttons, #settings-buttons {
        height: 3;
        dock: bottom;
        padding: 1 0;
    }
    
    /* Header Styles */
    Header {
        background: #161b22;
        text-align: center;
        color: #c9d1d9;
        border-bottom: solid #30363d;
    }
    
    /* Footer Styles */
    Footer {
        background: #161b22;
        color: #8b949e;
        border-top: solid #30363d;
    }
    
    /* Main Layout */
    #main-container {
        layout: grid;
        grid-size: 3 1;
        grid-columns: 1fr 20% 1fr;
        padding: 1;
    }
    
    /* Chat Area */
    #chat-area {
        layout: vertical;
        height: 100%;
    }
    
    #message-list {
        height: 1fr;
        border: solid #30363d;
        background: #0d1117;
        padding: 1;
    }
    
    #input-container {
        height: 3;
        border: solid #30363d;
        padding: 1;
        background: #161b22;
    }
    
    #message-input {
        width: 100%;
        border: solid #58a6ff;
        background: #0d1117;
        color: #c9d1d9;
    }
    
    #message-input:focus {
        border: solid #79c0ff;
        background: #0d1117;
    }
    
    /* Side Panel */
    #side-panel {
        layout: vertical;
        height: 100%;
        border-left: solid #30363d;
        padding: 1;
    }
    
    #room-info {
        height: 8;
        border: solid #30363d;
        background: #161b22;
        margin-bottom: 1;
    }
    
    #user-list {
        height: 1fr;
        border: solid #30363d;
        background: #161b22;
        overflow-y: auto;
    }
    
    /* Status Panel */
    #status-panel {
        height: 6;
        border: solid #30363d;
        background: #161b22;
        border-top: solid #30363d;
        margin-top: 1;
    }
    
    /* Button Styles */
    Button {
        width: 100%;
        margin: 0 1;
    }
    
    Button.-primary {
        background: #238636;
        color: white;
        border: solid #2ea043;
    }
    
    Button.-primary:hover {
        background: #2ea043;
        border: solid #3fb950;
    }
    
    /* Input Styles */
    Input, Select {
        width: 100%;
        margin: 0 0 1 0;
        border: solid #30363d;
        background: #0d1117;
        color: #c9d1d9;
    }
    
    Input:focus, Select:focus {
        border: solid #58a6ff;
        background: #0d1117;
    }
    
    /* Checkbox and Switch Styles */
    Checkbox, Switch {
        margin: 0 0 1 0;
    }
    
    /* Tab Styles */
    TabbedContent {
        height: 1fr;
    }
    
    TabPane {
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
        color: #8b949e;
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
        Binding("ctrl+n", "connect", "New Connection"),
        Binding("ctrl+l", "clear", "Clear Chat"),
        Binding("ctrl+h", "help", "Help"),
        Binding("ctrl+r", "room_list", "Room List"),
        Binding("ctrl+u", "user_list", "User List"),
        Binding("f1", "toggle_side_panel", "Toggle Side Panel"),
        Binding("f2", "toggle_status", "Toggle Status"),
        Binding("escape", "dismiss_modal", "Close Modal"),
    ]
    
    def __init__(self):
        super().__init__()
        self.net: Optional[ChatNetworkClient] = None
        self.message_list = MessageList()
        self.user_list = UserListPanel()
        self.status_panel = StatusPanel()
        self.room_info: Optional[RoomInfo] = None
        self.side_panel_visible = True
        self.status_visible = True
    
    def compose(self) -> ComposeResult:
        """Compose the application layout"""
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            # Chat Area (left)
            with Vertical(id="chat-area"):
                yield self.message_list
                with Horizontal(id="input-container"):
                    yield Input(
                        placeholder="Type a message or /command...",
                        id="message-input"
                    )
                    yield Button("Send", variant="primary", id="send-btn")
            
            # Side Panel (right)
            with Vertical(id="side-panel"):
                yield Static("🏠 Room Info", id="room-info")
                yield self.user_list
                yield self.status_panel
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the application"""
        # Focus the input box
        input_box = self.query_one("#message-input", Input)
        self.set_focus(input_box)
        
        # Set up periodic tasks
        self.set_interval(1.0, self.update_status)
        self.set_interval(5.0, self.update_user_list)
        
        # Show connection modal if not connected
        if not self.net or not self.net._connected:
            self.push_screen(ConnectionModal())
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "send-btn":
            await self.send_message()
        elif event.button.id == "connect-btn":
            await self.handle_connect()
        elif event.button.id == "cancel-btn":
            self.dismiss_screen()
    
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
            self.message_list.add_message(Message(
                "System", 
                "Not connected to server", 
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
                self.message_list.add_message(Message(
                    self.net.nick,
                    message_text,
                    "chat",
                    room=self.net.room
                ))
            
            input_box.value = ""
            
        except Exception as e:
            self.message_list.add_message(Message(
                "System",
                f"Error sending message: {e}",
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
            self.message_list.clear_messages()
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
            self.message_list.add_message(Message(
                "System",
                f"Unknown command: {command}",
                "error"
            ))
    
    def show_help(self) -> None:
        """Show help information"""
        help_text = """
🌟 secure-term-chat Commands:

/help          - Show this help
/clear         - Clear chat history
/quit          - Exit application
/connect       - Connect to server
/settings      - Open settings
/rooms         - List available rooms
/users         - List online users
/nick <name>   - Change nickname
/join <room>   - Join room
/part          - Leave current room

Keyboard Shortcuts:
Ctrl+S         - Settings
Ctrl+N         - New connection
Ctrl+L         - Clear chat
Ctrl+H         - Help
Ctrl+R         - Room list
Ctrl+U         - User list
F1             - Toggle side panel
F2             - Toggle status panel
Escape         - Close modal
        """.strip()
        
        self.message_list.add_message(Message(
            "System",
            help_text,
            "system"
        ))
    
    async def handle_connect(self) -> None:
        """Handle connection from modal"""
        try:
            server = self.query_one("#server-input", Input).value.strip()
            nick = self.query_one("#nick-input", Input).value.strip()
            room = self.query_one("#room-input", Input).value.strip()
            use_tls = self.query_one("#tls-checkbox", Checkbox).value
            
            if not server or not nick or not room:
                self.message_list.add_message(Message(
                    "System",
                    "Please fill in all connection details",
                    "error"
                ))
                return
            
            # Disconnect existing connection
            if self.net and self.net._connected:
                await self.disconnect()
            
            # Create new client
            self.net = ChatNetworkClient(server, nick, room, use_tls)
            
            # Connect
            self.status_panel.state = UIState.CONNECTING
            self.status_panel.server_info = server
            self.status_panel.user_info = f"{nick} in {room}"
            
            success = await self.net.connect()
            
            if success:
                self.status_panel.state = UIState.CONNECTED
                self.message_list.add_message(Message(
                    "System",
                    f"Connected to {server} as {nick} in {room}",
                    "system"
                ))
                
                # Update room info
                self.room_info = RoomInfo(room)
                
                # Start message handling
                asyncio.create_task(self.handle_messages())
                
                self.dismiss_screen()
            else:
                self.status_panel.state = UIState.ERROR
                self.message_list.add_message(Message(
                    "System",
                    "Failed to connect to server",
                    "error"
                ))
        
        except Exception as e:
            self.status_panel.state = UIState.ERROR
            self.message_list.add_message(Message(
                "System",
                f"Connection error: {e}",
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
                self.message_list.add_message(Message(
                    "System",
                    f"Message handling error: {e}",
                    "error"
                ))
                break
    
    async def process_message(self, msg: dict) -> None:
        """Process incoming message"""
        msg_type = msg.get("type", "unknown")
        
        if msg_type == "chat":
            self.message_list.add_message(Message(
                msg.get("from", "Unknown"),
                msg.get("msg", ""),
                "chat",
                room=msg.get("room", "")
            ))
        elif msg_type == "pm":
            self.message_list.add_message(Message(
                msg.get("from", "Unknown"),
                msg.get("msg", ""),
                "pm"
            ))
        elif msg_type == "system":
            self.message_list.add_message(Message(
                "System",
                msg.get("msg", ""),
                "system"
            ))
        elif msg_type == "event":
            self.message_list.add_message(Message(
                "System",
                msg.get("msg", ""),
                "event",
                metadata=msg
            ))
        elif msg_type == "error":
            self.message_list.add_message(Message(
                "System",
                msg.get("msg", ""),
                "error"
            ))
    
    async def disconnect(self) -> None:
        """Disconnect from server"""
        if self.net:
            await self.net.disconnect()
            self.status_panel.state = UIState.DISCONNECTED
            self.message_list.add_message(Message(
                "System",
                "Disconnected from server",
                "system"
            ))
    
    def update_status(self) -> None:
        """Update status panel"""
        if self.net and self.net._connected:
            self.status_panel.state = UIState.CONNECTED
        else:
            self.status_panel.state = UIState.DISCONNECTED
    
    def update_user_list(self) -> None:
        """Update user list (placeholder)"""
        # This would be populated with actual user data
        pass
    
    def action_settings(self) -> None:
        """Show settings modal"""
        self.push_screen(SettingsModal())
    
    def action_connect(self) -> None:
        """Show connection modal"""
        self.push_screen(ConnectionModal())
    
    def action_clear(self) -> None:
        """Clear chat"""
        self.message_list.clear_messages()
    
    def action_help(self) -> None:
        """Show help"""
        self.show_help()
    
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
        status_panel = self.query_one("#status-panel")
        if self.status_visible:
            status_panel.display = False
        else:
            status_panel.display = True
        self.status_visible = not self.status_visible

# Main entry point
if __name__ == "__main__":
    app = EnhancedChatApp()
    app.run()
