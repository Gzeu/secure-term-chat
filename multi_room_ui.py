#!/usr/bin/env python3
"""
Multi-room Management UI for secure-term-chat
Advanced room management interface with permissions and analytics
"""

import asyncio
import time
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from enum import Enum

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, RichLog, Input, Button, 
    ProgressBar, Label, DataTable, Tabs, TabPane, TabbedContent,
    Select, Switch, Checkbox, Placeholder
)
from textual.reactive import reactive
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.message import Message
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.columns import Columns
from rich.console import Console

from room_manager import (
    RoomManager, Room, RoomType, UserRole, RoomPermission,
    RoomSettings, RoomAnalytics, create_room_manager
)

class RoomManagementScreen(ModalScreen):
    """Screen for room management operations"""
    
    def __init__(self, room_manager: RoomManager, user_id: str):
        super().__init__()
        self.room_manager = room_manager
        self.user_id = user_id
        self.selected_room: Optional[Room] = None
    
    def compose(self) -> ComposeResult:
        """Compose room management screen"""
        with Container(id="room-management-container"):
            yield Static("🏠 Room Management", classes="screen-title")
            
            with Horizontal():
                # Room list
                with Vertical(id="room-list-container"):
                    yield Static("Your Rooms", classes="section-title")
                    yield DataTable(id="room-list")
                    yield Button("➕ Create Room", id="create-room-btn")
                    yield Button("🔄 Refresh", id="refresh-rooms-btn")
                
                # Room details
                with Vertical(id="room-details-container"):
                    yield Static("Room Details", classes="section-title")
                    yield Static("Select a room to view details", id="room-details")
                    yield Button("⚙️ Settings", id="room-settings-btn", disabled=True)
                    yield Button("👥 Members", id="room-members-btn", disabled=True)
                    yield Button("📊 Analytics", id="room-analytics-btn", disabled=True)
                    yield Button("🗑️ Delete", id="delete-room-btn", disabled=True)
    
    def on_mount(self) -> None:
        """Initialize screen"""
        self._setup_room_list()
        self._load_rooms()
    
    def _setup_room_list(self):
        """Setup room list table"""
        table = self.query_one("#room-list", DataTable)
        table.add_columns("Name", "Type", "Members", "Created")
        table.cursor_type = "row"
    
    def _load_rooms(self):
        """Load user's rooms"""
        table = self.query_one("#room-list", DataTable)
        table.clear()
        
        rooms = self.room_manager.get_user_rooms(self.user_id)
        
        for room in rooms:
            created_time = time.strftime("%Y-%m-%d", time.localtime(room.created_at))
            table.add_row(
                room.name,
                room.room_type.value,
                str(len(room.members)),
                created_time
            )
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "create-room-btn":
            await self._show_create_room_modal()
        elif event.button.id == "refresh-rooms-btn":
            self._load_rooms()
        elif event.button.id == "room-settings-btn":
            await self._show_room_settings()
        elif event.button.id == "room-members-btn":
            await self._show_room_members()
        elif event.button.id == "room-analytics-btn":
            await self._show_room_analytics()
        elif event.button.id == "delete-room-btn":
            await self._delete_room()
    
    def on_data_table_selected(self, event: DataTable.Selected) -> None:
        """Handle room selection"""
        if event.row_key is not None:
            table = event.data_table
            row_data = table.get_row(event.row_key)
            
            # Find room by name
            rooms = self.room_manager.get_user_rooms(self.user_id)
            for room in rooms:
                if room.name == row_data[0]:  # Name column
                    self.selected_room = room
                    self._update_room_details()
                    break
    
    def _update_room_details(self):
        """Update room details display"""
        if not self.selected_room:
            return
        
        details = self.query_one("#room-details", Static)
        
        # Create room info table
        info_table = Table(show_header=False, box=None)
        info_table.add_column("Property", style="#58a6ff")
        info_table.add_column("Value", style="#c9d1d9")
        
        info_table.add_row("Name", self.selected_room.name)
        info_table.add_row("Description", self.selected_room.description)
        info_table.add_row("Type", self.selected_room.room_type.value)
        info_table.add_row("Owner", self.selected_room.owner_id)
        info_table.add_row("Members", str(len(self.selected_room.members)))
        info_table.add_row("Created", time.strftime("%Y-%m-%d %H:%M", time.localtime(self.selected_room.created_at)))
        
        details.update(Panel(info_table, title="Room Information"))
        
        # Enable buttons
        self.query_one("#room-settings-btn").disabled = False
        self.query_one("#room-members-btn").disabled = False
        self.query_one("#room-analytics-btn").disabled = False
        
        # Only enable delete for owners
        is_owner = self.selected_room.owner_id == self.user_id
        self.query_one("#delete-room-btn").disabled = not is_owner
    
    async def _show_create_room_modal(self):
        """Show create room modal"""
        modal = CreateRoomModal(self.room_manager, self.user_id)
        await self.app.push_screen(modal, self._on_room_created)
    
    async def _on_room_created(self, result):
        """Handle room creation result"""
        if result:
            self._load_rooms()
            self.app.bell()  # Notification sound
    
    async def _show_room_settings(self):
        """Show room settings modal"""
        if self.selected_room:
            modal = RoomSettingsModal(self.room_manager, self.selected_room, self.user_id)
            await self.app.push_screen(modal)
    
    async def _show_room_members(self):
        """Show room members modal"""
        if self.selected_room:
            modal = RoomMembersModal(self.room_manager, self.selected_room, self.user_id)
            await self.app.push_screen(modal)
    
    async def _show_room_analytics(self):
        """Show room analytics modal"""
        if self.selected_room:
            modal = RoomAnalyticsModal(self.room_manager, self.selected_room)
            await self.app.push_screen(modal)
    
    async def _delete_room(self):
        """Delete selected room"""
        if self.selected_room:
            # Confirm deletion
            modal = ConfirmModal(
                "Delete Room",
                f"Are you sure you want to delete '{self.selected_room.name}'? This action cannot be undone.",
                "Delete"
            )
            result = await self.app.push_screen(modal)
            
            if result:
                success = await self.room_manager.delete_room(self.selected_room.room_id, self.user_id)
                if success:
                    self.selected_room = None
                    self._load_rooms()
                    self.query_one("#room-details").update(Static("Select a room to view details"))
                    self.app.bell()

class CreateRoomModal(ModalScreen):
    """Modal for creating new rooms"""
    
    def __init__(self, room_manager: RoomManager, user_id: str):
        super().__init__()
        self.room_manager = room_manager
        self.user_id = user_id
    
    def compose(self) -> ComposeResult:
        """Compose create room modal"""
        with Container(id="create-room-modal"):
            yield Static("➕ Create New Room", classes="modal-title")
            
            with Vertical():
                yield Label("Room Name:")
                yield Input(placeholder="Enter room name...", id="room-name-input")
                
                yield Label("Description:")
                yield Input(placeholder="Enter room description...", id="room-description-input")
                
                yield Label("Room Type:")
                yield Select(
                    options=[
                        ("Public", "public"),
                        ("Private", "private"),
                        ("Restricted", "restricted"),
                        ("Temporary", "temporary")
                    ],
                    value="public",
                    id="room-type-select"
                )
                
                yield Label("Max Members:")
                yield Input(value="50", id="max-members-input")
                
                yield Horizontal():
                    yield Switch(value=True, id="allow-guests-switch")
                    yield Label("Allow Guests")
                
                yield Horizontal():
                    yield Switch(value=True, id="enable-file-sharing-switch")
                    yield Label("Enable File Sharing")
                
                yield Horizontal():
                    yield Button("✅ Create", id="create-btn", variant="primary")
                    yield Button("❌ Cancel", id="cancel-btn")

class RoomSettingsModal(ModalScreen):
    """Modal for room settings"""
    
    def __init__(self, room_manager: RoomManager, room: Room, user_id: str):
        super().__init__()
        self.room_manager = room_manager
        self.room = room
        self.user_id = user_id
    
    def compose(self) -> ComposeResult:
        """Compose room settings modal"""
        with Container(id="room-settings-modal"):
            yield Static("⚙️ Room Settings", classes="modal-title")
            
            with Vertical():
                yield Label("Room Name:")
                yield Input(value=self.room.name, id="room-name-input")
                
                yield Label("Description:")
                yield Input(value=self.room.description, id="room-description-input")
                
                yield Label("Max Members:")
                yield Input(value=str(self.room.settings.max_members), id="max-members-input")
                
                yield Horizontal():
                    yield Switch(value=self.room.settings.allow_guests, id="allow-guests-switch")
                    yield Label("Allow Guests")
                
                yield Horizontal():
                    yield Switch(value=self.room.settings.enable_file_sharing, id="enable-file-sharing-switch")
                    yield Label("Enable File Sharing")
                
                yield Label("Max File Size (MB):")
                yield Input(value=str(self.room.settings.max_file_size_mb), id="max-file-size-input")
                
                yield Horizontal():
                    yield Switch(value=self.room.settings.enable_analytics, id="enable-analytics-switch")
                    yield Label("Enable Analytics")
                
                yield Horizontal():
                    yield Button("💾 Save", id="save-btn", variant="primary")
                    yield Button("❌ Cancel", id="cancel-btn")

class RoomMembersModal(ModalScreen):
    """Modal for room members management"""
    
    def __init__(self, room_manager: RoomManager, room: Room, user_id: str):
        super().__init__()
        self.room_manager = room_manager
        self.room = room
        self.user_id = user_id
    
    def compose(self) -> ComposeResult:
        """Compose room members modal"""
        with Container(id="room-members-modal"):
            yield Static("👥 Room Members", classes="modal-title")
            
            with Vertical():
                yield DataTable(id="members-table")
                
                with Horizontal():
                    yield Button("➕ Invite", id="invite-btn")
                    yield Button("👋 Kick", id="kick-btn")
                    yield Button("🚫 Ban", id="ban-btn")
                    yield Button("❌ Close", id="close-btn")

class RoomAnalyticsModal(ModalScreen):
    """Modal for room analytics"""
    
    def __init__(self, room_manager: RoomManager, room: Room):
        super().__init__()
        self.room_manager = room_manager
        self.room = room
    
    def compose(self) -> ComposeResult:
        """Compose room analytics modal"""
        with Container(id="room-analytics-modal"):
            yield Static("📊 Room Analytics", classes="modal-title")
            
            with Vertical():
                yield Static("", id="analytics-content")
                yield Button("❌ Close", id="close-btn")
    
    def on_mount(self) -> None:
        """Load analytics data"""
        analytics = self.room_manager.get_room_analytics(self.room.room_id)
        
        if analytics:
            content = self.query_one("#analytics-content", Static)
            
            # Create analytics table
            table = Table(show_header=False, box=None)
            table.add_column("Metric", style="#58a6ff")
            table.add_column("Value", style="#c9d1d9")
            
            table.add_row("Total Messages", str(analytics.total_messages))
            table.add_row("Active Users", str(analytics.active_users))
            table.add_row("Peak Users", str(analytics.peak_users))
            table.add_row("Messages/Hour", f"{analytics.messages_per_hour:.2f}")
            table.add_row("File Transfers", str(analytics.file_transfers))
            table.add_row("Total File Size", f"{analytics.total_file_size_mb:.2f} MB")
            table.add_row("Most Active User", analytics.most_active_user or "N/A")
            table.add_row("Uptime", f"{analytics.uptime_hours:.1f} hours")
            
            content.update(Panel(table, title="Room Statistics"))

class ConfirmModal(ModalScreen):
    """Generic confirmation modal"""
    
    def __init__(self, title: str, message: str, confirm_text: str = "Confirm"):
        super().__init__()
        self.title = title
        self.message = message
        self.confirm_text = confirm_text
    
    def compose(self) -> ComposeResult:
        """Compose confirmation modal"""
        with Container(id="confirm-modal"):
            yield Static(self.title, classes="modal-title")
            yield Static(self.message, id="confirm-message")
            
            with Horizontal():
                yield Button(self.confirm_text, id="confirm-btn", variant="primary")
                yield Button("Cancel", id="cancel-btn")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press"""
        if event.button.id == "confirm-btn":
            self.dismiss(True)
        else:
            self.dismiss(False)

class MultiRoomUI(App):
    """Multi-room management application"""
    
    CSS = """
    /* Multi-room UI Styles */
    Screen {
        background: #0d1117;
        text-style: none;
    }
    
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
    
    /* Modal Styles */
    #room-management-container, #create-room-modal, #room-settings-modal, #room-members-modal, #room-analytics-modal, #confirm-modal {
        background: #161b22;
        border: solid #30363d;
        padding: 2;
        margin: 2;
        width: 80%;
        height: 80%;
    }
    
    .screen-title, .modal-title {
        text-align: center;
        color: #58a6ff;
        text-style: bold;
        margin: 0 0 2 0;
    }
    
    .section-title {
        color: #f0f6fc;
        text-style: bold;
        margin: 0 0 1 0;
    }
    
    /* Form Styles */
    Label {
        color: #8b949e;
        margin: 1 0 0 0;
    }
    
    Input {
        margin: 0 0 1 0;
        border: solid #30363d;
        background: #0d1117;
        color: #c9d1d9;
    }
    
    Select {
        margin: 0 0 1 0;
        border: solid #30363d;
        background: #0d1117;
        color: #c9d1d9;
    }
    
    Switch {
        margin: 0 1 0 0;
    }
    
    /* Button Styles */
    Button {
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
    
    /* Container Styles */
    #room-list-container, #room-details-container {
        border: solid #30363d;
        padding: 1;
        margin: 0 1;
    }
    
    #room-list-container {
        width: 40%;
    }
    
    #room-details-container {
        width: 60%;
    }
    
    /* Table Styles */
    DataTable {
        background: #0d1117;
        border: solid #30363d;
    }
    
    DataTable > .datatable--header {
        background: #161b22;
        text-style: bold;
    }
    
    DataTable > .datatable--cursor {
        background: #1f242c;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "dismiss_screen", "Close Modal"),
        Binding("r", "refresh", "Refresh"),
        Binding("n", "create_room", "Create Room"),
    ]
    
    def __init__(self, user_id: str = "demo_user"):
        super().__init__()
        self.user_id = user_id
        self.room_manager = create_room_manager()
        self.management_screen: Optional[RoomManagementScreen] = None
    
    def on_mount(self) -> None:
        """Initialize application"""
        self._show_management_screen()
    
    def _show_management_screen(self):
        """Show room management screen"""
        self.management_screen = RoomManagementScreen(self.room_manager, self.user_id)
        self.push_screen(self.management_screen)
    
    async def action_refresh(self) -> None:
        """Refresh room list"""
        if self.management_screen:
            self.management_screen._load_rooms()
    
    async def action_create_room(self) -> None:
        """Create new room"""
        if self.management_screen:
            await self.management_screen._show_create_room_modal()
    
    async def action_dismiss_screen(self) -> None:
        """Dismiss current screen"""
        if self.screen == self.management_screen:
            await self.action_quit()
        else:
            self.pop_screen()

# Utility functions
def create_multi_room_ui(user_id: str = "demo_user") -> MultiRoomUI:
    """Create multi-room UI instance"""
    return MultiRoomUI(user_id)

# Main entry point
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    app = create_multi_room_ui()
    app.run()
