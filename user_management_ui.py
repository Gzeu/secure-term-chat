#!/usr/bin/env python3
"""
User Management UI for secure-term-chat
Advanced user management interface with roles and permissions
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
    Select, Switch, Checkbox, Placeholder, Tree
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

from user_manager import (
    UserManager, UserRole, Permission, UserStatus,
    create_user_manager
)

class UserManagementScreen(ModalScreen):
    """Screen for user management operations"""
    
    def __init__(self, user_manager: UserManager, current_user_id: str):
        super().__init__()
        self.user_manager = user_manager
        self.current_user_id = current_user_id
        self.selected_user: Optional[Any] = None
    
    def compose(self) -> ComposeResult:
        """Compose user management screen"""
        with Container(id="user-management-container"):
            yield Static("👥 User Management", classes="screen-title")
            
            with Horizontal():
                # User list
                with Vertical(id="user-list-container"):
                    yield Static("All Users", classes="section-title")
                    yield DataTable(id="user-list")
                    yield Button("➕ Create User", id="create-user-btn")
                    yield Button("🔄 Refresh", id="refresh-btn")
                
                # User details
                with Vertical(id="user-details-container"):
                    yield Static("User Details", classes="section-title")
                    yield Static("Select a user to view details", id="user-details")
                    yield Button("✏️ Edit", id="edit-user-btn", disabled=True)
                    yield Button("🔐 Change Role", id="change-role-btn", disabled=True)
                    yield Button("🚫 Ban", id="ban-user-btn", disabled=True)
                    yield Button("🗑️ Delete", id="delete-user-btn", disabled=True)
                
                # User statistics
                with Vertical(id="user-stats-container"):
                    yield Static("User Statistics", classes="section-title")
                    yield Static("", id="user-stats")
                    yield Button("📊 Global Stats", id="global-stats-btn")
                    yield Button("📋 Audit Log", id="audit-log-btn")
    
    def on_mount(self) -> None:
        """Initialize screen"""
        self._setup_user_list()
        self._load_users()
    
    def _setup_user_list(self):
        """Setup user list table"""
        table = self.query_one("#user-list", DataTable)
        table.add_columns("Username", "Role", "Status", "Last Login", "Created")
        table.cursor_type = "row"
    
    def _load_users(self):
        """Load all users"""
        table = self.query_one("#user-list", DataTable)
        table.clear()
        
        for user in self.user_manager.users.values():
            last_login = time.strftime("%Y-%m-%d %H:%M", time.localtime(user.last_login))
            created_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(user.created_at))
            
            table.add_row(
                user.username,
                user.role.value,
                user.status.value,
                last_login,
                created_time
            )
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "create-user-btn":
            await self._show_create_user_modal()
        elif event.button.id == "edit-user-btn":
            await self._edit_user()
        elif event.button.id == "change-role-btn":
            await self._change_user_role()
        elif event.button.id == "ban-user-btn":
            await self._ban_user()
        elif event.button.id == "delete-user-btn":
            await self._delete_user()
        elif event.button.id == "refresh-btn":
            self._refresh_users()
        elif event.button.id == "global-stats-btn":
            await self._show_global_statistics()
        elif event.button.id == "audit-log-btn":
            await self._show_audit_log()
    
    def on_data_table_selected(self, event: DataTable.Selected) -> None:
        """Handle user selection"""
        if event.row_key is not None:
            table = event.data_table
            row_data = table.get_row(event.row_key)
            
            # Find user by username
            for user in self.user_manager.users.values():
                if user.username == row_data[0]:  # Username column
                    self.selected_user = user
                    self._update_user_details()
                    break
    
    def _update_user_details(self):
        """Update user details display"""
        if not self.selected_user:
            return
        
        details = self.query_one("#user-details", Static)
        
        # Create user info table
        info_table = Table(show_header=False, box=None)
        info_table.add_column("Property", style="#58a6ff")
        info_table.add_column("Value", style="#c9d1d9")
        
        info_table.add_row("Username", self.selected_user.username)
        info_table.add_row("Display Name", self.selected_user.display_name)
        info_table.add_row("Email", self.selected_user.email)
        info_table.add_row("User ID", self.selected_user.user_id)
        info_table.add_row("Role", self.selected_user.role.value)
        info_table.add_row("Status", self.selected_user.status.value)
        info_table.add_row("Created", time.strftime("%Y-%m-%d %H:%M", time.localtime(self.selected_user.created_at)))
        info_table.add_row("Last Login", time.strftime("%Y-%m-%d %H:%M", time.localtime(self.selected_user.last_login)))
        info_table.add_row("Permissions", str(len(self.selected_user.permissions)))
        info_table.add_row("Bio", self.selected_user.bio or "N/A")
        info_table.add_row("Avatar", self.selected_user.avatar_url or "N/A")
        
        details.update(Panel(info_table, title="User Information"))
        
        # Update user statistics
        self._update_user_statistics()
        
        # Enable buttons
        self.query_one("#edit-user-btn").disabled = False
        self.query_one("#change-role-btn").disabled = False
        self.query_one("#ban-user-btn").disabled = False
        self.query_one("#delete-user-btn").disabled = False
    
    def _update_user_statistics(self):
        """Update user statistics display"""
        if not self.selected_user:
            return
        
        stats = self.query_one("#user-stats", Static)
        user_stats = self.user_manager.get_user_statistics(self.selected_user.user_id)
        
        # Create stats table
        stats_table = Table(show_header=False, box=None)
        stats_table.add_column("Metric", style="#58a6ff")
        stats_table.add_column("Value", style="#c9d1d9")
        
        stats_table.add_row("Message Count", str(user_stats.get("message_count", 0)))
        stats_table.add_row("File Count", str(user_stats.get("file_count", 0)))
        stats_table.add_row("Room Count", str(user_stats.get("room_count", 0)))
        stats_table.add_row("Session Count", str(user_stats.get("session_count", 0)))
        stats_table.add_row("Permission Count", str(user_stats.get("permission_count", 0)))
        
        stats.update(Panel(stats_table, title="User Statistics"))
    
    async def _show_create_user_modal(self):
        """Show create user modal"""
        modal = CreateUserModal(self.user_manager)
        await self.app.push_screen(modal, self._on_user_created)
    
    async def _on_user_created(self, result):
        """Handle user creation result"""
        if result and result.get("success"):
            self._load_users()
            self.app.bell()  # Notification sound
    
    async def _edit_user(self):
        """Edit selected user"""
        if not self.selected_user:
            return
        
        modal = EditUserModal(self.user_manager, self.selected_user)
        await self.app.push_screen(modal, self._on_user_updated)
    
    async def _on_user_updated(self, result):
        """Handle user update result"""
        if result:
            self._load_users()
            self._update_user_details()
            self.app.bell()
    
    async def _change_user_role(self):
        """Change user role"""
        if not self.selected_user:
            return
        
        modal = ChangeRoleModal(self.user_manager, self.selected_user)
        await self.app.push_screen(modal, self._on_role_changed)
    
    async def _on_role_changed(self, result):
        """Handle role change result"""
        if result:
            self._load_users()
            self._update_user_details()
            self.app.bell()
    
    async def _ban_user(self):
        """Ban selected user"""
        if not self.selected_user:
            return
        
        modal = BanUserModal(self.user_manager, self.selected_user)
        await self.app.push_screen(modal, self._on_user_banned)
    
    async def _on_user_banned(self, result):
        """Handle user ban result"""
        if result:
            self._load_users()
            self.selected_user = None
            self._update_user_details()
            self.app.bell()
    
    async def _delete_user(self):
        """Delete selected user"""
        if not self.selected_user:
            return
        
        # Confirm deletion
        modal = ConfirmModal(
            "Delete User",
            f"Are you sure you want to delete '{self.selected_user.username}'? This action cannot be undone.",
            "Delete"
        )
        result = await self.app.push_screen(modal)
        
        if result:
            success = self.user_manager.delete_user(self.selected_user.user_id)
            if success:
                self.selected_user = None
                self._load_users()
                self._update_user_details()
                self.app.bell()
    
    def _refresh_users(self):
        """Refresh user list"""
        self._load_users()
        self.app.bell()
    
    async def _show_global_statistics(self):
        """Show global statistics"""
        stats = self.user_manager.get_global_statistics()
        
        modal = GlobalStatsModal(stats)
        await self.app.push_screen(modal)
    
    async def _show_audit_log(self):
        """Show audit log"""
        modal = AuditLogModal(self.user_manager)
        await self.app.push_screen(modal)

class CreateUserModal(ModalScreen):
    """Modal for creating new users"""
    
    def __init__(self, user_manager: UserManager):
        super().__init__()
        self.user_manager = user_manager
    
    def compose(self) -> ComposeResult:
        """Compose create user modal"""
        with Container(id="create-user-modal"):
            yield Static("➕ Create New User", classes="modal-title")
            
            with Vertical():
                yield Label("Username:")
                yield Input(placeholder="Enter username...", id="username-input")
                
                yield Label("Email:")
                yield Input(placeholder="Enter email...", id="email-input")
                
                yield Label("Password:")
                yield Input(placeholder="Enter password...", id="password-input", password=True)
                
                yield Label("Display Name:")
                yield Input(placeholder="Enter display name...", id="display-name-input")
                
                yield Label("Bio:")
                yield Input(placeholder="Enter bio...", id="bio-input")
                
                yield Label("Role:")
                yield Select(
                    options=[
                        ("Member", "member"),
                        ("Moderator", "moderator"),
                        ("Admin", "admin"),
                        ("Super Admin", "super_admin")
                    ],
                    value="member",
                    id="role-select"
                )
                
                yield Horizontal():
                    yield Switch(value=True, id="send-verification-switch")
                    yield Label("Send Verification Email")
                
                yield Horizontal():
                    yield Button("✅ Create", id="create-btn", variant="primary")
                    yield Button("❌ Cancel", id="cancel-btn")
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press"""
        if event.button.id == "create-btn":
            await self._create_user()
        elif event.button.id == "cancel-btn":
            self.dismiss(None)
    
    async def _create_user(self):
        """Create new user"""
        try:
            username = self.query_one("#username-input", Input).value
            email = self.query_one("#email-input", Input).value
            password = self.query_one("#password-input", Input).value
            display_name = self.query_one("#display-name-input", Input).value
            bio = self.query_one("#bio-input", Input).value
            role_str = self.query_one("#role-select", Select).value
            send_verification = self.query_one("#send-verification-switch", Switch).value
            
            if not username or not email or not password:
                self.app.notify("Please fill in all required fields")
                return
            
            role = UserRole(role_str)
            
            success, user_id = await self.user_manager.create_user(
                username=username,
                email=email,
                password=password,
                display_name=display_name,
                bio=bio,
                role=role
            )
            
            if success:
                self.app.notify(f"User '{username}' created successfully")
                self.dismiss({"success": True, "user_id": user_id})
            else:
                self.app.notify(f"Failed to create user: {user_id}")
                
        except Exception as e:
            self.app.notify(f"Error creating user: {e}")

class EditUserModal(ModalScreen):
    """Modal for editing user details"""
    
    def __init__(self, user_manager: UserManager, user_profile):
        super().__init__()
        self.user_manager = user_manager
        self.user = user_profile
    
    def compose(self) -> ComposeResult:
        """Compose edit user modal"""
        with Container(id="edit-user-modal"):
            yield Static("✏️ Edit User", classes="modal-title")
            
            with Vertical():
                yield Label("Display Name:")
                yield Input(value=self.user.display_name, id="display-name-input")
                
                yield Label("Email:")
                yield Input(value=self.user.email, id="email-input")
                
                yield Label("Bio:")
                yield Input(value=self.user.bio, id="bio-input")
                
                yield Label("Avatar URL:")
                yield Input(value=self.user.avatar_url, id="avatar-input")
                
                yield Label("Status:")
                yield Select(
                    options=[
                        ("Active", "active"),
                        ("Inactive", "inactive"),
                        ("Suspended", "suspended"),
                        ("Banned", "banned")
                    ],
                    value=self.user.status.value,
                    id="status-select"
                )
                
                yield Horizontal():
                    yield Button("💾 Save", id="save-btn", variant="primary")
                    yield Button("❌ Cancel", id="cancel-btn")
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press"""
        if event.button.id == "save-btn":
            await self._save_user()
        elif event.button.id == "cancel-btn":
            self.dismiss(None)
    
    async def _save_user(self):
        """Save user changes"""
        try:
            display_name = self.query_one("#display-name-input", Input).value
            email = self.query_one("#email-input", Input).value
            bio = self.query_one("#bio-input", Input).value
            avatar_url = self.query_one("#avatar-input", Input).value
            status_str = self.query_one("#status-select", Select).value
            
            success = self.user_manager.update_user_profile(
                self.user.user_id,
                display_name=display_name,
                email=email,
                bio=bio,
                avatar_url=avatar_url,
                status=UserStatus(status_str)
            )
            
            if success:
                self.app.notify(f"User '{self.user.username}' updated successfully")
                self.dismiss(True)
            else:
                self.app.notify("Failed to update user")
                
        except Exception as e:
            self.app.notify(f"Error updating user: {e}")

class ChangeRoleModal(ModalScreen):
    """Modal for changing user role"""
    
    def __init__(self, user_manager: UserManager, user_profile):
        super().__init__()
        self.user_manager = user_manager
        self.user = user_profile
    
    def compose(self) -> ComposeResult:
        """Compose change role modal"""
        with Container(id="change-role-modal"):
            yield Static("🔐 Change User Role", classes="modal-title")
            
            with Vertical():
                yield Static(f"User: {self.user.username}")
                yield Static(f"Current Role: {self.user.role.value}")
                
                yield Label("New Role:")
                yield Select(
                    options=[
                        ("Guest", "guest"),
                        ("Member", "member"),
                        ("Moderator", "moderator"),
                        ("Admin", "admin"),
                        ("Super Admin", "super_admin")
                    ],
                    value=self.user.role.value,
                    id="role-select"
                )
                
                yield Horizontal():
                    yield Button("🔐 Change", id="change-btn", variant="primary")
                    yield Button("❌ Cancel", id="cancel-btn")
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press"""
        if event.button.id == "change-btn":
            await self._change_role()
        elif event.button.id == "cancel-btn":
            self.dismiss(None)
    
    async def _change_role(self):
        """Change user role"""
        try:
            new_role_str = self.query_one("#role-select", Select).value
            new_role = UserRole(new_role_str)
            
            if new_role == self.user.role:
                self.app.notify("Role is already set to this value")
                return
            
            success = self.user_manager.promote_user(self.user.user_id, new_role)
            
            if success:
                self.app.notify(f"Changed role to {new_role.value}")
                self.dismiss(True)
            else:
                self.app.notify("Failed to change role")
                
        except Exception as e:
            self.app.notify(f"Error changing role: {e}")

class BanUserModal(ModalScreen):
    """Modal for banning users"""
    
    def __init__(self, user_manager: UserManager, user_profile):
        super().__init__()
        self.user_manager = user_manager
        self.user = user_profile
    
    def compose(self) -> ComposeResult:
        """Compose ban user modal"""
        with Container(id="ban-user-modal"):
            yield Static("🚫 Ban User", classes="modal-title")
            
            with Vertical():
                yield Static(f"User: {self.user.username}")
                yield Static(f"Current Status: {self.user.status.value}")
                
                yield Label("Ban Reason:")
                yield Input(placeholder="Enter ban reason...", id="reason-input")
                
                yield Label("Duration (hours):")
                yield Input(value="24", id="duration-input")
                
                yield Horizontal():
                    yield Switch(value=True, id="notify-switch")
                    yield Label("Notify User")
                
                yield Horizontal():
                    yield Button("🚫 Ban", id="ban-btn", variant="primary")
                    yield Button("❌ Cancel", id="cancel-btn")
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press"""
        if event.button.id == "ban-btn":
            await self._ban_user()
        elif event.button.id == "cancel-btn":
            self.dismiss(None)
    
    async def _ban_user(self):
        """Ban user"""
        try:
            reason = self.query_one("#reason-input", Input).value
            duration_str = self.query_one("#duration-input", Input).value
            notify = self.query_one("#notify-switch", Switch).value
            
            if not reason:
                self.app.notify("Please provide a ban reason")
                return
            
            try:
                duration = int(duration_str)
            except ValueError:
                self.app.notify("Invalid duration")
                return
            
            success = self.user_manager.ban_user(self.user.user_id, reason, duration)
            
            if success:
                self.app.notify(f"User banned for {duration} hours")
                self.dismiss(True)
            else:
                self.app.notify("Failed to ban user")
                
        except Exception as e:
            self.app.notify(f"Error banning user: {e}")

class GlobalStatsModal(ModalScreen):
    """Modal for global statistics"""
    
    def __init__(self, stats: Dict[str, Any]):
        super().__init__()
        self.stats = stats
    
    def compose(self) -> ComposeResult:
        """Compose statistics modal"""
        with Container(id="stats-modal"):
            yield Static("📊 Global Statistics", classes="modal-title")
            
            with Vertical():
                yield Static("", id="stats-content")
                yield Button("❌ Close", id="close-btn")
    
    def on_mount(self) -> None:
        """Load statistics data"""
        content = self.query_one("#stats-content", Static)
        
        # Create statistics table
        table = Table(show_header=False, box=None)
        table.add_column("Metric", style="#58a6ff")
        table.add_column("Value", style="#c9d1d9")
        
        table.add_row("Total Users", str(self.stats.get("total_users", 0)))
        table.add_row("Active Users", str(self.stats.get("active_users", 0)))
        table.add_row("Total Logins", str(self.stats.get("total_logins", 0)))
        table.add_row("Failed Logins", str(self.stats.get("failed_logins", 0)))
        table.add_row("Success Rate", f"{self.stats.get('success_rate', 0):.1f}%")
        table.add_row("Cache Size", str(self.stats.get("cache_size", 0)))
        
        content.update(Panel(table, title="Global Statistics"))

class AuditLogModal(ModalScreen):
    """Modal for audit log"""
    
    def __init__(self, user_manager: UserManager):
        super().__init__()
        self.user_manager = user_manager
    
    def compose(self) -> ComposeResult:
        """Compose audit log modal"""
        with Container(id="audit-log-modal"):
            yield Static("📋 Audit Log", classes="modal-title")
            
            with Vertical():
                yield Static("Audit log functionality coming soon...", id="audit-content")
                yield Button("❌ Close", id="close-btn")

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

class UserManagementUI(App):
    """User management application"""
    
    CSS = """
    /* User Management UI Styles */
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
    #user-management-container, #create-user-modal, #edit-user-modal, #change-role-modal, #ban-user-modal, #stats-modal, #audit-log-modal, #confirm-modal {
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
    #user-list-container, #user-details-container, #user-stats-container {
        border: solid #30363d;
        padding: 1;
        margin: 0 1;
    }
    
    #user-list-container {
        width: 40%;
    }
    
    #user-details-container {
        width: 35%;
    }
    
    #user-stats-container {
        width: 25%;
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
        Binding("c", "create_user", "Create User"),
        Binding("r", "refresh", "Refresh"),
        Binding("e", "edit_user", "Edit User"),
        Binding("s", "statistics", "Show Statistics"),
    ]
    
    def __init__(self, current_user_id: str = "admin_user"):
        super().__init__()
        self.current_user_id = current_user_id
        self.user_manager = create_user_manager()
        self.management_screen: Optional[UserManagementScreen] = None
    
    def on_mount(self) -> None:
        """Initialize application"""
        self._show_management_screen()
    
    def _show_management_screen(self):
        """Show user management screen"""
        self.management_screen = UserManagementScreen(self.user_manager, self.current_user_id)
        self.push_screen(self.management_screen)
    
    async def action_create_user(self) -> None:
        """Create user"""
        if self.management_screen:
            await self.management_screen._show_create_user_modal()
    
    async def action_refresh(self) -> None:
        """Refresh user list"""
        if self.management_screen:
            self.management_screen._refresh_users()
    
    async def action_edit_user(self) -> None:
        """Edit selected user"""
        if self.management_screen:
            await self.management_screen._edit_user()
    
    async def action_statistics(self) -> None:
        """Show statistics"""
        if self.management_screen:
            await self.management_screen._show_global_statistics()
    
    async def action_dismiss_screen(self) -> None:
        """Dismiss current screen"""
        if self.screen == self.management_screen:
            await self.action_quit()
        else:
            self.pop_screen()

# Utility functions
def create_user_management_ui(current_user_id: str = "admin_user") -> UserManagementUI:
    """Create user management UI instance"""
    return UserManagementUI(current_user_id)

# Main entry point
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    app = create_user_management_ui()
    app.run()
