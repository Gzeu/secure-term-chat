#!/usr/bin/env python3
"""
File Transfer UI for secure-term-chat
Advanced file sharing interface with progress tracking and management
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
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live

from file_transfer import (
    FileTransferManager, FileType, TransferStatus, CompressionType, EncryptionType,
    create_file_transfer_manager
)

class FileTransferScreen(ModalScreen):
    """Screen for file transfer operations"""
    
    def __init__(self, transfer_manager: FileTransferManager, user_id: str, room_id: str):
        super().__init__()
        self.transfer_manager = transfer_manager
        self.user_id = user_id
        self.room_id = room_id
        self.selected_file: Optional[Any] = None
        self.upload_progress: Dict[str, float] = {}
        self.download_progress: Dict[str, float] = {}
    
    def compose(self) -> ComposeResult:
        """Compose file transfer screen"""
        with Container(id="file-transfer-container"):
            yield Static("📁 File Transfer Manager", classes="screen-title")
            
            with Horizontal():
                # File list
                with Vertical(id="file-list-container"):
                    yield Static("Your Files", classes="section-title")
                    yield DataTable(id="file-list")
                    yield Button("📤 Upload File", id="upload-btn")
                    yield Button("📊 Statistics", id="stats-btn")
                    yield Button("🔄 Refresh", id="refresh-btn")
                
                # File details
                with Vertical(id="file-details-container"):
                    yield Static("File Details", classes="section-title")
                    yield Static("Select a file to view details", id="file-details")
                    yield Button("⬇️ Download", id="download-btn", disabled=True)
                    yield Button("🗑️ Delete", id="delete-btn", disabled=True)
                    yield Button("📤 Share", id="share-btn", disabled=True)
                
                # Transfer queue
                with Vertical(id="transfer-queue-container"):
                    yield Static("Transfer Queue", classes="section-title")
                    yield DataTable(id="transfer-queue")
                    yield Button("⏸️ Pause All", id="pause-all-btn")
                    yield Button("▶️ Resume All", id="resume-all-btn")
                    yield Button("❌ Cancel All", id="cancel-all-btn")
    
    def on_mount(self) -> None:
        """Initialize screen"""
        self._setup_file_list()
        self._setup_transfer_queue()
        self._load_files()
        self._load_transfers()
    
    def _setup_file_list(self):
        """Setup file list table"""
        table = self.query_one("#file-list", DataTable)
        table.add_columns("Name", "Size", "Type", "Uploaded", "Downloads")
        table.cursor_type = "row"
    
    def _setup_transfer_queue(self):
        """Setup transfer queue table"""
        table = self.query_one("#transfer-queue", DataTable)
        table.add_columns("File", "Type", "Progress", "Status", "Rate")
        table.cursor_type = "row"
    
    def _load_files(self):
        """Load user's files"""
        table = self.query_one("#file-list", DataTable)
        table.clear()
        
        files = self.transfer_manager.get_user_files(self.user_id)
        
        for file in files:
            size_str = self._format_file_size(file.file_size)
            created_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(file.created_at))
            
            table.add_row(
                file.original_filename,
                size_str,
                file.file_type.value,
                created_time,
                str(file.download_count)
            )
    
    def _load_transfers(self):
        """Load transfer queue"""
        table = self.query_one("#transfer-queue", DataTable)
        table.clear()
        
        # In a real implementation, this would load active transfers
        # For now, we'll show placeholder data
        pass
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "upload-btn":
            await self._show_upload_modal()
        elif event.button.id == "download-btn":
            await self._download_file()
        elif event.button.id == "delete-btn":
            await self._delete_file()
        elif event.button.id == "share-btn":
            await self._share_file()
        elif event.button.id == "stats-btn":
            await self._show_statistics()
        elif event.button.id == "refresh-btn":
            self._refresh_files()
        elif event.button.id == "pause-all-btn":
            await self._pause_all_transfers()
        elif event.button.id == "resume-all-btn":
            await self._resume_all_transfers()
        elif event.button.id == "cancel-all-btn":
            await self._cancel_all_transfers()
    
    def on_data_table_selected(self, event: DataTable.Selected) -> None:
        """Handle file selection"""
        if event.row_key is not None:
            table = event.data_table
            row_data = table.get_row(event.row_key)
            
            # Find file by name
            files = self.transfer_manager.get_user_files(self.user_id)
            for file in files:
                if file.original_filename == row_data[0]:  # Name column
                    self.selected_file = file
                    self._update_file_details()
                    break
    
    def _update_file_details(self):
        """Update file details display"""
        if not self.selected_file:
            return
        
        details = self.query_one("#file-details", Static)
        
        # Create file info table
        info_table = Table(show_header=False, box=None)
        info_table.add_column("Property", style="#58a6ff")
        info_table.add_column("Value", style="#c9d1d9")
        
        info_table.add_row("Filename", self.selected_file.original_filename)
        info_table.add_row("File ID", self.selected_file.file_id)
        info_table.add_row("Size", self._format_file_size(self.selected_file.file_size))
        info_table.add_row("Type", self.selected_file.file_type.value)
        info_table.add_row("MIME Type", self.selected_file.mime_type)
        info_table.add_row("Checksum", self.selected_file.checksum_sha256[:16] + "...")
        info_table.add_row("Uploaded By", self.selected_file.uploaded_by)
        info_table.add_row("Room", self.selected_file.room_id)
        info_table.add_row("Created", time.strftime("%Y-%m-%d %H:%M", time.localtime(self.selected_file.created_at)))
        info_table.add_row("Downloads", str(self.selected_file.download_count))
        info_table.add_row("Compression", self.selected_file.compression_type.value)
        info_table.add_row("Encryption", self.selected_file.encryption_type.value)
        info_table.add_row("Chunks", str(self.selected_file.chunk_count))
        info_table.add_row("Scanned", "✅" if self.selected_file.virus_scanned else "❌")
        
        details.update(Panel(info_table, title="File Information"))
        
        # Enable buttons
        self.query_one("#download-btn").disabled = False
        self.query_one("#delete-btn").disabled = False
        self.query_one("#share-btn").disabled = False
    
    async def _show_upload_modal(self):
        """Show upload modal"""
        modal = UploadFileModal(self.transfer_manager, self.user_id, self.room_id)
        await self.app.push_screen(modal, self._on_file_uploaded)
    
    async def _on_file_uploaded(self, result):
        """Handle file upload result"""
        if result and result.get("success"):
            self._load_files()
            self.app.bell()  # Notification sound
            self._show_upload_progress(result.get("file_id"))
    
    def _show_upload_progress(self, file_id: str):
        """Show upload progress"""
        # In a real implementation, this would show progress bar
        self.app.bell()
    
    async def _download_file(self):
        """Download selected file"""
        if not self.selected_file:
            return
        
        # Confirm download
        modal = ConfirmModal(
            "Download File",
            f"Download '{self.selected_file.original_filename}' ({self._format_file_size(self.selected_file.file_size)})?",
            "Download"
        )
        result = await self.app.push_screen(modal)
        
        if result:
            success, downloaded_data, error = await self.transfer_manager.download_file(
                self.selected_file.file_id,
                self.user_id
            )
            
            if success:
                # In a real implementation, this would save the file
                print(f"Downloaded {len(downloaded_data)} bytes")
                self.app.bell()
            else:
                self.app.notify(f"Download failed: {error}")
    
    async def _delete_file(self):
        """Delete selected file"""
        if not self.selected_file:
            return
        
        # Confirm deletion
        modal = ConfirmModal(
            "Delete File",
            f"Are you sure you want to delete '{self.selected_file.original_filename}'? This action cannot be undone.",
            "Delete"
        )
        result = await self.app.push_screen(modal)
        
        if result:
            # In a real implementation, this would delete the file
            del self.transfer_manager.files[self.selected_file.file_id]
            if self.selected_file.file_id in self.transfer_manager.file_chunks:
                del self.transfer_manager.file_chunks[self.selected_file.file_id]
            
            self.selected_file = None
            self._load_files()
            self._update_file_details()
            self.app.bell()
    
    async def _share_file(self):
        """Share selected file"""
        if not self.selected_file:
            return
        
        # In a real implementation, this would generate a share link
        share_link = f"https://chat.example.com/share/{self.selected_file.file_id}"
        
        modal = ShareFileModal(self.selected_file, share_link)
        await self.app.push_screen(modal)
    
    async def _show_statistics(self):
        """Show transfer statistics"""
        stats = self.transfer_manager.get_transfer_stats()
        
        modal = TransferStatsModal(stats)
        await self.app.push_screen(modal)
    
    def _refresh_files(self):
        """Refresh file list"""
        self._load_files()
        self.app.bell()
    
    async def _pause_all_transfers(self):
        """Pause all transfers"""
        # In a real implementation, this would pause all active transfers
        self.app.bell()
    
    async def _resume_all_transfers(self):
        """Resume all transfers"""
        # In a real implementation, this would resume all paused transfers
        self.app.bell()
    
    async def _cancel_all_transfers(self):
        """Cancel all transfers"""
        # In a real implementation, this would cancel all active transfers
        self.app.bell()
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

class UploadFileModal(ModalScreen):
    """Modal for uploading files"""
    
    def __init__(self, transfer_manager: FileTransferManager, user_id: str, room_id: str):
        super().__init__()
        self.transfer_manager = transfer_manager
        self.user_id = user_id
        self.room_id = room_id
    
    def compose(self) -> ComposeResult:
        """Compose upload modal"""
        with Container(id="upload-modal"):
            yield Static("📤 Upload File", classes="modal-title")
            
            with Vertical():
                yield Label("Select File:")
                yield Input(placeholder="Enter file path or drag & drop...", id="file-path-input")
                
                yield Label("File Name (optional):")
                yield Input(placeholder="Custom file name...", id="file-name-input")
                
                yield Label("Compression:")
                yield Select(
                    options=[
                        ("None", "none"),
                        ("GZIP", "gzip"),
                        ("ZLIB", "zlib"),
                        ("Brotli", "brotli")
                    ],
                    value="gzip",
                    id="compression-select"
                )
                
                yield Label("Encryption:")
                yield Select(
                    options=[
                        ("None", "none"),
                        ("AES-256-GCM", "aes256_gcm"),
                        ("ChaCha20-Poly1305", "chacha20_poly1305")
                    ],
                    value="aes256_gcm",
                    id="encryption-select"
                )
                
                yield Horizontal():
                    yield Switch(value=True, id="virus-scan-switch")
                    yield Label("Virus Scan")
                
                yield Horizontal():
                    yield Button("📤 Upload", id="upload-btn", variant="primary")
                    yield Button("❌ Cancel", id="cancel-btn")

class ShareFileModal(ModalScreen):
    """Modal for sharing files"""
    
    def __init__(self, file_info, share_link: str):
        super().__init__()
        self.file_info = file_info
        self.share_link = share_link
    
    def compose(self) -> ComposeResult:
        """Compose share modal"""
        with Container(id="share-modal"):
            yield Static("🔗 Share File", classes="modal-title")
            
            with Vertical():
                yield Static(f"File: {self.file_info.original_filename}")
                yield Static(f"Size: {self._format_file_size(self.file_info.file_size)}")
                yield Static(f"Type: {self.file_info.file_type.value}")
                
                yield Label("Share Link:")
                yield Input(value=self.share_link, id="share-link-input", readonly=True)
                
                yield Horizontal():
                    yield Button("📋 Copy", id="copy-btn", variant="primary")
                    yield Button("❌ Close", id="close-btn")

class TransferStatsModal(ModalScreen):
    """Modal for transfer statistics"""
    
    def __init__(self, stats: Dict[str, Any]):
        super().__init__()
        self.stats = stats
    
    def compose(self) -> ComposeResult:
        """Compose statistics modal"""
        with Container(id="stats-modal"):
            yield Static("📊 Transfer Statistics", classes="modal-title")
            
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
        
        table.add_row("Total Files", str(self.stats.get("total_files", 0)))
        table.add_row("Total Size", self._format_file_size(self.stats.get("total_size", 0)))
        table.add_row("Average Size", self._format_file_size(self.stats.get("average_file_size", 0)))
        table.add_row("Compression Ratio", f"{self.stats.get('compression_ratio', 0):.2f}%")
        table.add_row("Encryption Usage", f"{self.stats.get('encryption_usage', 0):.1f}%")
        
        content.update(Panel(table, title="Transfer Statistics"))
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

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

class FileTransferUI(App):
    """File transfer management application"""
    
    CSS = """
    /* File Transfer UI Styles */
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
    #file-transfer-container, #upload-modal, #share-modal, #stats-modal, #confirm-modal {
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
    #file-list-container, #file-details-container, #transfer-queue-container {
        border: solid #30363d;
        padding: 1;
        margin: 0 1;
    }
    
    #file-list-container {
        width: 40%;
    }
    
    #file-details-container {
        width: 35%;
    }
    
    #transfer-queue-container {
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
        Binding("u", "upload", "Upload File"),
        Binding("r", "refresh", "Refresh"),
        Binding("d", "download", "Download Selected"),
        Binding("s", "statistics", "Show Statistics"),
    ]
    
    def __init__(self, user_id: str = "demo_user", room_id: str = "demo_room"):
        super().__init__()
        self.user_id = user_id
        self.room_id = room_id
        self.transfer_manager = create_transfer_manager()
        self.transfer_screen: Optional[FileTransferScreen] = None
    
    def on_mount(self) -> None:
        """Initialize application"""
        self._show_transfer_screen()
    
    def _show_transfer_screen(self):
        """Show file transfer screen"""
        self.transfer_screen = FileTransferScreen(self.transfer_manager, self.user_id, self.room_id)
        self.push_screen(self.transfer_screen)
    
    async def action_upload(self) -> None:
        """Upload file"""
        if self.transfer_screen:
            await self.transfer_screen._show_upload_modal()
    
    async def action_refresh(self) -> None:
        """Refresh file list"""
        if self.transfer_screen:
            self.transfer_screen._refresh_files()
    
    async def action_download(self) -> None:
        """Download selected file"""
        if self.transfer_screen:
            await self.transfer_screen._download_file()
    
    async def action_statistics(self) -> None:
        """Show statistics"""
        if self.transfer_screen:
            await self.transfer_screen._show_statistics()
    
    async def action_dismiss_screen(self) -> None:
        """Dismiss current screen"""
        if self.screen == self.transfer_screen:
            await self.action_quit()
        else:
            self.pop_screen()

# Utility functions
def create_file_transfer_ui(user_id: str = "demo_user", room_id: str = "demo_room") -> FileTransferUI:
    """Create file transfer UI instance"""
    return FileTransferUI(user_id, room_id)

# Main entry point
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    app = create_file_transfer_ui()
    app.run()
