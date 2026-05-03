#!/usr/bin/env python3
"""
Performance Dashboard UI for secure-term-chat
Real-time performance monitoring and visualization
"""

import asyncio
import time
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from enum import Enum

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, RichLog, Button, 
    ProgressBar, Label, DataTable, Tabs, TabPane, TabbedContent,
    Static, Placeholder
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

from performance_monitor import (
    MetricsCollector, AlertManager, PerformanceAnalyzer,
    MetricType, AlertLevel, create_metrics_collector, create_alert_manager
)

class DashboardState(Enum):
    """Dashboard state"""
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"

class MetricWidget(Static):
    """Widget for displaying a single metric"""
    
    value = reactive(0.0)
    label = reactive("")
    unit = reactive("")
    status = reactive("normal")
    
    def __init__(self, label: str, unit: str = ""):
        super().__init__()
        self.label = label
        self.unit = unit
    
    def render(self) -> Panel:
        """Render metric widget"""
        # Determine color based on value and status
        if self.status == "warning":
            color = "#ff79c6"
        elif self.status == "critical":
            color = "#f85149"
        elif self.status == "good":
            color = "#56d364"
        else:
            color = "#58a6ff"
        
        # Create display text
        display_value = f"{self.value:.1f}" if isinstance(self.value, (int, float)) else str(self.value)
        
        content = f"[bold {color}]{display_value}[/] {self.unit}"
        
        return Panel(
            content,
            title=self.label,
            border_style=color,
            width=20
        )

class MetricsGrid(Static):
    """Grid of metric widgets"""
    
    def __init__(self):
        super().__init__()
        self.metrics = {
            "cpu": MetricWidget("CPU Usage", "%"),
            "memory": MetricWidget("Memory", "%"),
            "disk": MetricWidget("Disk", "%"),
            "network": MetricWidget("Network", "MB/s"),
            "messages": MetricWidget("Messages", "/s"),
            "p2p": MetricWidget("P2P", "connections"),
            "latency": MetricWidget("Latency", "ms"),
            "errors": MetricWidget("Errors", "%")
        }
    
    def compose(self) -> ComposeResult:
        """Compose metrics grid"""
        with Horizontal():
            with Vertical():
                yield self.metrics["cpu"]
                yield self.metrics["memory"]
            with Vertical():
                yield self.metrics["disk"]
                yield self.metrics["network"]
            with Vertical():
                yield self.metrics["messages"]
                yield self.metrics["p2p"]
            with Vertical():
                yield self.metrics["latency"]
                yield self.metrics["errors"]
    
    def update_metrics(self, metrics: Dict[str, float]):
        """Update all metric widgets"""
        # Update CPU
        cpu_value = metrics.get("cpu_percent", 0)
        self.metrics["cpu"].value = cpu_value
        self.metrics["cpu"].status = self._get_status(cpu_value, [70, 90])
        
        # Update Memory
        memory_value = metrics.get("memory_percent", 0)
        self.metrics["memory"].value = memory_value
        self.metrics["memory"].status = self._get_status(memory_value, [75, 90])
        
        # Update Disk
        disk_value = metrics.get("disk_usage_percent", 0)
        self.metrics["disk"].value = disk_value
        self.metrics["disk"].status = self._get_status(disk_value, [80, 95])
        
        # Update Network
        network_value = metrics.get("network_sent_mb", 0) + metrics.get("network_recv_mb", 0)
        self.metrics["network"].value = network_value
        self.metrics["network"].status = "normal"
        
        # Update Messages
        messages_value = metrics.get("message_rate", 0)
        self.metrics["messages"].value = messages_value
        self.metrics["messages"].status = "normal"
        
        # Update P2P
        p2p_value = metrics.get("p2p_connections", 0)
        self.metrics["p2p"].value = p2p_value
        self.metrics["p2p"].status = "good" if p2p_value > 0 else "normal"
        
        # Update Latency
        latency_value = metrics.get("server_latency_ms", 0)
        self.metrics["latency"].value = latency_value
        self.metrics["latency"].status = self._get_status(latency_value, [500, 1000], reverse=True)
        
        # Update Errors
        errors_value = metrics.get("error_rate", 0)
        self.metrics["errors"].value = errors_value
        self.metrics["errors"].status = self._get_status(errors_value, [1, 5])
    
    def _get_status(self, value: float, thresholds: List[float], reverse: bool = False) -> str:
        """Get status based on value and thresholds"""
        if reverse:
            # Lower is better (e.g., latency)
            if value < thresholds[0]:
                return "good"
            elif value < thresholds[1]:
                return "normal"
            else:
                return "critical" if value > thresholds[1] * 2 else "warning"
        else:
            # Higher is worse (e.g., CPU, memory)
            if value < thresholds[0]:
                return "good"
            elif value < thresholds[1]:
                return "normal"
            else:
                return "critical" if value > thresholds[1] * 1.5 else "warning"

class AlertsPanel(Static):
    """Panel for displaying alerts"""
    
    def __init__(self):
        super().__init__()
        self.alerts = []
    
    def update_alerts(self, alerts: List[Dict[str, Any]]):
        """Update alerts display"""
        self.alerts = alerts
        self.refresh()
    
    def render(self) -> Panel:
        """Render alerts panel"""
        if not self.alerts:
            content = "[dim #6e7681]No active alerts[/]"
        else:
            # Create alert list
            alert_lines = []
            for alert_data in self.alerts[-5:]:  # Show last 5 alerts
                alert = alert_data["alert"]
                timestamp = time.strftime("%H:%M:%S", time.localtime(alert_data["timestamp"]))
                
                # Color based on level
                level_colors = {
                    AlertLevel.INFO: "#58a6ff",
                    AlertLevel.WARNING: "#ff79c6",
                    AlertLevel.CRITICAL: "#f85149",
                    AlertLevel.EMERGENCY: "#ff0000"
                }
                color = level_colors.get(alert.level, "#58a6ff")
                
                alert_lines.append(
                    f"[dim #6e7681]{timestamp}[/] [{color}]{alert.level.value.upper()}[/] "
                    f"{alert.message}: {alert_data['metric_value']:.1f}"
                )
            
            content = "\n".join(alert_lines)
        
        return Panel(
            content,
            title="🚨 Alerts",
            border_style="#f85149" if self.alerts else "#30363d"
        )

class PerformanceGraph(Static):
    """Simple ASCII graph for performance trends"""
    
    def __init__(self, title: str, max_points: int = 50):
        super().__init__()
        self.title = title
        self.max_points = max_points
        self.points = []
    
    def add_point(self, value: float):
        """Add a data point"""
        self.points.append(value)
        if len(self.points) > self.max_points:
            self.points.pop(0)
        self.refresh()
    
    def render(self) -> Panel:
        """Render performance graph"""
        if not self.points:
            content = "[dim #6e7681]No data yet[/]"
        else:
            # Create simple ASCII graph
            height = 8
            width = self.max_points
            
            # Normalize points
            min_val = min(self.points)
            max_val = max(self.points)
            range_val = max_val - min_val if max_val != min_val else 1
            
            # Create graph lines
            graph_lines = []
            for i in range(height - 1, -1, -1):
                line = ""
                threshold = min_val + (range_val * i / (height - 1))
                
                for point in self.points:
                    if point >= threshold:
                        line += "█"
                    else:
                        line += " "
                
                graph_lines.append(line)
            
            # Add value labels
            max_label = f"{max_val:.1f}"
            min_label = f"{min_val:.1f}"
            
            content = "\n".join(graph_lines)
            content += f"\n[dim #6e7681]{min_label}{' ' * (width - len(max_label) - len(min_label))}{max_label}[/]"
        
        return Panel(
            content,
            title=self.title,
            border_style="#58a6ff"
        )

class PerformanceDashboard(App):
    """Performance monitoring dashboard application"""
    
    CSS = """
    /* Dashboard Styles */
    Screen {
        background: #0d1117;
        text-style: none;
    }
    
    /* Header */
    Header {
        background: #161b22;
        text-align: center;
        color: #c9d1d9;
        text-style: bold;
    }
    
    /* Footer */
    Footer {
        background: #161b22;
        color: #8b949e;
    }
    
    /* Main Layout */
    #dashboard-container {
        layout: grid;
        grid-size: 2 2;
        grid-columns: 1fr 1fr;
        grid-rows: auto 1fr;
        padding: 1;
        height: 100%;
    }
    
    /* Metrics Section */
    #metrics-section {
        grid-column: 1;
        grid-row: 1;
        height: auto;
        border: solid #30363d;
        background: #161b22;
        padding: 1;
    }
    
    /* Graphs Section */
    #graphs-section {
        grid-column: 2;
        grid-row: 1;
        height: auto;
        border: solid #30363d;
        background: #161b22;
        padding: 1;
    }
    
    /* Alerts Section */
    #alerts-section {
        grid-column: 1;
        grid-row: 2;
        border: solid #30363d;
        background: #161b22;
        padding: 1;
    }
    
    /* Details Section */
    #details-section {
        grid-column: 2;
        grid-row: 2;
        border: solid #30363d;
        background: #161b22;
        padding: 1;
    }
    
    /* Section Headers */
    .section-header {
        text-align: center;
        color: #58a6ff;
        text-style: bold;
        margin: 0 0 1 0;
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
    
    /* Status Indicators */
    .status-good {
        color: #56d364;
    }
    
    .status-warning {
        color: #ff79c6;
    }
    
    .status-critical {
        color: #f85149;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("p", "pause", "Pause/Resume"),
        Binding("a", "toggle_alerts", "Toggle Alerts"),
        Binding("s", "save_report", "Save Report"),
        Binding("escape", "dismiss_modal", "Close Modal"),
    ]
    
    def __init__(self):
        super().__init__()
        self.state = DashboardState.STARTING
        
        # Performance components
        self.collector: Optional[MetricsCollector] = None
        self.alert_manager: Optional[AlertManager] = None
        self.analyzer: Optional[PerformanceAnalyzer] = None
        
        # UI components
        self.metrics_grid: Optional[MetricsGrid] = None
        self.alerts_panel: Optional[AlertsPanel] = None
        self.graphs: Dict[str, PerformanceGraph] = {}
        
        # State
        self.running = True
        self.show_alerts = True
        self.update_task: Optional[asyncio.Task] = None
    
    def compose(self) -> ComposeResult:
        """Compose dashboard layout"""
        yield Header("📊 Performance Dashboard")
        
        with Container(id="dashboard-container"):
            # Metrics Section
            with Vertical(id="metrics-section"):
                yield Static("🔍 System Metrics", classes="section-header")
                self.metrics_grid = MetricsGrid()
                yield self.metrics_grid
            
            # Graphs Section
            with Vertical(id="graphs-section"):
                yield Static("📈 Performance Trends", classes="section-header")
                with Horizontal():
                    self.graphs["cpu"] = PerformanceGraph("CPU Usage (%)")
                    yield self.graphs["cpu"]
                with Horizontal():
                    self.graphs["memory"] = PerformanceGraph("Memory Usage (%)")
                    yield self.graphs["memory"]
                with Horizontal():
                    self.graphs["network"] = PerformanceGraph("Network (MB/s)")
                    yield self.graphs["network"]
                with Horizontal():
                    self.graphs["messages"] = PerformanceGraph("Messages (/s)")
                    yield self.graphs["messages"]
            
            # Alerts Section
            with Vertical(id="alerts-section"):
                yield Static("🚨 Active Alerts", classes="section-header")
                self.alerts_panel = AlertsPanel()
                yield self.alerts_panel
            
            # Details Section
            with Vertical(id="details-section"):
                yield Static("📋 Performance Details", classes="section-header")
                with Horizontal():
                    yield Button("🔄 Refresh", id="refresh-btn")
                    yield Button("⏸️ Pause", id="pause-btn")
                    yield Button("💾 Save Report", id="save-btn")
                yield Static("", id="details-content")
        
        yield Footer("Press 'q' to quit | 'r' to refresh | 'p' to pause | 's' to save report")
    
    def on_mount(self) -> None:
        """Initialize dashboard"""
        self._initialize_components()
        self._setup_alert_handlers()
        self._start_monitoring()
    
    def _initialize_components(self):
        """Initialize performance components"""
        try:
            self.collector = create_metrics_collector(interval=1.0)
            self.alert_manager = create_alert_manager()
            self.analyzer = PerformanceAnalyzer()
            
            self.state = DashboardState.RUNNING
            
        except Exception as e:
            self.state = DashboardState.ERROR
            print(f"Error initializing components: {e}")
    
    def _setup_alert_handlers(self):
        """Setup alert handlers"""
        if self.alert_manager:
            def handle_alert(alert_data):
                # Update alerts panel
                active_alerts = self.alert_manager.get_active_alerts()
                if self.alerts_panel:
                    self.alerts_panel.update_alerts(active_alerts)
            
            self.alert_manager.add_alert_handler(handle_alert)
    
    def _start_monitoring(self):
        """Start performance monitoring"""
        if self.collector:
            self.update_task = asyncio.create_task(self._update_loop())
    
    async def _update_loop(self):
        """Main update loop"""
        while self.running and self.state == DashboardState.RUNNING:
            try:
                # Get current metrics
                current_metrics = self.collector.get_current_metrics()
                
                # Update UI
                if self.metrics_grid:
                    self.metrics_grid.update_metrics(current_metrics)
                
                # Update graphs
                self._update_graphs(current_metrics)
                
                # Check alerts
                if self.alert_manager:
                    self.alert_manager.check_alerts(current_metrics)
                
                # Update details
                self._update_details(current_metrics)
                
                await asyncio.sleep(1.0)
                
            except Exception as e:
                print(f"Error in update loop: {e}")
                await asyncio.sleep(1.0)
    
    def _update_graphs(self, metrics: Dict[str, float]):
        """Update performance graphs"""
        if "cpu" in self.graphs:
            self.graphs["cpu"].add_point(metrics.get("cpu_percent", 0))
        
        if "memory" in self.graphs:
            self.graphs["memory"].add_point(metrics.get("memory_percent", 0))
        
        if "network" in self.graphs:
            network_value = metrics.get("network_sent_mb", 0) + metrics.get("network_recv_mb", 0)
            self.graphs["network"].add_point(network_value)
        
        if "messages" in self.graphs:
            self.graphs["messages"].add_point(metrics.get("message_rate", 0))
    
    def _update_details(self, metrics: Dict[str, float]):
        """Update details section"""
        details_content = self.query_one("#details-content", Static)
        
        # Create details table
        table = Table(show_header=True, box=None, padding=(0, 1))
        table.add_column("Metric", style="#58a6ff")
        table.add_column("Value", style="#c9d1d9")
        table.add_column("Status", style="#56d364")
        
        # Add rows
        table.add_row("CPU Usage", f"{metrics.get('cpu_percent', 0):.1f}%", "Normal")
        table.add_row("Memory Usage", f"{metrics.get('memory_percent', 0):.1f}%", "Normal")
        table.add_row("Disk Usage", f"{metrics.get('disk_usage_percent', 0):.1f}%", "Normal")
        table.add_row("Network I/O", f"{metrics.get('network_sent_mb', 0) + metrics.get('network_recv_mb', 0):.2f} MB/s", "Normal")
        table.add_row("Messages/s", f"{metrics.get('message_rate', 0):.1f}", "Normal")
        table.add_row("P2P Connections", f"{metrics.get('p2p_connections', 0)}", "Normal")
        table.add_row("Server Latency", f"{metrics.get('server_latency_ms', 0):.1f} ms", "Normal")
        table.add_row("Error Rate", f"{metrics.get('error_rate', 0):.2f}%", "Normal")
        table.add_row("Uptime", f"{metrics.get('uptime_seconds', 0) / 3600:.1f} hours", "Normal")
        
        details_content.update(Panel(table, title="System Status"))
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "refresh-btn":
            await self.action_refresh()
        elif event.button.id == "pause-btn":
            await self.action_pause()
        elif event.button.id == "save-btn":
            await self.action_save_report()
    
    async def action_refresh(self) -> None:
        """Force refresh"""
        if self.collector and self.running:
            current_metrics = self.collector.get_current_metrics()
            if self.metrics_grid:
                self.metrics_grid.update_metrics(current_metrics)
            self._update_graphs(current_metrics)
            self._update_details(current_metrics)
    
    async def action_pause(self) -> None:
        """Toggle pause/resume"""
        self.running = not self.running
        pause_btn = self.query_one("#pause-btn", Button)
        
        if self.running:
            pause_btn.label = "⏸️ Pause"
            if self.update_task:
                self.update_task = asyncio.create_task(self._update_loop())
        else:
            pause_btn.label = "▶️ Resume"
            if self.update_task:
                self.update_task.cancel()
    
    async def action_save_report(self) -> None:
        """Save performance report"""
        if self.collector and self.analyzer:
            try:
                recent_metrics = self.collector.get_recent_metrics(300)  # 5 minutes
                report = self.analyzer.generate_report(recent_metrics)
                
                # Save to file
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"performance_report_{timestamp}.json"
                
                with open(filename, "w") as f:
                    import json
                    json.dump(report, f, indent=2)
                
                # Show notification
                details_content = self.query_one("#details-content", Static)
                details_content.update(Static(f"✅ Report saved to {filename}"))
                
            except Exception as e:
                details_content = self.query_one("#details-content", Static)
                details_content.update(Static(f"❌ Error saving report: {e}"))
    
    async def action_toggle_alerts(self) -> None:
        """Toggle alerts display"""
        self.show_alerts = not self.show_alerts
        alerts_section = self.query_one("#alerts-section")
        alerts_section.display = self.show_alerts
    
    async def on_unmount(self) -> None:
        """Cleanup on app exit"""
        self.running = False
        
        if self.collector:
            self.collector.stop_collection()
        
        if self.update_task:
            self.update_task.cancel()

# Utility functions
def create_performance_dashboard() -> PerformanceDashboard:
    """Create performance dashboard instance"""
    return PerformanceDashboard()

# Main entry point
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    app = create_performance_dashboard()
    app.run()
