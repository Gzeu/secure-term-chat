#!/usr/bin/env python3
"""
Audit and Compliance UI for secure-term-chat
Comprehensive audit trail and compliance monitoring interface
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

from audit_compliance import (
    AuditManager, AuditEventType, SeverityLevel, ComplianceFramework,
    ComplianceStatus, create_audit_manager
)

class AuditComplianceScreen(ModalScreen):
    """Screen for audit and compliance operations"""
    
    def __init__(self, audit_manager: AuditManager):
        super().__init__()
        self.audit_manager = audit_manager
        self.selected_event: Optional[Any] = None
        self.selected_framework: ComplianceFramework = ComplianceFramework.GDPR
    
    def compose(self) -> ComposeResult:
        """Compose audit compliance screen"""
        with Container(id="audit-compliance-container"):
            yield Static("📋 Audit & Compliance", classes="screen-title")
            
            with Horizontal():
                # Event log
                with Vertical(id="event-log-container"):
                    yield Static("Audit Events", classes="section-title")
                    yield DataTable(id="event-log")
                    yield Button("🔄 Refresh", id="refresh-events-btn")
                    yield Button("📤 Export", id="export-events-btn")
                
                # Compliance monitoring
                with Vertical(id="compliance-container"):
                    yield Static("Compliance Monitoring", classes="section-title")
                    yield Select(
                        options=[
                            ("GDPR", "gdpr"),
                            ("HIPAA", "hipaa"),
                            ("SOX", "sox"),
                            ("ISO 27001", "iso27001"),
                            ("PCI DSS", "pci_dss"),
                            ("CCPA", "ccpa"),
                            ("SOC 2", "soc2")
                        ],
                        value="gdpr",
                        id="framework-select"
                    )
                    yield Button("📊 Generate Report", id="generate-report-btn")
                    yield Button("⚙️ Rules", id="rules-btn")
                
                # Statistics
                with Vertical(id="stats-container"):
                    yield Static("Statistics", classes="section-title")
                    yield Static("", id="audit-stats")
                    yield Button("🧹 Cleanup", id="cleanup-btn")
                    yield Button("📈 Real-time", id="realtime-btn")
    
    def on_mount(self) -> None:
        """Initialize screen"""
        self._setup_event_log()
        self._setup_framework_select()
        self._load_events()
        self._update_statistics()
    
    def _setup_event_log(self):
        """Setup event log table"""
        table = self.query_one("#event-log", DataTable)
        table.add_columns("Timestamp", "Event Type", "User", "Action", "Severity", "Status")
        table.cursor_type = "row"
    
    def _setup_framework_select(self):
        """Setup framework selection"""
        framework_select = self.query_one("#framework-select", Select)
        framework_select.value = self.selected_framework.value
    
    def _load_events(self):
        """Load audit events"""
        table = self.query_one("#event-log", DataTable)
        table.clear()
        
        # Get recent events
        events = list(self.audit_manager.audit_events)[-50:]  # Last 50 events
        
        for event in reversed(events):  # Most recent first
            timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(event.timestamp))
            severity_emoji = self._get_severity_emoji(event.severity)
            status_emoji = "✅" if event.success else "❌"
            
            table.add_row(
                timestamp,
                event.event_type.value,
                event.user_id,
                event.action,
                f"{severity_emoji} {event.severity.value}",
                status_emoji
            )
    
    def _update_statistics(self):
        """Update statistics display"""
        stats = self.query_one("#audit-stats", Static)
        audit_stats = self.audit_manager.get_audit_statistics()
        
        # Create statistics table
        stats_table = Table(show_header=False, box=None)
        stats_table.add_column("Metric", style="#58a6ff")
        stats_table.add_column("Value", style="#c9d1d9")
        
        stats_table.add_row("Total Events", str(audit_stats.get("total_events", 0)))
        stats_table.add_row("Max Events", str(audit_stats.get("max_events", 0)))
        stats_table.add_row("Retention Days", str(audit_stats.get("retention_days", 0)))
        stats_table.add_row("Compliance Rules", f"{audit_stats.get('compliance_rules', {}).get('enabled', 0)}/{audit_stats.get('compliance_rules', {}).get('total', 0)}")
        
        # Event type breakdown
        events_by_type = audit_stats.get("events_by_type", {})
        if events_by_type:
            most_common_type = max(events_by_type.items(), key=lambda x: x[1])
            stats_table.add_row("Most Common", f"{most_common_type[0]} ({most_common_type[1]})")
        
        # Severity breakdown
        events_by_severity = audit_stats.get("events_by_severity", {})
        if events_by_severity:
            critical_count = events_by_severity.get("critical", 0)
            high_count = events_by_severity.get("high", 0)
            stats_table.add_row("Critical Events", str(critical_count))
            stats_table.add_row("High Severity", str(high_count))
        
        # Framework violations
        violations_by_framework = audit_stats.get("violations_by_framework", {})
        if violations_by_framework:
            gdpr_violations = violations_by_framework.get("gdpr", 0)
            stats_table.add_row("GDPR Violations", str(gdpr_violations))
        
        stats.update(Panel(stats_table, title="Audit Statistics"))
    
    def _get_severity_emoji(self, severity: SeverityLevel) -> str:
        """Get emoji for severity level"""
        emoji_mapping = {
            SeverityLevel.LOW: "🟢",
            SeverityLevel.MEDIUM: "🟡",
            SeverityLevel.HIGH: "🟠",
            SeverityLevel.CRITICAL: "🔴",
            SeverityLevel.INFO: "🔵"
        }
        return emoji_mapping.get(severity, "⚪")
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        if event.button.id == "refresh-events-btn":
            self._refresh_events()
        elif event.button.id == "export-events-btn":
            await self._export_events()
        elif event.button.id == "generate-report-btn":
            await self._generate_report()
        elif event.button.id == "rules-btn":
            await self._show_rules()
        elif event.button.id == "cleanup-btn":
            await self._cleanup_events()
        elif event.button.id == "realtime-btn":
            await self._toggle_realtime()
    
    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle framework selection change"""
        if event.select.id == "framework-select":
            framework_value = event.value
            self.selected_framework = ComplianceFramework(framework_value)
            self._update_compliance_summary()
    
    def on_data_table_selected(self, event: DataTable.Selected) -> None:
        """Handle event selection"""
        if event.row_key is not None:
            table = event.data_table
            row_data = table.get_row(event.row_key)
            
            # Find event by timestamp
            for audit_event in reversed(list(self.audit_manager.audit_events)):
                event_timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(audit_event.timestamp))
                if event_timestamp == row_data[0]:  # Timestamp column
                    self.selected_event = audit_event
                    self._show_event_details()
                    break
    
    def _show_event_details(self):
        """Show selected event details"""
        if not self.selected_event:
            return
        
        # Create event details modal
        modal = EventDetailsModal(self.selected_event)
        self.app.push_screen(modal)
    
    def _refresh_events(self):
        """Refresh event list"""
        self._load_events()
        self._update_statistics()
        self.app.bell()
    
    async def _export_events(self):
        """Export audit events"""
        try:
            # Show export options modal
            modal = ExportEventsModal(self.audit_manager)
            result = await self.app.push_screen(modal)
            
            if result:
                self.app.notify("Events exported successfully")
                self.app.bell()
                
        except Exception as e:
            self.app.notify(f"Export failed: {e}")
    
    async def _generate_report(self):
        """Generate compliance report"""
        try:
            # Generate report for last 30 days
            end_time = time.time()
            start_time = end_time - (30 * 24 * 3600)
            
            report_id = await self.audit_manager.generate_compliance_report(
                self.selected_framework,
                start_time,
                end_time
            )
            
            if report_id:
                self.app.notify(f"Generated {self.selected_framework.value} report: {report_id[:8]}...")
                self.app.bell()
                
                # Show report details
                modal = ComplianceReportModal(
                    self.audit_manager.reports.get(report_id),
                    self.selected_framework
                )
                self.app.push_screen(modal)
            else:
                self.app.notify("Failed to generate report")
                
        except Exception as e:
            self.app.notify(f"Report generation failed: {e}")
    
    async def _show_rules(self):
        """Show compliance rules"""
        modal = ComplianceRulesModal(self.audit_manager)
        await self.app.push_screen(modal)
    
    async def _cleanup_events(self):
        """Cleanup old events"""
        try:
            await self.audit_manager.cleanup_old_events()
            self._load_events()
            self._update_statistics()
            self.app.notify("Old events cleaned up")
            self.app.bell()
            
        except Exception as e:
            self.app.notify(f"Cleanup failed: {e}")
    
    async def _toggle_realtime(self):
        """Toggle real-time monitoring"""
        try:
            self.audit_manager.real_time_monitoring = not self.audit_manager.real_time_monitoring
            
            status = "enabled" if self.audit_manager.real_time_monitoring else "disabled"
            self.app.notify(f"Real-time monitoring {status}")
            self.app.bell()
            
        except Exception as e:
            self.app.notify(f"Failed to toggle real-time monitoring: {e}")
    
    def _update_compliance_summary(self):
        """Update compliance summary for selected framework"""
        summary = self.audit_manager.get_compliance_summary(self.selected_framework)
        
        # Create summary display
        summary_text = f"""
📋 {summary['framework'].upper()} Compliance Summary:
├─ Total Events: {summary['total_events']}
├─ Compliant: {summary['compliant_events']}
├─ Non-Compliant: {summary['non_compliant_events']}
├─ Compliance Rate: {summary['compliance_rate']:.1f}%
├─ Violations: {summary['violations_count']}
└─ Status: {summary['status'].value}
        """
        
        # Update display (would need a dedicated widget in real implementation)
        self.app.notify(f"Updated {self.selected_framework.value} summary")

class EventDetailsModal(ModalScreen):
    """Modal for showing event details"""
    
    def __init__(self, event):
        super().__init__()
        self.event = event
    
    def compose(self) -> ComposeResult:
        """Compose event details modal"""
        with Container(id="event-details-modal"):
            yield Static("📋 Event Details", classes="modal-title")
            
            with Vertical():
                yield Static(f"Event ID: {self.event.event_id}")
                yield Static(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.event.timestamp))}")
                yield Static(f"Event Type: {self.event.event_type.value}")
                yield Static(f"User ID: {self.event.user_id}")
                yield Static(f"Target User: {self.event.target_user_id or 'N/A'}")
                yield Static(f"Target Resource: {self.event.target_resource or 'N/A'}")
                yield Static(f"Action: {self.event.action}")
                yield Static(f"Severity: {self.event.severity.value}")
                yield Static(f"Success: {'✅ Yes' if self.event.success else '❌ No'}")
                yield Static(f"IP Address: {self.event.ip_address or 'N/A'}")
                yield Static(f"User Agent: {self.event.user_agent or 'N/A'}")
                
                if self.event.error_message:
                    yield Static(f"Error: {self.event.error_message}")
                
                if self.event.details:
                    yield Static("Details:")
                    for key, value in self.event.details.items():
                        yield Static(f"  {key}: {value}")
                
                if self.event.compliance_framework:
                    frameworks = ", ".join([fw.value for fw in self.event.compliance_framework])
                    yield Static(f"Compliance Frameworks: {frameworks}")
                
                yield Button("❌ Close", id="close-btn")

class ExportEventsModal(ModalScreen):
    """Modal for exporting events"""
    
    def __init__(self, audit_manager: AuditManager):
        super().__init__()
        self.audit_manager = audit_manager
    
    def compose(self) -> ComposeResult:
        """Compose export modal"""
        with Container(id="export-modal"):
            yield Static("📤 Export Audit Events", classes="modal-title")
            
            with Vertical():
                yield Label("Export Format:")
                yield Select(
                    options=[
                        ("JSON", "json"),
                        ("CSV", "csv")
                    ],
                    value="json",
                    id="format-select"
                )
                
                yield Label("Time Period:")
                yield Select(
                    options=[
                        ("Last 24 Hours", "24h"),
                        ("Last 7 Days", "7d"),
                        ("Last 30 Days", "30d"),
                        ("Last 90 Days", "90d"),
                        ("All Time", "all")
                    ],
                    value="30d",
                    id="period-select"
                )
                
                yield Horizontal():
                    yield Switch(value=False, id="include-violations-switch")
                    yield Label("Include Violations Only")
                
                yield Horizontal():
                    yield Button("📤 Export", id="export-btn", variant="primary")
                    yield Button("❌ Cancel", id="cancel-btn")
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press"""
        if event.button.id == "export-btn":
            await self._export_events()
        elif event.button.id == "cancel-btn":
            self.dismiss(None)
    
    async def _export_events(self):
        """Export events with selected options"""
        try:
            format_type = self.query_one("#format-select", Select).value
            period = self.query_one("#period-select", Select).value
            include_violations = self.query_one("#include-violations-switch", Switch).value
            
            # Calculate time range
            end_time = time.time()
            if period == "24h":
                start_time = end_time - (24 * 3600)
            elif period == "7d":
                start_time = end_time - (7 * 24 * 3600)
            elif period == "30d":
                start_time = end_time - (30 * 24 * 3600)
            elif period == "90d":
                start_time = end_time - (90 * 24 * 3600)
            else:  # all
                start_time = 0
            
            # Export events
            exported_data = self.audit_manager.export_events(
                format_type=format_type,
                start_time=start_time,
                end_time=end_time
            )
            
            if exported_data:
                # In a real implementation, this would save to file
                # For now, we'll just show success
                self.dismiss({"success": True, "data": exported_data})
            else:
                self.app.notify("Export failed")
                
        except Exception as e:
            self.app.notify(f"Export error: {e}")

class ComplianceReportModal(ModalScreen):
    """Modal for showing compliance report"""
    
    def __init__(self, report, framework: ComplianceFramework):
        super().__init__()
        self.report = report
        self.framework = framework
    
    def compose(self) -> ComposeResult:
        """Compose compliance report modal"""
        with Container(id="report-modal"):
            yield Static(f"📊 {self.framework.value.upper()} Compliance Report", classes="modal-title")
            
            with Vertical():
                yield Static(f"Report ID: {self.report.report_id}")
                yield Static(f"Generated: {time.strftime('%Y-%m-%d %H:%M', time.localtime(self.report.generated_at))}")
                yield Static(f"Period: {time.strftime('%Y-%m-%d', time.localtime(self.report.period_start))} to {time.strftime('%Y-%m-%d', time.localtime(self.report.period_end))}")
                yield Static(f"Status: {self.report.status.value}")
                
                yield Static(f"Total Events: {self.report.total_events}")
                yield Static(f"Compliant Events: {self.report.compliant_events}")
                yield Static(f"Non-Compliant Events: {self.report.non_compliant_events}")
                
                if self.report.violations:
                    yield Static("Violations:")
                    for violation in self.report.violations[:10]:  # Show first 10
                        yield Static(f"  • {violation['rule_name']}: {violation['message']}")
                
                if self.report.recommendations:
                    yield Static("Recommendations:")
                    for rec in self.report.recommendations[:5]:  # Show first 5
                        yield Static(f"  • {rec}")
                
                yield Horizontal():
                    yield Button("📤 Export Report", id="export-report-btn")
                    yield Button("❌ Close", id="close-btn")

class ComplianceRulesModal(ModalScreen):
    """Modal for showing compliance rules"""
    
    def __init__(self, audit_manager: AuditManager):
        super().__init__()
        self.audit_manager = audit_manager
    
    def compose(self) -> ComposeResult:
        """Compose compliance rules modal"""
        with Container(id="rules-modal"):
            yield Static("⚙️ Compliance Rules", classes="modal-title")
            
            with Vertical():
                yield DataTable(id="rules-table")
                yield Button("➕ Add Rule", id="add-rule-btn")
                yield Button("❌ Close", id="close-btn")
    
    def on_mount(self) -> None:
        """Initialize rules modal"""
        self._load_rules()
    
    def _load_rules(self):
        """Load compliance rules"""
        table = self.query_one("#rules-table", DataTable)
        table.add_columns("Rule Name", "Framework", "Category", "Severity", "Enabled")
        table.cursor_type = "row"
        
        for rule_id, rule in self.audit_manager.compliance_rules.items():
            status_emoji = "✅" if rule.enabled else "❌"
            
            table.add_row(
                rule.name,
                rule.framework.value,
                rule.category,
                rule.severity.value,
                f"{status_emoji} {rule.enabled}"
            )

class AuditComplianceUI(App):
    """Audit and compliance management application"""
    
    CSS = """
    /* Audit & Compliance UI Styles */
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
    #audit-compliance-container, #event-details-modal, #export-modal, #report-modal, #rules-modal {
        background: #161b22;
        border: solid #30363d;
        padding: 2;
        margin: 2;
        width: 85%;
        height: 85%;
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
    #event-log-container, #compliance-container, #stats-container {
        border: solid #30363d;
        padding: 1;
        margin: 0 1;
    }
    
    #event-log-container {
        width: 50%;
    }
    
    #compliance-container {
        width: 30%;
    }
    
    #stats-container {
        width: 20%;
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
        Binding("r", "refresh", "Refresh Events"),
        Binding("e", "export", "Export Events"),
        Binding("g", "generate", "Generate Report"),
        Binding("s", "statistics", "Show Statistics"),
    ]
    
    def __init__(self):
        super().__init__()
        self.audit_manager = create_audit_manager()
        self.audit_screen: Optional[AuditComplianceScreen] = None
    
    def on_mount(self) -> None:
        """Initialize application"""
        self._show_audit_screen()
    
    def _show_audit_screen(self):
        """Show audit compliance screen"""
        self.audit_screen = AuditComplianceScreen(self.audit_manager)
        self.push_screen(self.audit_screen)
    
    async def action_refresh(self) -> None:
        """Refresh events"""
        if self.audit_screen:
            self.audit_screen._refresh_events()
    
    async def action_export(self) -> None:
        """Export events"""
        if self.audit_screen:
            await self.audit_screen._export_events()
    
    async def action_generate(self) -> None:
        """Generate report"""
        if self.audit_screen:
            await self.audit_screen._generate_report()
    
    async def action_statistics(self) -> None:
        """Show statistics"""
        if self.audit_screen:
            self.audit_screen._update_statistics()
    
    async def action_dismiss_screen(self) -> None:
        """Dismiss current screen"""
        if self.screen == self.audit_screen:
            await self.action_quit()
        else:
            self.pop_screen()

# Utility functions
def create_audit_compliance_ui() -> AuditComplianceUI:
    """Create audit compliance UI instance"""
    return AuditComplianceUI()

# Main entry point
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    app = create_audit_compliance_ui()
    app.run()
