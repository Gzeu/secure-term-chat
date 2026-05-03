#!/usr/bin/env python3
"""
Audit and Compliance System for secure-term-chat
Comprehensive audit trail, compliance monitoring, and security reporting
"""

import asyncio
import time
import json
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta

log = logging.getLogger(__name__)

class AuditEventType(Enum):
    """Audit event types"""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_CREATE = "user_create"
    USER_DELETE = "user_delete"
    USER_BAN = "user_ban"
    USER_UNBAN = "user_unban"
    ROLE_CHANGE = "role_change"
    PERMISSION_CHANGE = "permission_change"
    ROOM_CREATE = "room_create"
    ROOM_DELETE = "room_delete"
    ROOM_JOIN = "room_join"
    ROOM_LEAVE = "room_leave"
    MESSAGE_SEND = "message_send"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    FILE_DELETE = "file_delete"
    SYSTEM_CONFIG = "system_config"
    SECURITY_EVENT = "security_event"
    COMPLIANCE_CHECK = "compliance_check"

class ComplianceStatus(Enum):
    """Compliance status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PENDING_REVIEW = "pending_review"
    VIOLATION = "violation"
    EXEMPT = "exempt"

class SeverityLevel(Enum):
    """Severity levels for events"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    INFO = "info"

class ComplianceFramework(Enum):
    """Compliance frameworks"""
    GDPR = "gdpr"
    HIPAA = "hipaa"
    SOX = "sox"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    CCPA = "ccpa"
    SOC2 = "soc2"

@dataclass
class AuditEvent:
    """Audit event entry"""
    event_id: str
    timestamp: float
    event_type: AuditEventType
    user_id: str
    target_user_id: str
    target_resource: str
    action: str
    details: Dict[str, Any]
    ip_address: str
    user_agent: str
    severity: SeverityLevel
    success: bool
    error_message: str = ""
    compliance_framework: List[ComplianceFramework] = None
    retention_days: int = 365
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
        if self.compliance_framework is None:
            self.compliance_framework = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        """Create audit event from dictionary"""
        return cls(
            event_id=data["event_id"],
            timestamp=data.get("timestamp", time.time()),
            event_type=AuditEventType(data.get("event_type", "user_login")),
            user_id=data.get("user_id", ""),
            target_user_id=data.get("target_user_id", ""),
            target_resource=data.get("target_resource", ""),
            action=data.get("action", ""),
            details=data.get("details", {}),
            ip_address=data.get("ip_address", ""),
            user_agent=data.get("user_agent", ""),
            severity=SeverityLevel(data.get("severity", "info")),
            success=data.get("success", True),
            error_message=data.get("error_message", ""),
            compliance_framework=[ComplianceFramework(fw) for fw in data.get("compliance_framework", [])],
            retention_days=data.get("retention_days", 365)
        )

@dataclass
class ComplianceRule:
    """Compliance rule definition"""
    rule_id: str
    name: str
    description: str
    framework: ComplianceFramework
    category: str
    severity: SeverityLevel
    enabled: bool
    conditions: Dict[str, Any]
    actions: List[str]
    retention_days: int
    notification_required: bool
    
    def evaluate_event(self, event: AuditEvent) -> Tuple[bool, str]:
        """Evaluate if event complies with this rule"""
        try:
            # Basic rule evaluation - can be extended
            if not self.enabled:
                return True, "Rule disabled"
            
            # Check event type
            if self.conditions.get("event_types"):
                if event.event_type.value not in self.conditions["event_types"]:
                    return False, f"Event type {event.event_type.value} not allowed"
            
            # Check severity
            if self.conditions.get("max_severity"):
                max_sev = SeverityLevel(self.conditions["max_severity"])
                severity_levels = [SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
                if severity_levels.index(event.severity) > severity_levels.index(max_sev):
                    return False, f"Severity {event.severity.value} exceeds maximum {max_sev.value}"
            
            # Check time restrictions
            if self.conditions.get("time_restrictions"):
                time_restr = self.conditions["time_restrictions"]
                current_hour = datetime.fromtimestamp(event.timestamp).hour
                
                if time_restr.get("business_hours_only"):
                    if current_hour < 9 or current_hour > 17:
                        return False, f"Event outside business hours (9-17)"
                
                if time_restr.get("weekends_only"):
                    if datetime.fromtimestamp(event.timestamp).weekday() >= 5:
                        return False, f"Event on weekend not allowed"
            
            return True, "Compliant"
            
        except Exception as e:
            log.error(f"Error evaluating compliance rule: {e}")
            return False, f"Rule evaluation error: {e}"

@dataclass
class ComplianceReport:
    """Compliance report"""
    report_id: str
    generated_at: float
    framework: ComplianceFramework
    period_start: float
    period_end: float
    total_events: int
    compliant_events: int
    non_compliant_events: int
    violations: List[Dict[str, Any]]
    recommendations: List[str]
    status: ComplianceStatus
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary"""
        return asdict(self)

class AuditManager:
    """Manages audit trail and compliance"""
    
    def __init__(self):
        self.audit_events: deque = deque(maxlen=10000)  # Keep last 10k events
        self.compliance_rules: Dict[str, ComplianceRule] = {}
        self.reports: Dict[str, ComplianceReport] = {}
        
        # Configuration
        self.max_events = 10000
        self.retention_days = 365
        self.auto_cleanup = True
        self.real_time_monitoring = True
        
        # Statistics
        self.total_events = 0
        self.events_by_type: Dict[str, int] = defaultdict(int)
        self.events_by_severity: Dict[str, int] = defaultdict(int)
        self.violations_by_framework: Dict[str, int] = defaultdict(int)
        
        # Initialize default compliance rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default compliance rules"""
        # GDPR rules
        self.compliance_rules["gdpr_data_access"] = ComplianceRule(
            rule_id="gdpr_data_access",
            name="GDPR Data Access Logging",
            description="Log all data access events for GDPR compliance",
            framework=ComplianceFramework.GDPR,
            category="data_protection",
            severity=SeverityLevel.HIGH,
            enabled=True,
            conditions={
                "event_types": ["user_login", "file_download", "message_send"],
                "require_consent": True
            },
            actions=["log", "notify", "retain"],
            retention_days=2555,  # 7 years
            notification_required=True
        )
        
        self.compliance_rules["gdpr_data_deletion"] = ComplianceRule(
            rule_id="gdpr_data_deletion",
            name="GDPR Right to be Forgotten",
            description="Track data deletion requests and confirmations",
            framework=ComplianceFramework.GDPR,
            category="data_protection",
            severity=SeverityLevel.CRITICAL,
            enabled=True,
            conditions={
                "event_types": ["user_delete", "file_delete"],
                "verification_required": True
            },
            actions=["log", "verify", "retain"],
            retention_days=2555,
            notification_required=True
        )
        
        # Security rules
        self.compliance_rules["security_admin_access"] = ComplianceRule(
            rule_id="security_admin_access",
            name="Administrative Access Monitoring",
            description="Monitor all administrative access attempts",
            framework=ComplianceFramework.ISO27001,
            category="access_control",
            severity=SeverityLevel.HIGH,
            enabled=True,
            conditions={
                "event_types": ["role_change", "permission_change", "system_config"],
                "require_mfa": True
            },
            actions=["log", "alert", "verify"],
            retention_days=1825,  # 5 years
            notification_required=True
        )
        
        # Business hours rule
        self.compliance_rules["business_hours_only"] = ComplianceRule(
            rule_id="business_hours_only",
            name="Business Hours Restriction",
            description="Restrict sensitive operations to business hours",
            framework=ComplianceFramework.SOX,
            category="operational_controls",
            severity=SeverityLevel.MEDIUM,
            enabled=False,  # Disabled by default
            conditions={
                "event_types": ["user_delete", "room_delete", "system_config"],
                "time_restrictions": {
                    "business_hours_only": True
                }
            },
            actions=["log", "block", "notify"],
            retention_days=1825,
            notification_required=True
        )
    
    async def log_event(self, event_type: AuditEventType, user_id: str,
                      action: str, target_resource: str = "",
                      target_user_id: str = "", details: Dict[str, Any] = None,
                      ip_address: str = "", user_agent: str = "",
                      severity: SeverityLevel = SeverityLevel.INFO,
                      success: bool = True, error_message: str = "") -> str:
        """Log audit event"""
        try:
            # Create audit event
            event_id = hashlib.sha256(f"{event_type.value}{user_id}{time.time()}".encode()).hexdigest()
            
            event = AuditEvent(
                event_id=event_id,
                timestamp=time.time(),
                event_type=event_type,
                user_id=user_id,
                target_user_id=target_user_id,
                target_resource=target_resource,
                action=action,
                details=details or {},
                ip_address=ip_address,
                user_agent=user_agent,
                severity=severity,
                success=success,
                error_message=error_message,
                compliance_framework=self._get_relevant_frameworks(event_type)
            )
            
            # Store event
            self.audit_events.append(event)
            self.total_events += 1
            self.events_by_type[event_type.value] += 1
            self.events_by_severity[severity.value] += 1
            
            # Evaluate compliance
            await self._evaluate_compliance(event)
            
            # Trigger real-time alerts if needed
            if self.real_time_monitoring:
                await self._trigger_compliance_alerts(event)
            
            log.info(f"Logged audit event: {event_type.value} by {user_id}")
            return event_id
            
        except Exception as e:
            log.error(f"Error logging audit event: {e}")
            return ""
    
    def _get_relevant_frameworks(self, event_type: AuditEventType) -> List[ComplianceFramework]:
        """Get relevant compliance frameworks for event type"""
        framework_mapping = {
            AuditEventType.USER_LOGIN: [ComplianceFramework.GDPR, ComplianceFramework.ISO27001],
            AuditEventType.USER_DELETE: [ComplianceFramework.GDPR, ComplianceFramework.CCPA],
            AuditEventType.FILE_UPLOAD: [ComplianceFramework.GDPR, ComplianceFramework.HIPAA],
            AuditEventType.FILE_DOWNLOAD: [ComplianceFramework.GDPR, ComplianceFramework.HIPAA],
            AuditEventType.ROLE_CHANGE: [ComplianceFramework.SOx, ComplianceFramework.ISO27001],
            AuditEventType.SYSTEM_CONFIG: [ComplianceFramework.ISO27001, ComplianceFramework.SOC2],
        }
        return framework_mapping.get(event_type, [])
    
    async def _evaluate_compliance(self, event: AuditEvent):
        """Evaluate event against compliance rules"""
        try:
            violations = []
            
            for rule_id, rule in self.compliance_rules.items():
                if not rule.enabled:
                    continue
                
                is_compliant, message = rule.evaluate_event(event)
                if not is_compliant:
                    violations.append({
                        "rule_id": rule_id,
                        "rule_name": rule.name,
                        "message": message,
                        "severity": rule.severity.value,
                        "framework": rule.framework.value
                    })
                    
                    # Update violation statistics
                    self.violations_by_framework[rule.framework.value] += 1
            
            # Store violations in event details
            if violations:
                event.details["compliance_violations"] = violations
                
        except Exception as e:
            log.error(f"Error evaluating compliance: {e}")
    
    async def _trigger_compliance_alerts(self, event: AuditEvent):
        """Trigger compliance alerts for critical events"""
        try:
            # Check for critical violations
            if event.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                await self._send_alert({
                    "type": "compliance_violation",
                    "event_id": event.event_id,
                    "severity": event.severity.value,
                    "message": f"Compliance violation: {event.action}",
                    "user_id": event.user_id,
                    "timestamp": event.timestamp
                })
            
            # Check for multiple violations
            if event.details.get("compliance_violations"):
                violation_count = len(event.details["compliance_violations"])
                if violation_count > 1:
                    await self._send_alert({
                        "type": "multiple_violations",
                        "event_id": event.event_id,
                        "violation_count": violation_count,
                        "message": f"Multiple compliance violations: {violation_count}",
                        "user_id": event.user_id,
                        "timestamp": event.timestamp
                    })
                        
        except Exception as e:
            log.error(f"Error triggering compliance alerts: {e}")
    
    async def _send_alert(self, alert_data: Dict[str, Any]):
        """Send compliance alert"""
        # In a real implementation, this would send notifications
        # For now, we'll just log the alert
        log.warning(f"Compliance alert: {alert_data}")
    
    def get_events_by_user(self, user_id: str, limit: int = 100) -> List[AuditEvent]:
        """Get events for specific user"""
        user_events = [event for event in self.audit_events if event.user_id == user_id]
        return user_events[-limit:] if len(user_events) > limit else user_events
    
    def get_events_by_type(self, event_type: AuditEventType, limit: int = 100) -> List[AuditEvent]:
        """Get events by type"""
        type_events = [event for event in self.audit_events if event.event_type == event_type]
        return type_events[-limit:] if len(type_events) > limit else type_events
    
    def get_events_by_timeframe(self, start_time: float, end_time: float) -> List[AuditEvent]:
        """Get events within timeframe"""
        return [event for event in self.audit_events 
                if start_time <= event.timestamp <= end_time]
    
    def get_events_by_severity(self, severity: SeverityLevel, limit: int = 100) -> List[AuditEvent]:
        """Get events by severity"""
        severity_events = [event for event in self.audit_events if event.severity == severity]
        return severity_events[-limit:] if len(severity_events) > limit else severity_events
    
    async def generate_compliance_report(self, framework: ComplianceFramework,
                                     period_start: float, period_end: float) -> str:
        """Generate compliance report"""
        try:
            # Filter events for period
            period_events = self.get_events_by_timeframe(period_start, period_end)
            
            # Filter events for framework
            framework_events = [event for event in period_events 
                             if framework in event.compliance_framework]
            
            # Evaluate compliance
            compliant_count = 0
            non_compliant_count = 0
            violations = []
            
            for event in framework_events:
                event_violations = event.details.get("compliance_violations", [])
                if event_violations:
                    non_compliant_count += 1
                    violations.extend(event_violations)
                else:
                    compliant_count += 1
            
            # Generate recommendations
            recommendations = self._generate_recommendations(violations, framework)
            
            # Create report
            report_id = hashlib.sha256(f"{framework.value}{period_start}{period_end}".encode()).hexdigest()
            
            report = ComplianceReport(
                report_id=report_id,
                generated_at=time.time(),
                framework=framework,
                period_start=period_start,
                period_end=period_end,
                total_events=len(framework_events),
                compliant_events=compliant_count,
                non_compliant_events=non_compliant_count,
                violations=violations,
                recommendations=recommendations,
                status=self._calculate_compliance_status(compliant_count, non_compliant_count)
            )
            
            # Store report
            self.reports[report_id] = report
            
            log.info(f"Generated compliance report for {framework.value}: {report_id}")
            return report_id
            
        except Exception as e:
            log.error(f"Error generating compliance report: {e}")
            return ""
    
    def _generate_recommendations(self, violations: List[Dict[str, Any]], 
                              framework: ComplianceFramework) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        # Count violations by type
        violation_types = defaultdict(int)
        for violation in violations:
            violation_types[violation["rule_id"]] += 1
        
        # Generate recommendations based on violation patterns
        for rule_id, count in violation_types.items():
            if rule_id == "gdpr_data_access":
                recommendations.append("Review data access policies and implement consent management")
            elif rule_id == "gdpr_data_deletion":
                recommendations.append("Ensure data deletion requests are processed within 30 days")
            elif rule_id == "security_admin_access":
                recommendations.append("Implement multi-factor authentication for all administrative access")
            elif rule_id == "business_hours_only":
                recommendations.append("Review business hours restrictions and consider automation")
        
        # Framework-specific recommendations
        if framework == ComplianceFramework.GDPR:
            recommendations.append("Conduct GDPR impact assessment for new features")
        elif framework == ComplianceFramework.ISO27001:
            recommendations.append("Schedule regular security audits and penetration testing")
        elif framework == ComplianceFramework.HIPAA:
            recommendations.append("Implement HIPAA training for all staff members")
        
        return recommendations
    
    def _calculate_compliance_status(self, compliant_count: int, 
                                   non_compliant_count: int) -> ComplianceStatus:
        """Calculate overall compliance status"""
        total_events = compliant_count + non_compliant_count
        
        if total_events == 0:
            return ComplianceStatus.COMPLIANT
        
        compliance_rate = compliant_count / total_events
        
        if compliance_rate >= 0.95:
            return ComplianceStatus.COMPLIANT
        elif compliance_rate >= 0.80:
            return ComplianceStatus.PENDING_REVIEW
        elif non_compliant_count > 0:
            return ComplianceStatus.VIOLATION
        else:
            return ComplianceStatus.NON_COMPLIANT
    
    def get_audit_statistics(self) -> Dict[str, Any]:
        """Get audit statistics"""
        return {
            "total_events": self.total_events,
            "events_by_type": dict(self.events_by_type),
            "events_by_severity": dict(self.events_by_severity),
            "violations_by_framework": dict(self.violations_by_framework),
            "compliance_rules": {
                "total": len(self.compliance_rules),
                "enabled": len([r for r in self.compliance_rules.values() if r.enabled]),
                "disabled": len([r for r in self.compliance_rules.values() if not r.enabled])
            },
            "reports_generated": len(self.reports),
            "retention_days": self.retention_days,
            "max_events": self.max_events
        }
    
    def get_compliance_summary(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """Get compliance summary for framework"""
        framework_events = [event for event in self.audit_events 
                         if framework in event.compliance_framework]
        
        total_events = len(framework_events)
        compliant_events = 0
        violations = []
        
        for event in framework_events:
            event_violations = event.details.get("compliance_violations", [])
            if event_violations:
                violations.extend(event_violations)
            else:
                compliant_events += 1
        
        return {
            "framework": framework.value,
            "total_events": total_events,
            "compliant_events": compliant_events,
            "non_compliant_events": total_events - compliant_events,
            "compliance_rate": (compliant_events / total_events) * 100 if total_events > 0 else 0,
            "violations_count": len(violations),
            "violations": violations[:10],  # Last 10 violations
            "status": self._calculate_compliance_status(compliant_events, total_events - compliant_events)
        }
    
    async def cleanup_old_events(self):
        """Clean up events older than retention period"""
        try:
            cutoff_time = time.time() - (self.retention_days * 24 * 3600)
            original_count = len(self.audit_events)
            
            # Remove old events
            self.audit_events = deque(
                [event for event in self.audit_events if event.timestamp > cutoff_time],
                maxlen=self.max_events
            )
            
            removed_count = original_count - len(self.audit_events)
            if removed_count > 0:
                log.info(f"Cleaned up {removed_count} old audit events")
                
        except Exception as e:
            log.error(f"Error cleaning up old events: {e}")
    
    def export_events(self, format_type: str = "json", 
                   start_time: float = None, end_time: float = None) -> str:
        """Export audit events"""
        try:
            events = list(self.audit_events)
            
            # Filter by timeframe if specified
            if start_time and end_time:
                events = self.get_events_by_timeframe(start_time, end_time)
            
            # Convert to requested format
            if format_type.lower() == "json":
                return json.dumps([event.to_dict() for event in events], indent=2)
            elif format_type.lower() == "csv":
                return self._export_to_csv(events)
            else:
                raise ValueError(f"Unsupported export format: {format_type}")
                
        except Exception as e:
            log.error(f"Error exporting events: {e}")
            return ""
    
    def _export_to_csv(self, events: List[AuditEvent]) -> str:
        """Export events to CSV format"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "event_id", "timestamp", "event_type", "user_id", "target_user_id",
            "target_resource", "action", "severity", "success", "ip_address",
            "user_agent", "error_message", "compliance_frameworks"
        ])
        
        # Write events
        for event in events:
            writer.writerow([
                event.event_id,
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp)),
                event.event_type.value,
                event.user_id,
                event.target_user_id,
                event.target_resource,
                event.action,
                event.severity.value,
                event.success,
                event.ip_address,
                event.user_agent,
                event.error_message,
                ",".join([fw.value for fw in event.compliance_framework])
            ])
        
        return output.getvalue()

# Utility functions
def create_audit_manager() -> AuditManager:
    """Create audit manager instance"""
    return AuditManager()

# Main usage example
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    async def test_audit_system():
        """Test audit and compliance system"""
        audit_manager = create_audit_manager()
        
        # Test logging events
        event_id1 = await audit_manager.log_event(
            AuditEventType.USER_LOGIN,
            "alice_admin",
            "User login",
            target_resource="authentication_system",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            severity=SeverityLevel.INFO
        )
        
        event_id2 = await audit_manager.log_event(
            AuditEventType.ROLE_CHANGE,
            "admin_user",
            "Role change",
            target_user_id="bob_user",
            details={"old_role": "member", "new_role": "moderator"},
            severity=SeverityLevel.HIGH
        )
        
        event_id3 = await audit_manager.log_event(
            AuditEventType.FILE_UPLOAD,
            "charlie_user",
            "File upload",
            target_resource="document.pdf",
            details={"file_size": 1024000, "file_type": "application/pdf"},
            severity=SeverityLevel.MEDIUM
        )
        
        if event_id1:
            print(f"✅ Logged login event: {event_id1}")
        
        if event_id2:
            print(f"✅ Logged role change event: {event_id2}")
        
        if event_id3:
            print(f"✅ Logged file upload event: {event_id3}")
        
        # Generate compliance report
        end_time = time.time()
        start_time = end_time - (7 * 24 * 3600)  # Last 7 days
        
        report_id = await audit_manager.generate_compliance_report(
            ComplianceFramework.GDPR,
            start_time,
            end_time
        )
        
        if report_id:
            print(f"✅ Generated GDPR compliance report: {report_id}")
        
        # Get statistics
        stats = audit_manager.get_audit_statistics()
        print(f"📊 Audit statistics: {stats}")
        
        # Get compliance summary
        gdpr_summary = audit_manager.get_compliance_summary(ComplianceFramework.GDPR)
        print(f"🔒 GDPR compliance: {gdpr_summary}")
        
        print("✅ Audit system test completed")
    
    asyncio.run(test_audit_system())
