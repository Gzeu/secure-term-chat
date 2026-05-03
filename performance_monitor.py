#!/usr/bin/env python3
"""
Performance Monitoring System for secure-term-chat
Real-time metrics collection and analysis
"""

import asyncio
import time
import psutil
import json
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from collections import deque, defaultdict
import statistics

log = logging.getLogger(__name__)

class MetricType(Enum):
    """Types of performance metrics"""
    CPU = "cpu"
    MEMORY = "memory"
    NETWORK = "network"
    DISK = "disk"
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    CONNECTIONS = "connections"
    P2P = "p2p"
    MESSAGES = "messages"
    ERROR_RATE = "error_rate"

class AlertLevel(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

@dataclass
class MetricPoint:
    """Single metric data point"""
    timestamp: float
    value: float
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class PerformanceAlert:
    """Performance alert definition"""
    metric_type: MetricType
    threshold: float
    operator: str  # ">", "<", ">=", "<=", "=="
    level: AlertLevel
    message: str
    enabled: bool = True
    last_triggered: Optional[float] = None
    trigger_count: int = 0

@dataclass
class SystemMetrics:
    """System performance metrics"""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_total_mb: float
    disk_usage_percent: float
    disk_used_gb: float
    disk_total_gb: float
    network_sent_mb: float
    network_recv_mb: float
    active_connections: int
    timestamp: float

@dataclass
class ApplicationMetrics:
    """Application-specific metrics"""
    message_count: int
    message_rate: float  # messages per second
    p2p_connections: int
    p2p_message_rate: float
    server_latency_ms: float
    p2p_latency_ms: float
    error_rate: float
    uptime_seconds: float
    timestamp: float

class MetricsCollector:
    """Collects system and application metrics"""
    
    def __init__(self, collection_interval: float = 1.0):
        self.collection_interval = collection_interval
        self.running = False
        self.start_time = time.time()
        
        # Metrics storage
        self.system_metrics: deque = deque(maxlen=300)  # 5 minutes at 1s interval
        self.app_metrics: deque = deque(maxlen=300)
        
        # Network stats
        self.last_network_stats = None
        
        # Counters
        self.message_counter = 0
        self.p2p_message_counter = 0
        self.error_counter = 0
        self.last_message_count = 0
        self.last_p2p_message_count = 0
        
    async def start_collection(self):
        """Start metrics collection"""
        self.running = True
        self.last_network_stats = psutil.net_io_counters()
        
        while self.running:
            try:
                # Collect system metrics
                system_metrics = self._collect_system_metrics()
                self.system_metrics.append(system_metrics)
                
                # Collect application metrics
                app_metrics = self._collect_application_metrics()
                self.app_metrics.append(app_metrics)
                
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                log.error(f"Error collecting metrics: {e}")
                await asyncio.sleep(self.collection_interval)
    
    def stop_collection(self):
        """Stop metrics collection"""
        self.running = False
    
    def _collect_system_metrics(self) -> SystemMetrics:
        """Collect system-level metrics"""
        # CPU
        cpu_percent = psutil.cpu_percent(interval=None)
        
        # Memory
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_mb = memory.used / 1024 / 1024
        memory_total_mb = memory.total / 1024 / 1024
        
        # Disk
        disk = psutil.disk_usage('/')
        disk_usage_percent = disk.percent
        disk_used_gb = disk.used / 1024 / 1024 / 1024
        disk_total_gb = disk.total / 1024 / 1024 / 1024
        
        # Network
        network_stats = psutil.net_io_counters()
        if self.last_network_stats:
            network_sent_mb = (network_stats.bytes_sent - self.last_network_stats.bytes_sent) / 1024 / 1024
            network_recv_mb = (network_stats.bytes_recv - self.last_network_stats.bytes_recv) / 1024 / 1024
        else:
            network_sent_mb = 0
            network_recv_mb = 0
        self.last_network_stats = network_stats
        
        # Connections
        active_connections = len(psutil.net_connections())
        
        return SystemMetrics(
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_used_mb=memory_used_mb,
            memory_total_mb=memory_total_mb,
            disk_usage_percent=disk_usage_percent,
            disk_used_gb=disk_used_gb,
            disk_total_gb=disk_total_gb,
            network_sent_mb=network_sent_mb,
            network_recv_mb=network_recv_mb,
            active_connections=active_connections,
            timestamp=time.time()
        )
    
    def _collect_application_metrics(self) -> ApplicationMetrics:
        """Collect application-specific metrics"""
        # Calculate rates
        current_time = time.time()
        time_diff = current_time - (self.app_metrics[-1].timestamp if self.app_metrics else current_time - 1)
        
        if time_diff > 0:
            message_rate = (self.message_counter - self.last_message_count) / time_diff
            p2p_message_rate = (self.p2p_message_counter - self.last_p2p_message_count) / time_diff
        else:
            message_rate = 0
            p2p_message_rate = 0
        
        self.last_message_count = self.message_counter
        self.last_p2p_message_count = self.p2p_message_counter
        
        # Calculate error rate
        total_messages = self.message_counter + self.p2p_message_counter
        error_rate = (self.error_counter / total_messages * 100) if total_messages > 0 else 0
        
        return ApplicationMetrics(
            message_count=self.message_counter,
            message_rate=message_rate,
            p2p_connections=0,  # Will be updated by P2P manager
            p2p_message_rate=p2p_message_rate,
            server_latency_ms=0,  # Will be updated by network client
            p2p_latency_ms=0,  # Will be updated by P2P manager
            error_rate=error_rate,
            uptime_seconds=current_time - self.start_time,
            timestamp=current_time
        )
    
    def increment_message_counter(self, is_p2p: bool = False):
        """Increment message counters"""
        if is_p2p:
            self.p2p_message_counter += 1
        else:
            self.message_counter += 1
    
    def increment_error_counter(self):
        """Increment error counter"""
        self.error_counter += 1
    
    def update_p2p_connections(self, count: int):
        """Update P2P connection count"""
        if self.app_metrics:
            self.app_metrics[-1].p2p_connections = count
    
    def update_latency(self, server_latency_ms: float = None, p2p_latency_ms: float = None):
        """Update latency metrics"""
        if self.app_metrics:
            if server_latency_ms is not None:
                self.app_metrics[-1].server_latency_ms = server_latency_ms
            if p2p_latency_ms is not None:
                self.app_metrics[-1].p2p_latency_ms = p2p_latency_ms
    
    def get_recent_metrics(self, seconds: int = 60) -> Dict[str, List[MetricPoint]]:
        """Get metrics from the last N seconds"""
        cutoff_time = time.time() - seconds
        
        recent_system = [
            MetricPoint(m.timestamp, m.cpu_percent, {"type": "cpu"})
            for m in self.system_metrics if m.timestamp >= cutoff_time
        ]
        
        recent_memory = [
            MetricPoint(m.timestamp, m.memory_percent, {"type": "memory"})
            for m in self.system_metrics if m.timestamp >= cutoff_time
        ]
        
        recent_network = [
            MetricPoint(m.timestamp, m.network_sent_mb + m.network_recv_mb, {"type": "network"})
            for m in self.system_metrics if m.timestamp >= cutoff_time
        ]
        
        recent_messages = [
            MetricPoint(m.timestamp, m.message_rate, {"type": "messages"})
            for m in self.app_metrics if m.timestamp >= cutoff_time
        ]
        
        return {
            "cpu": recent_system,
            "memory": recent_memory,
            "network": recent_network,
            "messages": recent_messages
        }
    
    def get_current_metrics(self) -> Dict[str, float]:
        """Get current system metrics"""
        if not self.system_metrics or not self.app_metrics:
            return {}
        
        system = self.system_metrics[-1]
        app = self.app_metrics[-1]
        
        return {
            "cpu_percent": system.cpu_percent,
            "memory_percent": system.memory_percent,
            "memory_used_mb": system.memory_used_mb,
            "disk_usage_percent": system.disk_usage_percent,
            "network_sent_mb": system.network_sent_mb,
            "network_recv_mb": system.network_recv_mb,
            "active_connections": system.active_connections,
            "message_rate": app.message_rate,
            "p2p_connections": app.p2p_connections,
            "p2p_message_rate": app.p2p_message_rate,
            "server_latency_ms": app.server_latency_ms,
            "p2p_latency_ms": app.p2p_latency_ms,
            "error_rate": app.error_rate,
            "uptime_seconds": app.uptime_seconds
        }
    
    def get_report(self) -> str:
        """Generate a performance report"""
        current_metrics = self.get_current_metrics()
        if not current_metrics:
            return "No metrics available yet"
        
        report = f"""
Performance Report - {time.strftime('%Y-%m-%d %H:%M:%S')}
============================================
CPU Usage: {current_metrics.get('cpu_percent', 0):.1f}%
Memory Usage: {current_metrics.get('memory_percent', 0):.1f}% ({current_metrics.get('memory_used_mb', 0):.1f} MB)
Disk Usage: {current_metrics.get('disk_usage_percent', 0):.1f}%
Network: {current_metrics.get('network_sent_mb', 0):.2f} MB sent, {current_metrics.get('network_recv_mb', 0):.2f} MB received
Active Connections: {current_metrics.get('active_connections', 0)}
Message Rate: {current_metrics.get('message_rate', 0):.2f} msg/s
P2P Connections: {current_metrics.get('p2p_connections', 0)}
P2P Message Rate: {current_metrics.get('p2p_message_rate', 0):.2f} msg/s
Server Latency: {current_metrics.get('server_latency_ms', 0):.1f} ms
P2P Latency: {current_metrics.get('p2p_latency_ms', 0):.1f} ms
Error Rate: {current_metrics.get('error_rate', 0):.2f}%
Uptime: {current_metrics.get('uptime_seconds', 0):.1f} seconds
============================================
        """.strip()
        
        return report

class AlertManager:
    """Manages performance alerts and notifications"""
    
    def __init__(self):
        self.alerts: List[PerformanceAlert] = []
        self.alert_handlers: List[Callable] = []
        self.alert_history: deque = deque(maxlen=100)
        
        # Default alerts
        self._setup_default_alerts()
    
    def _setup_default_alerts(self):
        """Setup default performance alerts"""
        default_alerts = [
            PerformanceAlert(
                metric_type=MetricType.CPU,
                threshold=80.0,
                operator=">",
                level=AlertLevel.WARNING,
                message="High CPU usage detected"
            ),
            PerformanceAlert(
                metric_type=MetricType.CPU,
                threshold=95.0,
                operator=">",
                level=AlertLevel.CRITICAL,
                message="Critical CPU usage"
            ),
            PerformanceAlert(
                metric_type=MetricType.MEMORY,
                threshold=85.0,
                operator=">",
                level=AlertLevel.WARNING,
                message="High memory usage"
            ),
            PerformanceAlert(
                metric_type=MetricType.MEMORY,
                threshold=95.0,
                operator=">",
                level=AlertLevel.CRITICAL,
                message="Critical memory usage"
            ),
            PerformanceAlert(
                metric_type=MetricType.LATENCY,
                threshold=1000.0,
                operator=">",
                level=AlertLevel.WARNING,
                message="High server latency"
            ),
            PerformanceAlert(
                metric_type=MetricType.ERROR_RATE,
                threshold=5.0,
                operator=">",
                level=AlertLevel.WARNING,
                message="High error rate"
            ),
            PerformanceAlert(
                metric_type=MetricType.THROUGHPUT,
                threshold=100.0,
                operator="<",
                level=AlertLevel.WARNING,
                message="Low message throughput"
            )
        ]
        
        self.alerts.extend(default_alerts)
    
    def add_alert(self, alert: PerformanceAlert):
        """Add new alert"""
        self.alerts.append(alert)
    
    def add_alert_handler(self, handler: Callable):
        """Add alert handler callback"""
        self.alert_handlers.append(handler)
    
    def check_alerts(self, metrics: Dict[str, float]):
        """Check all alerts against current metrics"""
        current_time = time.time()
        
        for alert in self.alerts:
            if not alert.enabled:
                continue
            
            # Get metric value
            metric_value = self._get_metric_value(alert.metric_type, metrics)
            if metric_value is None:
                continue
            
            # Check threshold
            triggered = self._check_threshold(metric_value, alert.threshold, alert.operator)
            
            if triggered:
                # Check cooldown (5 minutes)
                if (alert.last_triggered and 
                    current_time - alert.last_triggered < 300):
                    continue
                
                # Trigger alert
                alert.last_triggered = current_time
                alert.trigger_count += 1
                
                alert_data = {
                    "alert": alert,
                    "metric_value": metric_value,
                    "timestamp": current_time
                }
                
                self.alert_history.append(alert_data)
                
                # Call handlers
                for handler in self.alert_handlers:
                    try:
                        handler(alert_data)
                    except Exception as e:
                        log.error(f"Error in alert handler: {e}")
    
    def _get_metric_value(self, metric_type: MetricType, metrics: Dict[str, float]) -> Optional[float]:
        """Get metric value by type"""
        mapping = {
            MetricType.CPU: metrics.get("cpu_percent"),
            MetricType.MEMORY: metrics.get("memory_percent"),
            MetricType.LATENCY: metrics.get("server_latency_ms"),
            MetricType.ERROR_RATE: metrics.get("error_rate"),
            MetricType.THROUGHPUT: metrics.get("message_rate"),
            MetricType.CONNECTIONS: metrics.get("active_connections"),
            MetricType.P2P: metrics.get("p2p_connections"),
            MetricType.MESSAGES: metrics.get("message_rate")
        }
        
        return mapping.get(metric_type)
    
    def _check_threshold(self, value: float, threshold: float, operator: str) -> bool:
        """Check if value meets threshold condition"""
        if operator == ">":
            return value > threshold
        elif operator == "<":
            return value < threshold
        elif operator == ">=":
            return value >= threshold
        elif operator == "<=":
            return value <= threshold
        elif operator == "==":
            return value == threshold
        return False
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get currently active alerts"""
        current_time = time.time()
        active = []
        
        for alert_data in self.alert_history:
            if current_time - alert_data["timestamp"] < 300:  # Last 5 minutes
                active.append(alert_data)
        
        return active

class PerformanceAnalyzer:
    """Analyzes performance trends and patterns"""
    
    def __init__(self):
        self.trend_window = 300  # 5 minutes
        
    def analyze_trends(self, metrics: Dict[str, List[MetricPoint]]) -> Dict[str, str]:
        """Analyze performance trends"""
        trends = {}
        
        for metric_type, points in metrics.items():
            if len(points) < 10:  # Need at least 10 points for trend analysis
                continue
            
            values = [p.value for p in points]
            
            # Calculate trend
            if len(values) >= 2:
                recent_avg = statistics.mean(values[-5:])
                older_avg = statistics.mean(values[:5])
                
                change_percent = ((recent_avg - older_avg) / older_avg) * 100 if older_avg > 0 else 0
                
                if change_percent > 10:
                    trend = "increasing"
                elif change_percent < -10:
                    trend = "decreasing"
                else:
                    trend = "stable"
                
                trends[metric_type] = trend
        
        return trends
    
    def detect_anomalies(self, metrics: Dict[str, List[MetricPoint]]) -> List[Dict[str, Any]]:
        """Detect performance anomalies"""
        anomalies = []
        
        for metric_type, points in metrics.items():
            if len(points) < 20:  # Need at least 20 points for anomaly detection
                continue
            
            values = [p.value for p in points]
            
            # Calculate statistics
            mean = statistics.mean(values)
            stdev = statistics.stdev(values) if len(values) > 1 else 0
            
            # Detect outliers (2 standard deviations)
            threshold = mean + (2 * stdev)
            
            for point in points:
                if point.value > threshold:
                    anomalies.append({
                        "metric_type": metric_type,
                        "timestamp": point.timestamp,
                        "value": point.value,
                        "threshold": threshold,
                        "severity": "high" if point.value > mean + (3 * stdev) else "medium"
                    })
        
        return anomalies
    
    def generate_report(self, metrics: Dict[str, List[MetricPoint]]) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        report = {
            "timestamp": time.time(),
            "summary": {},
            "trends": self.analyze_trends(metrics),
            "anomalies": self.detect_anomalies(metrics)
        }
        
        # Generate summary statistics
        for metric_type, points in metrics.items():
            if not points:
                continue
            
            values = [p.value for p in points]
            
            report["summary"][metric_type] = {
                "current": values[-1] if values else 0,
                "average": statistics.mean(values),
                "min": min(values),
                "max": max(values),
                "count": len(values)
            }
        
        return report

# Utility functions
def create_metrics_collector(interval: float = 1.0) -> MetricsCollector:
    """Create metrics collector instance"""
    return MetricsCollector(interval)

def create_alert_manager() -> AlertManager:
    """Create alert manager instance"""
    return AlertManager()

def create_performance_analyzer() -> PerformanceAnalyzer:
    """Create performance analyzer instance"""
    return PerformanceAnalyzer()

# Main usage example
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    async def test_monitoring():
        """Test performance monitoring"""
        collector = create_metrics_collector()
        alert_manager = create_alert_manager()
        analyzer = create_performance_analyzer()
        
        # Add alert handler
        def handle_alert(alert_data):
            alert = alert_data["alert"]
            print(f"🚨 ALERT [{alert.level.value.upper()}]: {alert.message}")
            print(f"   Value: {alert_data['metric_value']:.2f} (threshold: {alert.threshold})")
        
        alert_manager.add_alert_handler(handle_alert)
        
        # Start collection
        collection_task = asyncio.create_task(collector.start_collection())
        
        try:
            # Run for 30 seconds
            for i in range(30):
                await asyncio.sleep(1)
                
                # Get current metrics
                current_metrics = collector.get_current_metrics()
                
                # Check alerts
                alert_manager.check_alerts(current_metrics)
                
                # Simulate some activity
                collector.increment_message_counter()
                if i % 10 == 0:
                    collector.increment_error_counter()
                
                print(f"📊 CPU: {current_metrics.get('cpu_percent', 0):.1f}% | "
                      f"Memory: {current_metrics.get('memory_percent', 0):.1f}% | "
                      f"Messages: {current_metrics.get('message_rate', 0):.1f}/s")
            
            # Generate report
            recent_metrics = collector.get_recent_metrics(30)
            report = analyzer.generate_report(recent_metrics)
            
            print("\n📋 Performance Report:")
            print(f"   Trends: {report['trends']}")
            print(f"   Anomalies: {len(report['anomalies'])}")
            print(f"   Summary: {report['summary']}")
            
        finally:
            collector.stop_collection()
            collection_task.cancel()
    
    asyncio.run(test_monitoring())
