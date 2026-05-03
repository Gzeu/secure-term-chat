#!/usr/bin/env python3
"""
Auto-scaling System for secure-term-chat
Intelligent resource management and optimization
"""

import asyncio
import time
import logging
import json
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from collections import deque, defaultdict
import statistics
import threading
import subprocess
import os

from performance_monitor import MetricsCollector, MetricType

log = logging.getLogger(__name__)

class ScalingAction(Enum):
    """Types of scaling actions"""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    ADJUST_P2P = "adjust_p2p"
    OPTIMIZE_CACHE = "optimize_cache"
    ADJUST_COMPRESSION = "adjust_compression"
    LIMIT_CONNECTIONS = "limit_connections"
    ENABLE_RELAY = "enable_relay"
    DISABLE_RELAY = "disable_relays"

class ScalingReason(Enum):
    """Reasons for scaling decisions"""
    HIGH_CPU = "high_cpu"
    HIGH_MEMORY = "high_memory"
    HIGH_LATENCY = "high_latency"
    HIGH_ERROR_RATE = "high_error_rate"
    LOW_THROUGHPUT = "low_throughput"
    P2P_FAILURE = "p2p_failure"
    RESOURCE_PRESSURE = "resource_pressure"
    PERFORMANCE_DEGRADATION = "performance_degradation"

@dataclass
class ScalingRule:
    """Auto-scaling rule definition"""
    name: str
    metric_type: MetricType
    threshold: float
    operator: str  # ">", "<", ">=", "<=", "=="
    action: ScalingAction
    reason: ScalingReason
    cooldown: int = 300  # 5 minutes cooldown
    priority: int = 1  # Higher priority rules execute first
    enabled: bool = True
    last_triggered: Optional[float] = None
    trigger_count: int = 0

@dataclass
class ScalingEvent:
    """Record of a scaling action"""
    timestamp: float
    action: ScalingAction
    reason: ScalingReason
    metric_value: float
    threshold: float
    rule_name: str
    success: bool
    message: str
    before_state: Dict[str, Any]
    after_state: Dict[str, Any]

@dataclass
class SystemState:
    """Current system state"""
    cpu_percent: float
    memory_percent: float
    active_connections: int
    p2p_connections: int
    message_rate: float
    server_latency_ms: float
    p2p_latency_ms: float
    error_rate: float
    cache_size_mb: float
    compression_enabled: bool
    relay_enabled: bool
    connection_limit: int
    timestamp: float

class ResourceOptimizer:
    """Optimizes system resources based on current load"""
    
    def __init__(self):
        self.optimization_history: deque = deque(maxlen=100)
        
    async def optimize_cache_size(self, current_metrics: Dict[str, float]) -> Dict[str, Any]:
        """Optimize cache size based on memory pressure"""
        memory_percent = current_metrics.get("memory_percent", 0)
        message_rate = current_metrics.get("message_rate", 0)
        
        optimizations = {}
        
        if memory_percent > 80:
            # Reduce cache size under memory pressure
            optimizations["cache_size_mb"] = max(10, 100 - (memory_percent - 80) * 2)
            optimizations["cache_cleanup"] = True
        elif memory_percent < 50 and message_rate > 100:
            # Increase cache size for high throughput
            optimizations["cache_size_mb"] = min(200, 50 + message_rate / 10)
            optimizations["cache_warmup"] = True
        
        return optimizations
    
    async def optimize_compression(self, current_metrics: Dict[str, float]) -> Dict[str, Any]:
        """Optimize compression settings based on CPU and network"""
        cpu_percent = current_metrics.get("cpu_percent", 0)
        network_sent_mb = current_metrics.get("network_sent_mb", 0)
        
        optimizations = {}
        
        if cpu_percent > 85:
            # Disable compression under CPU pressure
            optimizations["compression_enabled"] = False
            optimizations["compression_level"] = 0
        elif cpu_percent < 60 and network_sent_mb > 10:
            # Enable compression for high network usage
            optimizations["compression_enabled"] = True
            optimizations["compression_level"] = 6  # Balanced compression
        
        return optimizations
    
    async def optimize_connections(self, current_metrics: Dict[str, float]) -> Dict[str, Any]:
        """Optimize connection limits based on system load"""
        cpu_percent = current_metrics.get("cpu_percent", 0)
        memory_percent = current_metrics.get("memory_percent", 0)
        active_connections = current_metrics.get("active_connections", 0)
        
        optimizations = {}
        
        # Calculate system load score
        load_score = (cpu_percent + memory_percent) / 2
        
        if load_score > 80:
            # Limit connections under high load
            optimizations["connection_limit"] = max(10, active_connections - 10)
            optimizations["reject_new_connections"] = True
        elif load_score < 40:
            # Allow more connections under low load
            optimizations["connection_limit"] = min(1000, active_connections + 50)
            optimizations["reject_new_connections"] = False
        
        return optimizations
    
    async def optimize_p2p_routing(self, current_metrics: Dict[str, float]) -> Dict[str, Any]:
        """Optimize P2P vs relay routing"""
        p2p_connections = current_metrics.get("p2p_connections", 0)
        active_connections = current_metrics.get("active_connections", 0)
        p2p_latency_ms = current_metrics.get("p2p_latency_ms", 0)
        server_latency_ms = current_metrics.get("server_latency_ms", 0)
        
        optimizations = {}
        
        p2p_ratio = p2p_connections / active_connections if active_connections > 0 else 0
        
        if p2p_latency_ms > server_latency_ms * 2:
            # P2P is slow, prefer relay
            optimizations["p2p_enabled"] = False
            optimizations["relay_fallback"] = True
            optimizations["p2p_retry_interval"] = 60  # Retry P2P in 1 minute
        elif p2p_ratio < 0.3 and active_connections > 10:
            # Not enough P2P connections, try to enable more
            optimizations["p2p_enabled"] = True
            optimizations["p2p_aggressive"] = True
            optimizations["relay_fallback"] = True
        
        return optimizations

class AutoScalingManager:
    """Manages auto-scaling decisions and actions"""
    
    def __init__(self):
        self.rules: List[ScalingRule] = []
        self.events: deque = deque(maxlen=1000)
        self.current_state: Optional[SystemState] = None
        self.optimizer = ResourceOptimizer()
        
        # Scaling state
        self.last_scale_time = 0
        self.scale_cooldown = 60  # 1 minute between scaling actions
        self.scaling_enabled = True
        
        # Callbacks for executing scaling actions
        self.action_handlers: Dict[ScalingAction, Callable] = {}
        
        # Setup default rules
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Setup default auto-scaling rules"""
        default_rules = [
            # CPU-based rules
            ScalingRule(
                name="high_cpu_scale_up",
                metric_type=MetricType.CPU,
                threshold=85.0,
                operator=">",
                action=ScalingAction.SCALE_UP,
                reason=ScalingReason.HIGH_CPU,
                priority=3,
                cooldown=180
            ),
            ScalingRule(
                name="low_cpu_scale_down",
                metric_type=MetricType.CPU,
                threshold=30.0,
                operator="<",
                action=ScalingAction.SCALE_DOWN,
                reason=ScalingReason.RESOURCE_PRESSURE,
                priority=2,
                cooldown=300
            ),
            
            # Memory-based rules
            ScalingRule(
                name="high_memory_optimize",
                metric_type=MetricType.MEMORY,
                threshold=80.0,
                operator=">",
                action=ScalingAction.OPTIMIZE_CACHE,
                reason=ScalingReason.HIGH_MEMORY,
                priority=4,
                cooldown=120
            ),
            ScalingRule(
                name="critical_memory_limit",
                metric_type=MetricType.MEMORY,
                threshold=95.0,
                operator=">",
                action=ScalingAction.LIMIT_CONNECTIONS,
                reason=ScalingReason.RESOURCE_PRESSURE,
                priority=5,
                cooldown=60
            ),
            
            # Latency-based rules
            ScalingRule(
                name="high_latency_adjust_p2p",
                metric_type=MetricType.LATENCY,
                threshold=1000.0,
                operator=">",
                action=ScalingAction.ADJUST_P2P,
                reason=ScalingReason.HIGH_LATENCY,
                priority=3,
                cooldown=120
            ),
            
            # Throughput-based rules
            ScalingRule(
                name="low_throughput_scale_up",
                metric_type=MetricType.THROUGHPUT,
                threshold=50.0,
                operator="<",
                action=ScalingAction.SCALE_UP,
                reason=ScalingReason.LOW_THROUGHPUT,
                priority=2,
                cooldown=240
            ),
            
            # Error rate-based rules
            ScalingRule(
                name="high_error_rate_enable_relay",
                metric_type=MetricType.ERROR_RATE,
                threshold=10.0,
                operator=">",
                action=ScalingAction.ENABLE_RELAY,
                reason=ScalingReason.HIGH_ERROR_RATE,
                priority=4,
                cooldown=180
            ),
            
            # Connection-based rules
            ScalingRule(
                name="high_connections_optimize",
                metric_type=MetricType.CONNECTIONS,
                threshold=500,
                operator=">",
                action=ScalingAction.ADJUST_COMPRESSION,
                reason=ScalingReason.RESOURCE_PRESSURE,
                priority=3,
                cooldown=150
            )
        ]
        
        self.rules.extend(default_rules)
    
    def add_rule(self, rule: ScalingRule):
        """Add a new scaling rule"""
        self.rules.append(rule)
    
    def add_action_handler(self, action: ScalingAction, handler: Callable):
        """Add handler for scaling action"""
        self.action_handlers[action] = handler
    
    async def evaluate_scaling(self, metrics: Dict[str, float]) -> List[ScalingEvent]:
        """Evaluate all scaling rules and return triggered actions"""
        current_time = time.time()
        
        # Check cooldown
        if current_time - self.last_scale_time < self.scale_cooldown:
            return []
        
        triggered_events = []
        
        # Sort rules by priority (higher first)
        sorted_rules = sorted(self.rules, key=lambda r: r.priority, reverse=True)
        
        for rule in sorted_rules:
            if not rule.enabled:
                continue
            
            # Check cooldown for this specific rule
            if rule.last_triggered and current_time - rule.last_triggered < rule.cooldown:
                continue
            
            # Get metric value
            metric_value = self._get_metric_value(rule.metric_type, metrics)
            if metric_value is None:
                continue
            
            # Check threshold
            triggered = self._check_threshold(metric_value, rule.threshold, rule.operator)
            
            if triggered:
                # Execute scaling action
                success = await self._execute_scaling_action(rule, metric_value, metrics)
                
                # Record event
                event = ScalingEvent(
                    timestamp=current_time,
                    action=rule.action,
                    reason=rule.reason,
                    metric_value=metric_value,
                    threshold=rule.threshold,
                    rule_name=rule.name,
                    success=success,
                    message=f"Triggered by {rule.name}: {metric_value:.2f} {rule.operator} {rule.threshold}",
                    before_state=self.current_state.__dict__ if self.current_state else {},
                    after_state={}
                )
                
                triggered_events.append(event)
                self.events.append(event)
                
                # Update rule
                rule.last_triggered = current_time
                rule.trigger_count += 1
                
                # Update last scale time
                self.last_scale_time = current_time
                
                # Only execute one action per evaluation cycle
                break
        
        return triggered_events
    
    async def _execute_scaling_action(self, rule: ScalingRule, metric_value: float, metrics: Dict[str, float]) -> bool:
        """Execute a scaling action"""
        try:
            if rule.action in self.action_handlers:
                handler = self.action_handlers[rule.action]
                return await handler(rule, metric_value, metrics)
            else:
                # Default action handlers
                return await self._default_action_handler(rule, metric_value, metrics)
        except Exception as e:
            log.error(f"Error executing scaling action {rule.action}: {e}")
            return False
    
    async def _default_action_handler(self, rule: ScalingRule, metric_value: float, metrics: Dict[str, float]) -> bool:
        """Default action handlers"""
        if rule.action == ScalingAction.OPTIMIZE_CACHE:
            optimizations = await self.optimizer.optimize_cache_size(metrics)
            await self._apply_optimizations(optimizations)
            return True
        
        elif rule.action == ScalingAction.ADJUST_COMPRESSION:
            optimizations = await self.optimizer.optimize_compression(metrics)
            await self._apply_optimizations(optimizations)
            return True
        
        elif rule.action == ScalingAction.LIMIT_CONNECTIONS:
            optimizations = await self.optimizer.optimize_connections(metrics)
            await self._apply_optimizations(optimizations)
            return True
        
        elif rule.action == ScalingAction.ADJUST_P2P:
            optimizations = await self.optimizer.optimize_p2p_routing(metrics)
            await self._apply_optimizations(optimizations)
            return True
        
        elif rule.action == ScalingAction.ENABLE_RELAY:
            optimizations = {"relay_enabled": True, "p2p_enabled": False}
            await self._apply_optimizations(optimizations)
            return True
        
        elif rule.action == ScalingAction.DISABLE_RELAY:
            optimizations = {"relay_enabled": False, "p2p_enabled": True}
            await self._apply_optimizations(optimizations)
            return True
        
        return False
    
    async def _apply_optimizations(self, optimizations: Dict[str, Any]):
        """Apply system optimizations"""
        for key, value in optimizations.items():
            log.info(f"Applying optimization: {key} = {value}")
            # In a real implementation, this would apply actual system changes
            # For now, we just log the changes
    
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
    
    def update_system_state(self, metrics: Dict[str, float]):
        """Update current system state"""
        self.current_state = SystemState(
            cpu_percent=metrics.get("cpu_percent", 0),
            memory_percent=metrics.get("memory_percent", 0),
            active_connections=int(metrics.get("active_connections", 0)),
            p2p_connections=int(metrics.get("p2p_connections", 0)),
            message_rate=metrics.get("message_rate", 0),
            server_latency_ms=metrics.get("server_latency_ms", 0),
            p2p_latency_ms=metrics.get("p2p_latency_ms", 0),
            error_rate=metrics.get("error_rate", 0),
            cache_size_mb=0,  # Would be updated by actual system
            compression_enabled=True,  # Would be updated by actual system
            relay_enabled=False,  # Would be updated by actual system
            connection_limit=1000,  # Would be updated by actual system
            timestamp=time.time()
        )
    
    def get_scaling_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent scaling events"""
        recent_events = list(self.events)[-limit:]
        return [
            {
                "timestamp": event.timestamp,
                "action": event.action.value,
                "reason": event.reason.value,
                "metric_value": event.metric_value,
                "threshold": event.threshold,
                "rule_name": event.rule_name,
                "success": event.success,
                "message": event.message
            }
            for event in recent_events
        ]
    
    def get_scaling_stats(self) -> Dict[str, Any]:
        """Get scaling statistics"""
        if not self.events:
            return {}
        
        # Count actions by type
        action_counts = defaultdict(int)
        reason_counts = defaultdict(int)
        
        for event in self.events:
            action_counts[event.action.value] += 1
            reason_counts[event.reason.value] += 1
        
        # Calculate success rate
        successful = sum(1 for event in self.events if event.success)
        total = len(self.events)
        success_rate = (successful / total * 100) if total > 0 else 0
        
        return {
            "total_events": total,
            "success_rate": success_rate,
            "action_counts": dict(action_counts),
            "reason_counts": dict(reason_counts),
            "last_event": self.events[-1].timestamp if self.events else None,
            "rules_triggered": len(set(event.rule_name for event in self.events))
        }

# Utility functions
def create_auto_scaling_manager() -> AutoScalingManager:
    """Create auto-scaling manager instance"""
    return AutoScalingManager()

# Main usage example
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    async def test_auto_scaling():
        """Test auto-scaling system"""
        manager = create_auto_scaling_manager()
        
        # Add custom action handler
        async def handle_scale_up(rule, metric_value, metrics):
            print(f"🚀 Scaling up due to {rule.reason.value}: {metric_value:.2f}")
            return True
        
        manager.add_action_handler(ScalingAction.SCALE_UP, handle_scale_up)
        
        # Simulate metrics
        test_metrics = {
            "cpu_percent": 90.0,
            "memory_percent": 70.0,
            "active_connections": 100,
            "message_rate": 150.0,
            "server_latency_ms": 500.0,
            "error_rate": 2.0
        }
        
        # Update system state
        manager.update_system_state(test_metrics)
        
        # Evaluate scaling
        events = await manager.evaluate_scaling(test_metrics)
        
        print(f"📊 Triggered {len(events)} scaling events:")
        for event in events:
            print(f"   - {event.action.value}: {event.message}")
        
        # Get statistics
        stats = manager.get_scaling_stats()
        print(f"📈 Scaling stats: {stats}")
    
    asyncio.run(test_auto_scaling())
