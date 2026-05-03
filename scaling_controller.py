#!/usr/bin/env python3
"""
Scaling Controller for secure-term-chat
Integrates auto-scaling with server and client components
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

from auto_scaling import AutoScalingManager, ScalingAction, ScalingReason, create_auto_scaling_manager
from performance_monitor import MetricsCollector

log = logging.getLogger(__name__)

@dataclass
class ScalingConfiguration:
    """Configuration for auto-scaling behavior"""
    enabled: bool = True
    evaluation_interval: float = 30.0  # seconds
    max_scale_up_per_hour: int = 10
    max_scale_down_per_hour: int = 5
    min_connection_limit: int = 10
    max_connection_limit: int = 1000
    cache_size_min_mb: int = 10
    cache_size_max_mb: int = 500
    compression_threshold_cpu: float = 85.0
    latency_threshold_ms: float = 1000.0
    error_rate_threshold: float = 10.0

class ServerScalingController:
    """Controls auto-scaling for server components"""
    
    def __init__(self, server_instance, config: ScalingConfiguration = None):
        self.server = server_instance
        self.config = config or ScalingConfiguration()
        self.scaling_manager = create_auto_scaling_manager()
        self.metrics_collector: Optional[MetricsCollector] = None
        
        # Scaling state
        self.current_connection_limit = self.config.max_connection_limit
        self.current_cache_size = 100  # MB
        self.compression_enabled = True
        self.relay_enabled = False
        
        # Statistics
        self.scale_up_count = 0
        self.scale_down_count = 0
        self.last_scale_time = 0
        
        # Setup action handlers
        self._setup_action_handlers()
    
    def _setup_action_handlers(self):
        """Setup handlers for scaling actions"""
        self.scaling_manager.add_action_handler(ScalingAction.SCALE_UP, self._handle_scale_up)
        self.scaling_manager.add_action_handler(ScalingAction.SCALE_DOWN, self._handle_scale_down)
        self.scaling_manager.add_action_handler(ScalingAction.OPTIMIZE_CACHE, self._handle_optimize_cache)
        self.scaling_manager.add_action_handler(ScalingAction.ADJUST_COMPRESSION, self._handle_adjust_compression)
        self.scaling_manager.add_action_handler(ScalingAction.LIMIT_CONNECTIONS, self._handle_limit_connections)
        self.scaling_manager.add_action_handler(ScalingAction.ENABLE_RELAY, self._handle_enable_relay)
        self.scaling_manager.add_action_handler(ScalingAction.DISABLE_RELAY, self._handle_disable_relay)
        self.scaling_manager.add_action_handler(ScalingAction.ADJUST_P2P, self._handle_adjust_p2p)
    
    async def start_monitoring(self, metrics_collector: MetricsCollector):
        """Start auto-scaling monitoring"""
        if not self.config.enabled:
            log.info("Auto-scaling is disabled")
            return
        
        self.metrics_collector = metrics_collector
        
        # Start monitoring loop
        asyncio.create_task(self._monitoring_loop())
        
        log.info("Auto-scaling monitoring started")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.config.enabled:
            try:
                # Get current metrics
                current_metrics = self.metrics_collector.get_current_metrics()
                
                # Update system state
                self.scaling_manager.update_system_state(current_metrics)
                
                # Evaluate scaling rules
                events = await self.scaling_manager.evaluate_scaling(current_metrics)
                
                # Log triggered events
                for event in events:
                    log.info(f"🔧 Scaling event: {event.message}")
                
                await asyncio.sleep(self.config.evaluation_interval)
                
            except Exception as e:
                log.error(f"Error in scaling monitoring loop: {e}")
                await asyncio.sleep(self.config.evaluation_interval)
    
    async def _handle_scale_up(self, rule, metric_value: float, metrics: Dict[str, float]) -> bool:
        """Handle scale up action"""
        current_time = time.time()
        
        # Check rate limiting
        if current_time - self.last_scale_time < 300:  # 5 minutes
            return False
        
        # Check hourly limits
        if self.scale_up_count >= self.config.max_scale_up_per_hour:
            log.warning("Scale up hourly limit reached")
            return False
        
        try:
            # Increase connection limit
            new_limit = min(
                self.config.max_connection_limit,
                int(self.current_connection_limit * 1.2)
            )
            
            await self._update_connection_limit(new_limit)
            
            # Enable more aggressive caching
            new_cache_size = min(
                self.config.cache_size_max_mb,
                int(self.current_cache_size * 1.3)
            )
            await self._update_cache_size(new_cache_size)
            
            self.scale_up_count += 1
            self.last_scale_time = current_time
            
            log.info(f"🚀 Scaled up: connections={new_limit}, cache={new_cache_size}MB")
            return True
            
        except Exception as e:
            log.error(f"Error in scale up: {e}")
            return False
    
    async def _handle_scale_down(self, rule, metric_value: float, metrics: Dict[str, float]) -> bool:
        """Handle scale down action"""
        current_time = time.time()
        
        # Check rate limiting
        if current_time - self.last_scale_time < 300:  # 5 minutes
            return False
        
        # Check hourly limits
        if self.scale_down_count >= self.config.max_scale_down_per_hour:
            log.warning("Scale down hourly limit reached")
            return False
        
        try:
            # Decrease connection limit
            new_limit = max(
                self.config.min_connection_limit,
                int(self.current_connection_limit * 0.8)
            )
            
            await self._update_connection_limit(new_limit)
            
            # Reduce cache size
            new_cache_size = max(
                self.config.cache_size_min_mb,
                int(self.current_cache_size * 0.7)
            )
            await self._update_cache_size(new_cache_size)
            
            self.scale_down_count += 1
            self.last_scale_time = current_time
            
            log.info(f"📉 Scaled down: connections={new_limit}, cache={new_cache_size}MB")
            return True
            
        except Exception as e:
            log.error(f"Error in scale down: {e}")
            return False
    
    async def _handle_optimize_cache(self, rule, metric_value: float, metrics: Dict[str, float]) -> bool:
        """Handle cache optimization"""
        try:
            memory_percent = metrics.get("memory_percent", 0)
            
            if memory_percent > 80:
                # Reduce cache size
                new_size = max(
                    self.config.cache_size_min_mb,
                    int(self.current_cache_size * 0.6)
                )
                await self._update_cache_size(new_size)
                
                # Trigger cache cleanup
                await self._cleanup_cache()
                
                log.info(f"🧹 Optimized cache: reduced to {new_size}MB")
            else:
                # Increase cache size
                new_size = min(
                    self.config.cache_size_max_mb,
                    int(self.current_cache_size * 1.2)
                )
                await self._update_cache_size(new_size)
                
                log.info(f"📈 Optimized cache: increased to {new_size}MB")
            
            return True
            
        except Exception as e:
            log.error(f"Error in cache optimization: {e}")
            return False
    
    async def _handle_adjust_compression(self, rule, metric_value: float, metrics: Dict[str, float]) -> bool:
        """Handle compression adjustment"""
        try:
            cpu_percent = metrics.get("cpu_percent", 0)
            network_mb = metrics.get("network_sent_mb", 0) + metrics.get("network_recv_mb", 0)
            
            if cpu_percent > self.config.compression_threshold_cpu:
                # Disable compression under CPU pressure
                await self._update_compression(False, 0)
                log.info("📦 Disabled compression due to high CPU usage")
            elif network_mb > 10 and cpu_percent < 60:
                # Enable compression for high network usage
                await self._update_compression(True, 6)
                log.info("📦 Enabled compression for high network usage")
            
            return True
            
        except Exception as e:
            log.error(f"Error in compression adjustment: {e}")
            return False
    
    async def _handle_limit_connections(self, rule, metric_value: float, metrics: Dict[str, float]) -> bool:
        """Handle connection limiting"""
        try:
            active_connections = int(metrics.get("active_connections", 0))
            
            # Calculate new limit based on system load
            cpu_percent = metrics.get("cpu_percent", 0)
            memory_percent = metrics.get("memory_percent", 0)
            load_score = (cpu_percent + memory_percent) / 2
            
            if load_score > 80:
                # Aggressively limit connections
                new_limit = max(
                    self.config.min_connection_limit,
                    active_connections - 20
                )
            elif load_score > 60:
                # Moderately limit connections
                new_limit = max(
                    self.config.min_connection_limit,
                    active_connections - 10
                )
            else:
                # Allow more connections
                new_limit = min(
                    self.config.max_connection_limit,
                    active_connections + 50
                )
            
            await self._update_connection_limit(new_limit)
            log.info(f"🔗 Updated connection limit: {new_limit}")
            
            return True
            
        except Exception as e:
            log.error(f"Error in connection limiting: {e}")
            return False
    
    async def _handle_enable_relay(self, rule, metric_value: float, metrics: Dict[str, float]) -> bool:
        """Handle enabling relay mode"""
        try:
            await self._update_relay_mode(True)
            log.info("🌐 Enabled relay mode due to high error rate")
            return True
        except Exception as e:
            log.error(f"Error enabling relay mode: {e}")
            return False
    
    async def _handle_disable_relay(self, rule, metric_value: float, metrics: Dict[str, float]) -> bool:
        """Handle disabling relay mode"""
        try:
            await self._update_relay_mode(False)
            log.info("🔗 Disabled relay mode")
            return True
        except Exception as e:
            log.error(f"Error disabling relay mode: {e}")
            return False
    
    async def _handle_adjust_p2p(self, rule, metric_value: float, metrics: Dict[str, float]) -> bool:
        """Handle P2P adjustment"""
        try:
            p2p_latency = metrics.get("p2p_latency_ms", 0)
            server_latency = metrics.get("server_latency_ms", 0)
            
            if p2p_latency > self.config.latency_threshold_ms:
                # P2P is slow, prefer relay
                await self._update_p2p_preferences(
                    p2p_enabled=False,
                    relay_fallback=True,
                    p2p_retry_interval=60
                )
                log.info("🔄 Adjusted P2P: disabled due to high latency")
            elif p2p_latency < server_latency * 0.8:
                # P2P is faster, enable aggressively
                await self._update_p2p_preferences(
                    p2p_enabled=True,
                    relay_fallback=True,
                    p2p_aggressive=True
                )
                log.info("🚀 Adjusted P2P: enabled aggressively")
            
            return True
            
        except Exception as e:
            log.error(f"Error in P2P adjustment: {e}")
            return False
    
    async def _update_connection_limit(self, new_limit: int):
        """Update connection limit"""
        self.current_connection_limit = new_limit
        # In a real implementation, this would update server configuration
        if hasattr(self.server, 'max_connections'):
            self.server.max_connections = new_limit
    
    async def _update_cache_size(self, new_size_mb: int):
        """Update cache size"""
        self.current_cache_size = new_size_mb
        # In a real implementation, this would update cache configuration
        if hasattr(self.server, 'cache_size'):
            self.server.cache_size = new_size_mb
    
    async def _cleanup_cache(self):
        """Trigger cache cleanup"""
        # In a real implementation, this would trigger cache cleanup
        if hasattr(self.server, 'cleanup_cache'):
            await self.server.cleanup_cache()
    
    async def _update_compression(self, enabled: bool, level: int):
        """Update compression settings"""
        self.compression_enabled = enabled
        # In a real implementation, this would update compression settings
        if hasattr(self.server, 'compression_enabled'):
            self.server.compression_enabled = enabled
        if hasattr(self.server, 'compression_level'):
            self.server.compression_level = level
    
    async def _update_relay_mode(self, enabled: bool):
        """Update relay mode"""
        self.relay_enabled = enabled
        # In a real implementation, this would update relay settings
        if hasattr(self.server, 'relay_enabled'):
            self.server.relay_enabled = enabled
    
    async def _update_p2p_preferences(self, **kwargs):
        """Update P2P preferences"""
        # In a real implementation, this would update P2P settings
        if hasattr(self.server, 'p2p_config'):
            for key, value in kwargs.items():
                setattr(self.server.p2p_config, key, value)
    
    def get_scaling_status(self) -> Dict[str, Any]:
        """Get current scaling status"""
        return {
            "enabled": self.config.enabled,
            "connection_limit": self.current_connection_limit,
            "cache_size_mb": self.current_cache_size,
            "compression_enabled": self.compression_enabled,
            "relay_enabled": self.relay_enabled,
            "scale_up_count": self.scale_up_count,
            "scale_down_count": self.scale_down_count,
            "last_scale_time": self.last_scale_time,
            "scaling_stats": self.scaling_manager.get_scaling_stats()
        }

# Utility functions
def create_scaling_controller(server_instance, config: ScalingConfiguration = None) -> ServerScalingController:
    """Create scaling controller instance"""
    return ServerScalingController(server_instance, config)

# Main usage example
if __name__ == "__main__":
    import logging
    
    logging.basicConfig(level=logging.INFO)
    
    class MockServer:
        """Mock server for testing"""
        def __init__(self):
            self.max_connections = 100
            self.cache_size = 100
            self.compression_enabled = True
            self.relay_enabled = False
    
    async def test_scaling_controller():
        """Test scaling controller"""
        server = MockServer()
        config = ScalingConfiguration(enabled=True, evaluation_interval=5.0)
        controller = create_scaling_controller(server, config)
        
        from performance_monitor import create_metrics_collector
        
        # Create metrics collector
        collector = create_metrics_collector()
        
        # Start monitoring
        await controller.start_monitoring(collector)
        
        # Simulate some metrics
        for i in range(10):
            collector.increment_message_counter()
            await asyncio.sleep(1)
            
            if i % 3 == 0:
                status = controller.get_scaling_status()
                print(f"📊 Scaling status: {status}")
        
        print("✅ Scaling controller test completed")
    
    asyncio.run(test_scaling_controller())
